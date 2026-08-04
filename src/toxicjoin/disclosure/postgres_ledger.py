"""Shared-authoritative PostgreSQL persistence for cumulative disclosure state.

This backend is staged and intentionally not wired into the canonical HTTP runtime yet. It mirrors
ToxicJoin's security-owned disclosure contract while using one PostgreSQL transaction and one
row-level lock per privacy scope so independent application replicas serialize cumulative privacy
history against the same authoritative store.

The PostgreSQL driver is loaded lazily. The minimal ToxicJoin runtime therefore does not acquire a
PostgreSQL dependency merely by importing the package; deployments selecting this backend must
install Psycopg 3 explicitly.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from toxicjoin.disclosure.composition import (
    DisclosureCompositionError,
    build_composition_metadata,
    evaluate_composition_history,
    validate_event_composition,
)
from toxicjoin.disclosure.ledger import (
    DisclosureCommitmentReplay,
    DisclosureLedgerConflict,
    DisclosureLedgerError,
    DisclosureLedgerIntegrityError,
    _AUTHORIZATION_ID,
    _commitment,
    _protected_count,
    _same_privacy_scope,
)
from toxicjoin.disclosure.models import (
    CompositionRule,
    DisclosureCommitment,
    DisclosureCompositionDecision,
    DisclosureEvent,
    DisclosureRecord,
    DisclosureScope,
    compute_event_sha256,
    compute_record_sha256,
)
from toxicjoin.disclosure.topology import (
    DisclosureStateTopology,
    require_disclosure_state_topology,
    resolve_declared_replica_count,
)

_SCHEMA_NAME = re.compile(r"^[a-z][a-z0-9_]{0,62}$")
_MIN_COHORT_KEY_BYTES = 32
_COHORT_KEY_METADATA = "cohort_hmac_key_sha256"
_PENDING = "PENDING"
_RELEASED = "RELEASED"
_ABORTED = "ABORTED"


class PostgresDisclosureLedgerUnavailable(DisclosureLedgerError):
    """Raised when the optional PostgreSQL runtime dependency is unavailable."""


class PostgresDisclosureLedger:
    """PostgreSQL disclosure authority with shared, per-scope transactional serialization."""

    state_topology = DisclosureStateTopology.SHARED_AUTHORITATIVE

    def __init__(
        self,
        dsn: str,
        *,
        cohort_hmac_key: bytes,
        schema: str = "toxicjoin_disclosure",
        deployment_replica_count: int | str | None = None,
    ) -> None:
        if type(dsn) is not str or not dsn or dsn != dsn.strip():
            raise ValueError("PostgreSQL disclosure DSN must be a non-empty normalized string")
        if type(cohort_hmac_key) is not bytes or len(cohort_hmac_key) < _MIN_COHORT_KEY_BYTES:
            raise ValueError("PostgreSQL disclosure cohort HMAC key must be at least 32 bytes")
        if type(schema) is not str or not _SCHEMA_NAME.fullmatch(schema):
            raise ValueError("invalid PostgreSQL disclosure schema name")

        replica_count = resolve_declared_replica_count(deployment_replica_count)
        require_disclosure_state_topology(
            topology=self.state_topology,
            replica_count=replica_count,
        )

        psycopg, pg_sql, dict_row = _load_psycopg()
        self._psycopg = psycopg
        self._sql = pg_sql
        self._dict_row = dict_row
        self._dsn = dsn
        self._schema = schema
        self._cohort_key = bytes(cohort_hmac_key)
        self.deployment_replica_count = replica_count

        self._initialize_database()
        self._bind_cohort_key_fingerprint()

    def evaluate_and_commit(
        self,
        event: DisclosureEvent,
        *,
        sql: str,
        dialect: str = "duckdb",
    ) -> DisclosureCompositionDecision:
        """Serialize one privacy scope, evaluate global active history, and reserve an allowed release."""

        composition = build_composition_metadata(
            event.semantic,
            sql,
            secret_key=self._cohort_key,
            dialect=dialect,
        )
        bound_event = DisclosureEvent.model_validate(
            {
                **event.model_dump(mode="json"),
                "composition": composition.model_dump(mode="json"),
            }
        )
        validate_event_composition(bound_event)

        try:
            with self._connect() as connection:
                self._lock_scope(connection, bound_event.scope.scope_sha256)
                audit_history = self._records_for_scope_connection(connection, bound_event.scope)
                active_history = self._active_history_connection(connection, audit_history)
                existing = self._existing_receipt(connection, bound_event.receipt_id)
                if existing is not None:
                    if existing.event != bound_event:
                        raise DisclosureLedgerConflict(
                            "receipt_id already records different disclosure content"
                        )
                    if existing not in audit_history:
                        raise DisclosureLedgerIntegrityError(
                            "receipt index points outside validated privacy scope history"
                        )
                    state = self._release_state_connection(connection, existing.record_id)
                    if state == _ABORTED:
                        raise DisclosureLedgerConflict("aborted disclosure receipt cannot be replayed")
                    return DisclosureCompositionDecision(
                        allowed=True,
                        rule=CompositionRule.IDEMPOTENT_REPLAY,
                        protected_release=composition.protected_release,
                        prior_protected_count=_protected_count(active_history),
                        commitment=_commitment(existing),
                    )

                evaluation = evaluate_composition_history(active_history, bound_event)
                if not evaluation.allowed:
                    return DisclosureCompositionDecision(
                        allowed=False,
                        rule=evaluation.rule,
                        protected_release=evaluation.protected_release,
                        prior_protected_count=evaluation.prior_protected_count,
                    )

                record = self._append_event_connection(
                    connection,
                    bound_event,
                    history=audit_history,
                )
                self._insert_transition_connection(connection, record.record_id, _PENDING)
                return DisclosureCompositionDecision(
                    allowed=True,
                    rule=evaluation.rule,
                    protected_release=evaluation.protected_release,
                    prior_protected_count=evaluation.prior_protected_count,
                    commitment=_commitment(record),
                )
        except DisclosureLedgerError:
            raise
        except DisclosureCompositionError as exc:
            raise DisclosureLedgerIntegrityError(
                "cumulative disclosure state could not be evaluated safely"
            ) from exc
        except Exception as exc:
            if self._is_database_error(exc):
                raise DisclosureLedgerIntegrityError(
                    "PostgreSQL cumulative disclosure state could not be evaluated safely"
                ) from None
            raise

    def verify_commitment(
        self,
        commitment: DisclosureCommitment,
        event: DisclosureEvent,
        *,
        sql: str,
        dialect: str = "duckdb",
    ) -> DisclosureRecord:
        composition = build_composition_metadata(
            event.semantic,
            sql,
            secret_key=self._cohort_key,
            dialect=dialect,
        )
        bound_event = DisclosureEvent.model_validate(
            {
                **event.model_dump(mode="json"),
                "composition": composition.model_dump(mode="json"),
            }
        )
        validate_event_composition(bound_event)
        with self._connect() as connection:
            record = self._record_for_commitment_connection(connection, commitment)
            if not _same_privacy_scope(record.event.scope, bound_event.scope):
                raise DisclosureLedgerIntegrityError("disclosure commitment scope mismatch")
            if record.event != bound_event:
                raise DisclosureLedgerIntegrityError(
                    "disclosure commitment does not match current governed release"
                )
            if self._release_state_connection(connection, record.record_id) != _PENDING:
                raise DisclosureLedgerIntegrityError("disclosure commitment is not pending")
            return record

    def claim_commitment(
        self,
        commitment: DisclosureCommitment,
        authorization_id: str,
    ) -> None:
        if not _AUTHORIZATION_ID.fullmatch(authorization_id):
            raise ValueError("invalid execution authorization ID")
        try:
            with self._connect() as connection:
                record = self._record_for_commitment_connection(
                    connection,
                    commitment,
                    for_update=True,
                )
                if self._release_state_connection(connection, record.record_id) != _PENDING:
                    raise DisclosureLedgerIntegrityError("disclosure commitment is not pending")
                existing = self._fetchone(
                    connection,
                    """
                    SELECT authorization_id, receipt_id, commitment_content_sha256
                    FROM {claims}
                    WHERE record_id = %s
                    """,
                    (record.record_id,),
                )
                if existing is not None:
                    raise DisclosureCommitmentReplay(
                        "disclosure commitment was already claimed for execution"
                    )
                connection.execute(
                    self._format(
                        """
                        INSERT INTO {claims} (
                            record_id, authorization_id, receipt_id,
                            commitment_content_sha256, created_at
                        ) VALUES (%s, %s, %s, %s, %s)
                        """
                    ),
                    (
                        record.record_id,
                        authorization_id,
                        record.event.receipt_id,
                        record.content_sha256,
                        datetime.now(timezone.utc),
                    ),
                )
        except DisclosureLedgerError:
            raise
        except Exception as exc:
            if self._is_unique_violation(exc):
                raise DisclosureCommitmentReplay(
                    "disclosure commitment claim uniqueness conflict"
                ) from None
            raise

    def verify_authorization_claim(
        self,
        commitment: DisclosureCommitment,
        authorization_id: str,
    ) -> None:
        if not _AUTHORIZATION_ID.fullmatch(authorization_id):
            raise DisclosureLedgerIntegrityError("invalid claimed authorization ID")
        with self._connect() as connection:
            record = self._record_for_commitment_connection(connection, commitment)
            if self._release_state_connection(connection, record.record_id) != _PENDING:
                raise DisclosureLedgerIntegrityError("disclosure commitment is not pending")
            row = self._fetchone(
                connection,
                """
                SELECT authorization_id, receipt_id, commitment_content_sha256
                FROM {claims}
                WHERE record_id = %s
                """,
                (record.record_id,),
            )
        if row is None:
            raise DisclosureLedgerIntegrityError("disclosure commitment has no authorization claim")
        if (
            str(row["authorization_id"]) != authorization_id
            or str(row["receipt_id"]) != commitment.receipt_id
            or str(row["commitment_content_sha256"]) != commitment.content_sha256
            or record.content_sha256 != commitment.content_sha256
        ):
            raise DisclosureLedgerIntegrityError(
                "disclosure authorization claim does not match commitment"
            )

    def mark_released(self, commitment: DisclosureCommitment) -> None:
        with self._connect() as connection:
            record = self._record_for_commitment_connection(
                connection,
                commitment,
                for_update=True,
            )
            state = self._release_state_connection(connection, record.record_id)
            if state == _RELEASED:
                return
            if state != _PENDING:
                raise DisclosureLedgerIntegrityError(
                    f"cannot release disclosure from state {state}"
                )
            claim = self._fetchone(
                connection,
                "SELECT 1 AS present FROM {claims} WHERE record_id = %s",
                (record.record_id,),
            )
            if claim is None:
                raise DisclosureLedgerIntegrityError(
                    "cannot release disclosure without an execution authorization claim"
                )
            self._insert_transition_connection(connection, record.record_id, _RELEASED)

    def mark_aborted(self, commitment: DisclosureCommitment) -> None:
        with self._connect() as connection:
            record = self._record_for_commitment_connection(
                connection,
                commitment,
                for_update=True,
            )
            state = self._release_state_connection(connection, record.record_id)
            if state == _ABORTED:
                return
            if state != _PENDING:
                raise DisclosureLedgerIntegrityError(
                    f"cannot abort disclosure from state {state}"
                )
            self._insert_transition_connection(connection, record.record_id, _ABORTED)

    def release_state(self, commitment: DisclosureCommitment) -> str:
        with self._connect() as connection:
            record = self._record_for_commitment_connection(connection, commitment)
            return self._release_state_connection(connection, record.record_id)

    def read_receipt(self, receipt_id: str) -> DisclosureRecord:
        with self._connect() as connection:
            row = self._fetchone(
                connection,
                "SELECT * FROM {records} WHERE receipt_id = %s",
                (receipt_id,),
            )
        if row is None:
            raise KeyError(receipt_id)
        return self._row_to_record(row)

    def list_for_scope(self, scope: DisclosureScope) -> tuple[DisclosureRecord, ...]:
        with self._connect() as connection:
            return self._records_for_scope_connection(connection, scope)

    def verify_all(self) -> int:
        with self._connect() as connection:
            rows = self._fetchall(
                connection,
                "SELECT DISTINCT scope_sha256 FROM {records} ORDER BY scope_sha256",
            )
        count = 0
        for row in rows:
            scope_hash = str(row["scope_sha256"])
            with self._connect() as connection:
                first = self._fetchone(
                    connection,
                    """
                    SELECT * FROM {records}
                    WHERE scope_sha256 = %s
                    ORDER BY sequence ASC
                    LIMIT 1
                    """,
                    (scope_hash,),
                )
            if first is None:
                continue
            scope = self._row_to_record(first).event.scope
            count += len(self.list_for_scope(scope))

        with self._connect() as connection:
            claim_rows = self._fetchall(
                connection,
                """
                SELECT record_id, authorization_id, receipt_id, commitment_content_sha256
                FROM {claims}
                ORDER BY record_id
                """,
            )
            for row in claim_rows:
                record_row = self._fetchone(
                    connection,
                    "SELECT * FROM {records} WHERE record_id = %s",
                    (str(row["record_id"]),),
                )
                if record_row is None:
                    raise DisclosureLedgerIntegrityError(
                        "authorization claim references missing disclosure record"
                    )
                record = self._row_to_record(record_row)
                if (
                    not _AUTHORIZATION_ID.fullmatch(str(row["authorization_id"]))
                    or str(row["receipt_id"]) != record.event.receipt_id
                    or str(row["commitment_content_sha256"]) != record.content_sha256
                ):
                    raise DisclosureLedgerIntegrityError(
                        "authorization claim does not match disclosure record"
                    )
                state = self._release_state_connection(connection, record.record_id)
                if state == _RELEASED:
                    transitions = self._transition_states_connection(connection, record.record_id)
                    if transitions and row is None:
                        raise DisclosureLedgerIntegrityError(
                            "released disclosure is missing execution authorization claim"
                        )
        return count

    def _initialize_database(self) -> None:
        schema = self._identifier(self._schema)
        with self._connect() as connection:
            connection.execute(self._sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(schema))
            connection.execute(
                self._sql.SQL("CREATE SEQUENCE IF NOT EXISTS {}.disclosure_sequence").format(schema)
            )
            connection.execute(
                self._sql.SQL(
                    """
                    CREATE TABLE IF NOT EXISTS {}.disclosure_scope_locks (
                        scope_sha256 TEXT PRIMARY KEY
                    )
                    """
                ).format(schema)
            )
            connection.execute(
                self._sql.SQL(
                    """
                    CREATE TABLE IF NOT EXISTS {}.disclosure_records (
                        sequence BIGINT PRIMARY KEY,
                        record_id TEXT NOT NULL UNIQUE,
                        scope_sha256 TEXT NOT NULL,
                        receipt_id TEXT NOT NULL UNIQUE,
                        event_sha256 TEXT NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL,
                        previous_content_sha256 TEXT,
                        content_sha256 TEXT NOT NULL,
                        payload_json TEXT NOT NULL
                    )
                    """
                ).format(schema)
            )
            connection.execute(
                self._sql.SQL(
                    """
                    CREATE INDEX IF NOT EXISTS disclosure_records_scope_sequence
                    ON {}.disclosure_records(scope_sha256, sequence)
                    """
                ).format(schema)
            )
            connection.execute(
                self._sql.SQL(
                    """
                    CREATE TABLE IF NOT EXISTS {}.disclosure_metadata (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL
                    )
                    """
                ).format(schema)
            )
            connection.execute(
                self._sql.SQL(
                    """
                    CREATE TABLE IF NOT EXISTS {}.disclosure_authorization_claims (
                        record_id TEXT PRIMARY KEY REFERENCES {}.disclosure_records(record_id),
                        authorization_id TEXT NOT NULL UNIQUE,
                        receipt_id TEXT NOT NULL,
                        commitment_content_sha256 TEXT NOT NULL,
                        created_at TIMESTAMPTZ NOT NULL
                    )
                    """
                ).format(schema, schema)
            )
            connection.execute(
                self._sql.SQL(
                    """
                    CREATE TABLE IF NOT EXISTS {}.disclosure_release_transitions (
                        transition_id BIGSERIAL PRIMARY KEY,
                        record_id TEXT NOT NULL REFERENCES {}.disclosure_records(record_id),
                        state TEXT NOT NULL CHECK (state IN ('PENDING', 'RELEASED', 'ABORTED')),
                        created_at TIMESTAMPTZ NOT NULL
                    )
                    """
                ).format(schema, schema)
            )
            connection.execute(
                self._sql.SQL(
                    """
                    CREATE INDEX IF NOT EXISTS disclosure_release_transitions_record
                    ON {}.disclosure_release_transitions(record_id, transition_id)
                    """
                ).format(schema)
            )

    def _bind_cohort_key_fingerprint(self) -> None:
        fingerprint = hashlib.sha256(self._cohort_key).hexdigest()
        with self._connect() as connection:
            connection.execute(
                self._format(
                    """
                    INSERT INTO {metadata}(key, value)
                    VALUES (%s, %s)
                    ON CONFLICT (key) DO NOTHING
                    """
                ),
                (_COHORT_KEY_METADATA, fingerprint),
            )
            row = self._fetchone(
                connection,
                "SELECT value FROM {metadata} WHERE key = %s",
                (_COHORT_KEY_METADATA,),
            )
        if row is None or not hmac.compare_digest(str(row["value"]), fingerprint):
            raise DisclosureLedgerIntegrityError(
                "PostgreSQL disclosure cohort key does not match authoritative state"
            )

    def _lock_scope(self, connection: Any, scope_sha256: str) -> None:
        connection.execute(
            self._format(
                """
                INSERT INTO {scope_locks}(scope_sha256)
                VALUES (%s)
                ON CONFLICT (scope_sha256) DO NOTHING
                """
            ),
            (scope_sha256,),
        )
        row = self._fetchone(
            connection,
            "SELECT scope_sha256 FROM {scope_locks} WHERE scope_sha256 = %s FOR UPDATE",
            (scope_sha256,),
        )
        if row is None or str(row["scope_sha256"]) != scope_sha256:
            raise DisclosureLedgerIntegrityError("failed to lock authoritative disclosure scope")

    def _append_event_connection(
        self,
        connection: Any,
        event: DisclosureEvent,
        *,
        history: tuple[DisclosureRecord, ...],
    ) -> DisclosureRecord:
        validate_event_composition(event)
        previous_sha256 = history[-1].content_sha256 if history else None
        sequence_row = connection.execute(
            "SELECT nextval(%s::regclass) AS sequence",
            (f"{self._schema}.disclosure_sequence",),
        ).fetchone()
        sequence = int(sequence_row["sequence"])
        created_at = datetime.now(timezone.utc)
        record_id = f"dl_{uuid4().hex}"
        schema_version = "1.1" if event.composition is not None else "1.0"
        event_sha256 = compute_event_sha256(event)
        provisional = DisclosureRecord.model_construct(
            schema_version=schema_version,
            record_id=record_id,
            sequence=sequence,
            created_at=created_at,
            event=event,
            event_sha256=event_sha256,
            previous_content_sha256=previous_sha256,
            content_sha256="0" * 64,
        )
        content_sha256 = compute_record_sha256(provisional)
        record = DisclosureRecord(
            schema_version=schema_version,
            record_id=record_id,
            sequence=sequence,
            created_at=created_at,
            event=event,
            event_sha256=event_sha256,
            previous_content_sha256=previous_sha256,
            content_sha256=content_sha256,
        )
        payload_json = json.dumps(
            record.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
        connection.execute(
            self._format(
                """
                INSERT INTO {records} (
                    sequence, record_id, scope_sha256, receipt_id, event_sha256,
                    created_at, previous_content_sha256, content_sha256, payload_json
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """
            ),
            (
                record.sequence,
                record.record_id,
                record.event.scope.scope_sha256,
                record.event.receipt_id,
                record.event_sha256,
                record.created_at,
                record.previous_content_sha256,
                record.content_sha256,
                payload_json,
            ),
        )
        return record

    def _records_for_scope_connection(
        self,
        connection: Any,
        scope: DisclosureScope,
    ) -> tuple[DisclosureRecord, ...]:
        rows = self._fetchall(
            connection,
            """
            SELECT * FROM {records}
            WHERE scope_sha256 = %s
            ORDER BY sequence ASC
            """,
            (scope.scope_sha256,),
        )
        records = tuple(self._row_to_record(row) for row in rows)
        previous: str | None = None
        for record in records:
            if not _same_privacy_scope(record.event.scope, scope):
                raise DisclosureLedgerIntegrityError("scope payload does not match index")
            if record.previous_content_sha256 != previous:
                raise DisclosureLedgerIntegrityError("disclosure scope hash chain is broken")
            previous = record.content_sha256
        return records

    def _active_history_connection(
        self,
        connection: Any,
        audit_history: tuple[DisclosureRecord, ...],
    ) -> tuple[DisclosureRecord, ...]:
        return tuple(
            record
            for record in audit_history
            if self._release_state_connection(connection, record.record_id) != _ABORTED
        )

    def _existing_receipt(self, connection: Any, receipt_id: str) -> DisclosureRecord | None:
        row = self._fetchone(
            connection,
            "SELECT * FROM {records} WHERE receipt_id = %s",
            (receipt_id,),
        )
        return self._row_to_record(row) if row is not None else None

    def _record_for_commitment_connection(
        self,
        connection: Any,
        commitment: DisclosureCommitment,
        *,
        for_update: bool = False,
    ) -> DisclosureRecord:
        suffix = " FOR UPDATE" if for_update else ""
        row = self._fetchone(
            connection,
            "SELECT * FROM {records} WHERE record_id = %s" + suffix,
            (commitment.record_id,),
        )
        if row is None:
            raise DisclosureLedgerIntegrityError("disclosure commitment record is missing")
        record = self._row_to_record(row)
        if _commitment(record) != commitment:
            raise DisclosureLedgerIntegrityError("disclosure commitment hash mismatch")
        return record

    def _release_state_connection(self, connection: Any, record_id: str) -> str:
        states = self._transition_states_connection(connection, record_id)
        if not states:
            return _RELEASED
        if states == (_PENDING,):
            return _PENDING
        if states == (_PENDING, _RELEASED):
            return _RELEASED
        if states == (_PENDING, _ABORTED):
            return _ABORTED
        raise DisclosureLedgerIntegrityError(
            f"invalid disclosure release transition sequence for {record_id}: {states}"
        )

    def _transition_states_connection(self, connection: Any, record_id: str) -> tuple[str, ...]:
        rows = self._fetchall(
            connection,
            """
            SELECT state FROM {transitions}
            WHERE record_id = %s
            ORDER BY transition_id ASC
            """,
            (record_id,),
        )
        return tuple(str(row["state"]) for row in rows)

    def _insert_transition_connection(self, connection: Any, record_id: str, state: str) -> None:
        states = self._transition_states_connection(connection, record_id)
        if state == _PENDING:
            if states:
                raise DisclosureLedgerIntegrityError("PENDING must be the first release transition")
        elif state in (_RELEASED, _ABORTED):
            if states != (_PENDING,):
                raise DisclosureLedgerIntegrityError(
                    "terminal release transition requires exactly one PENDING state"
                )
        else:
            raise DisclosureLedgerIntegrityError("invalid disclosure release transition")
        connection.execute(
            self._format(
                """
                INSERT INTO {transitions}(record_id, state, created_at)
                VALUES (%s, %s, %s)
                """
            ),
            (record_id, state, datetime.now(timezone.utc)),
        )

    def _row_to_record(self, row: Any) -> DisclosureRecord:
        try:
            payload = row["payload_json"]
            if type(payload) is str:
                decoded = json.loads(payload)
            elif type(payload) is dict:
                decoded = payload
            else:
                raise ValueError("invalid PostgreSQL disclosure payload type")
            record = DisclosureRecord.model_validate(decoded)
        except Exception as exc:
            raise DisclosureLedgerIntegrityError("invalid persisted disclosure record") from exc

        if (
            int(row["sequence"]) != record.sequence
            or str(row["record_id"]) != record.record_id
            or str(row["scope_sha256"]) != record.event.scope.scope_sha256
            or str(row["receipt_id"]) != record.event.receipt_id
            or str(row["event_sha256"]) != record.event_sha256
            or str(row["content_sha256"]) != record.content_sha256
            or _nullable_text(row["previous_content_sha256"]) != record.previous_content_sha256
        ):
            raise DisclosureLedgerIntegrityError("disclosure record index does not match payload")
        if compute_event_sha256(record.event) != record.event_sha256:
            raise DisclosureLedgerIntegrityError("disclosure event hash mismatch")
        if compute_record_sha256(record) != record.content_sha256:
            raise DisclosureLedgerIntegrityError("disclosure record content hash mismatch")
        return record

    def _connect(self):
        return self._psycopg.connect(
            self._dsn,
            autocommit=False,
            row_factory=self._dict_row,
        )

    def _identifier(self, value: str):
        return self._sql.Identifier(value)

    def _format(self, template: str):
        return self._sql.SQL(template).format(
            records=self._qualified("disclosure_records"),
            metadata=self._qualified("disclosure_metadata"),
            claims=self._qualified("disclosure_authorization_claims"),
            transitions=self._qualified("disclosure_release_transitions"),
            scope_locks=self._qualified("disclosure_scope_locks"),
        )

    def _qualified(self, table: str):
        return self._sql.SQL("{}.{}").format(
            self._identifier(self._schema),
            self._identifier(table),
        )

    def _fetchone(self, connection: Any, template: str, params: tuple[Any, ...] = ()):
        return connection.execute(self._format(template), params).fetchone()

    def _fetchall(self, connection: Any, template: str, params: tuple[Any, ...] = ()):
        return connection.execute(self._format(template), params).fetchall()

    def _is_database_error(self, error: BaseException) -> bool:
        return isinstance(error, self._psycopg.Error)

    def _is_unique_violation(self, error: BaseException) -> bool:
        errors = getattr(self._psycopg, "errors", None)
        unique_violation = getattr(errors, "UniqueViolation", ()) if errors is not None else ()
        return isinstance(error, unique_violation)


def _load_psycopg():
    try:
        import psycopg
        from psycopg import sql
        from psycopg.rows import dict_row
    except ImportError:
        raise PostgresDisclosureLedgerUnavailable(
            "PostgreSQL disclosure backend requires Psycopg 3"
        ) from None
    return psycopg, sql, dict_row


def _nullable_text(value: object) -> str | None:
    return None if value is None else str(value)
