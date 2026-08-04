"""Transactional append-only persistence and cumulative disclosure authorization."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from toxicjoin.disclosure.composition import (
    DisclosureCompositionError,
    build_composition_metadata,
    evaluate_composition_history,
    is_protected_release,
    validate_event_composition,
)
from toxicjoin.disclosure.models import (
    CompositionRule,
    DisclosureBudget,
    DisclosureCommitment,
    DisclosureCompositionDecision,
    DisclosureEvent,
    DisclosureRecord,
    DisclosureScope,
    compute_event_sha256,
    compute_record_sha256,
)


_SCHEMA_VERSION = 2
_COHORT_KEY_BYTES = 32
_COHORT_KEY_METADATA = "cohort_hmac_key_sha256"
_AUTHORIZATION_ID = re.compile(r"^tj_auth_[0-9a-f]{32}$")


class DisclosureLedgerError(RuntimeError):
    """Base error for disclosure-ledger persistence failures."""


class DisclosureLedgerConflict(DisclosureLedgerError):
    """Raised when an idempotency key is reused for different disclosure content."""


class DisclosureCommitmentReplay(DisclosureLedgerConflict):
    """Raised when one disclosure commitment is claimed for a second capability."""


class DisclosureLedgerIntegrityError(DisclosureLedgerError):
    """Raised when persisted ledger content or its per-scope hash chain is invalid."""


class DisclosureLedger:
    """SQLite-backed append-only disclosure ledger with serialized privacy decisions.

    ``evaluate_and_commit`` acquires a SQLite writer lock, validates the complete scope
    history, evaluates cumulative release risk, and appends an allowed release before
    releasing the transaction. The resulting commitment must then be verified and
    single-claimed by the execution authorizer before a capability can be issued.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        busy_timeout_ms: int = 5_000,
        cohort_key_path: str | Path | None = None,
        budget: DisclosureBudget | None = None,
    ) -> None:
        self.budget = budget if budget is not None else DisclosureBudget.from_environment()
        self.path = Path(path)
        self.cohort_key_path = (
            Path(cohort_key_path)
            if cohort_key_path is not None
            else self.path.with_name(f"{self.path.name}.cohort.key")
        )
        if busy_timeout_ms < 1 or busy_timeout_ms > 60_000:
            raise ValueError("busy_timeout_ms must be between 1 and 60000")
        self.busy_timeout_ms = busy_timeout_ms
        previous_version = self._initialize_database()
        self._cohort_key = self._load_or_create_cohort_key(previous_version)
        self._bind_cohort_key_fingerprint()

    def append(self, event: DisclosureEvent) -> DisclosureRecord:
        """Append a legacy/foundation event without composition authorization.

        Runtime execution paths must use ``evaluate_and_commit``. This primitive remains
        for migration/tests and intentionally creates schema 1.0 records when no
        composition metadata is present; protected legacy history then fails closed in
        the cumulative gate.
        """

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            history = self._records_for_scope_connection(connection, event.scope)
            existing = self._existing_receipt(connection, event.receipt_id)
            if existing is not None:
                if existing.event != event:
                    raise DisclosureLedgerConflict(
                        "receipt_id already records different disclosure content"
                    )
                connection.commit()
                return existing
            record = self._append_event_connection(connection, event, history=history)
            connection.commit()
            return record
        except DisclosureLedgerError:
            connection.rollback()
            raise
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise DisclosureLedgerConflict("disclosure ledger uniqueness conflict") from exc
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def evaluate_and_commit(
        self,
        event: DisclosureEvent,
        *,
        sql: str,
        dialect: str = "duckdb",
    ) -> DisclosureCompositionDecision:
        """Atomically evaluate cumulative history and commit an allowed release."""

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

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            history = self._records_for_scope_connection(connection, bound_event.scope)
            existing = self._existing_receipt(connection, bound_event.receipt_id)
            if existing is not None:
                if existing.event != bound_event:
                    raise DisclosureLedgerConflict(
                        "receipt_id already records different disclosure content"
                    )
                if existing not in history:
                    raise DisclosureLedgerIntegrityError(
                        "receipt index points outside validated privacy scope history"
                    )
                commitment = _commitment(existing)
                connection.commit()
                return DisclosureCompositionDecision(
                    allowed=True,
                    rule=CompositionRule.IDEMPOTENT_REPLAY,
                    protected_release=composition.protected_release,
                    prior_protected_count=_protected_count(history),
                    commitment=commitment,
                )

            evaluation = evaluate_composition_history(
                history,
                bound_event,
                budget=self.budget,
            )
            if not evaluation.allowed:
                connection.rollback()
                return DisclosureCompositionDecision(
                    allowed=False,
                    rule=evaluation.rule,
                    protected_release=evaluation.protected_release,
                    prior_protected_count=evaluation.prior_protected_count,
                )

            record = self._append_event_connection(
                connection,
                bound_event,
                history=history,
            )
            commitment = _commitment(record)
            connection.commit()
            return DisclosureCompositionDecision(
                allowed=True,
                rule=evaluation.rule,
                protected_release=evaluation.protected_release,
                prior_protected_count=evaluation.prior_protected_count,
                commitment=commitment,
            )
        except DisclosureLedgerError:
            connection.rollback()
            raise
        except (DisclosureCompositionError, sqlite3.DatabaseError) as exc:
            connection.rollback()
            raise DisclosureLedgerIntegrityError(
                "cumulative disclosure state could not be evaluated safely"
            ) from exc
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def verify_commitment(
        self,
        commitment: DisclosureCommitment,
        event: DisclosureEvent,
        *,
        sql: str,
        dialect: str = "duckdb",
    ) -> DisclosureRecord:
        """Recompute and verify the exact committed release before capability issuance."""

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
        history = self.list_for_scope(bound_event.scope)
        matches = tuple(
            record for record in history if record.event.receipt_id == commitment.receipt_id
        )
        if len(matches) != 1:
            raise DisclosureLedgerIntegrityError("disclosure commitment receipt is not unique")
        record = matches[0]
        if record.event != bound_event:
            raise DisclosureLedgerIntegrityError(
                "disclosure commitment does not match current governed release"
            )
        expected = _commitment(record)
        if expected != commitment:
            raise DisclosureLedgerIntegrityError("disclosure commitment hash mismatch")
        return record

    def claim_commitment(
        self,
        commitment: DisclosureCommitment,
        authorization_id: str,
    ) -> None:
        """Bind one committed release to exactly one execution capability ID."""

        if not _AUTHORIZATION_ID.fullmatch(authorization_id):
            raise ValueError("invalid execution authorization ID")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            record = self._record_for_commitment_connection(connection, commitment)
            existing = connection.execute(
                """
                SELECT authorization_id, receipt_id, commitment_content_sha256
                FROM disclosure_authorization_claims
                WHERE record_id = ?
                """,
                (commitment.record_id,),
            ).fetchone()
            if existing is not None:
                raise DisclosureCommitmentReplay(
                    "disclosure commitment was already claimed for execution"
                )
            connection.execute(
                """
                INSERT INTO disclosure_authorization_claims (
                    record_id,
                    authorization_id,
                    receipt_id,
                    commitment_content_sha256,
                    created_at
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    record.record_id,
                    authorization_id,
                    record.event.receipt_id,
                    record.content_sha256,
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            connection.commit()
        except DisclosureLedgerError:
            connection.rollback()
            raise
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise DisclosureCommitmentReplay(
                "disclosure commitment claim uniqueness conflict"
            ) from exc
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def verify_authorization_claim(
        self,
        commitment: DisclosureCommitment,
        authorization_id: str,
    ) -> None:
        """Verify that this exact capability owns the committed release claim."""

        if not _AUTHORIZATION_ID.fullmatch(authorization_id):
            raise DisclosureLedgerIntegrityError("invalid claimed authorization ID")
        connection = self._connect()
        try:
            record = self._record_for_commitment_connection(connection, commitment)
            row = connection.execute(
                """
                SELECT authorization_id, receipt_id, commitment_content_sha256
                FROM disclosure_authorization_claims
                WHERE record_id = ?
                """,
                (commitment.record_id,),
            ).fetchone()
        finally:
            connection.close()
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

    def read_receipt(self, receipt_id: str) -> DisclosureRecord:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT * FROM disclosure_records WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
        finally:
            connection.close()
        if row is None:
            raise KeyError(receipt_id)
        return self._row_to_record(row)

    def list_for_scope(self, scope: DisclosureScope) -> tuple[DisclosureRecord, ...]:
        connection = self._connect()
        try:
            return self._records_for_scope_connection(connection, scope)
        finally:
            connection.close()

    def verify_all(self) -> int:
        """Validate all records, indexes, composition bindings, and scope chains."""

        connection = self._connect()
        try:
            scope_rows = connection.execute(
                "SELECT DISTINCT scope_sha256 FROM disclosure_records"
            ).fetchall()
        finally:
            connection.close()

        count = 0
        for row in scope_rows:
            scope_hash = str(row["scope_sha256"])
            connection = self._connect()
            try:
                first = connection.execute(
                    """
                    SELECT * FROM disclosure_records
                    WHERE scope_sha256 = ?
                    ORDER BY sequence ASC
                    LIMIT 1
                    """,
                    (scope_hash,),
                ).fetchone()
            finally:
                connection.close()
            if first is None:
                continue
            scope = self._row_to_record(first).event.scope
            count += len(self.list_for_scope(scope))
        self._verify_all_claims()
        return count

    def _append_event_connection(
        self,
        connection: sqlite3.Connection,
        event: DisclosureEvent,
        *,
        history: tuple[DisclosureRecord, ...],
    ) -> DisclosureRecord:
        validate_event_composition(event)
        previous_sha256 = history[-1].content_sha256 if history else None
        sequence = int(
            connection.execute(
                "SELECT COALESCE(MAX(sequence), 0) + 1 FROM disclosure_records"
            ).fetchone()[0]
        )
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
            """
            INSERT INTO disclosure_records (
                sequence,
                record_id,
                scope_sha256,
                receipt_id,
                event_sha256,
                created_at,
                previous_content_sha256,
                content_sha256,
                payload_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record.sequence,
                record.record_id,
                record.event.scope.scope_sha256,
                record.event.receipt_id,
                record.event_sha256,
                record.created_at.isoformat(),
                record.previous_content_sha256,
                record.content_sha256,
                payload_json,
            ),
        )
        return record

    def _records_for_scope_connection(
        self,
        connection: sqlite3.Connection,
        scope: DisclosureScope,
    ) -> tuple[DisclosureRecord, ...]:
        rows = connection.execute(
            """
            SELECT * FROM disclosure_records
            WHERE scope_sha256 = ?
            ORDER BY sequence ASC
            """,
            (scope.scope_sha256,),
        ).fetchall()
        records = tuple(self._row_to_record(row) for row in rows)
        previous: str | None = None
        for record in records:
            if not _same_privacy_scope(record.event.scope, scope):
                raise DisclosureLedgerIntegrityError("scope payload does not match index")
            if record.previous_content_sha256 != previous:
                raise DisclosureLedgerIntegrityError("disclosure scope hash chain is broken")
            previous = record.content_sha256
        return records

    def _existing_receipt(
        self,
        connection: sqlite3.Connection,
        receipt_id: str,
    ) -> DisclosureRecord | None:
        row = connection.execute(
            "SELECT * FROM disclosure_records WHERE receipt_id = ?",
            (receipt_id,),
        ).fetchone()
        return self._row_to_record(row) if row is not None else None

    def _record_for_commitment_connection(
        self,
        connection: sqlite3.Connection,
        commitment: DisclosureCommitment,
    ) -> DisclosureRecord:
        row = connection.execute(
            "SELECT * FROM disclosure_records WHERE record_id = ?",
            (commitment.record_id,),
        ).fetchone()
        if row is None:
            raise DisclosureLedgerIntegrityError("disclosure commitment record is missing")
        record = self._row_to_record(row)
        if _commitment(record) != commitment:
            raise DisclosureLedgerIntegrityError("disclosure commitment hash mismatch")
        return record

    def _verify_all_claims(self) -> None:
        connection = self._connect()
        try:
            rows = connection.execute(
                """
                SELECT record_id, authorization_id, receipt_id, commitment_content_sha256
                FROM disclosure_authorization_claims
                ORDER BY record_id
                """
            ).fetchall()
            for row in rows:
                record_row = connection.execute(
                    "SELECT * FROM disclosure_records WHERE record_id = ?",
                    (str(row["record_id"]),),
                ).fetchone()
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
        finally:
            connection.close()

    def _initialize_database(self) -> int:
        if self.path.exists() and self.path.is_symlink():
            raise ValueError("disclosure ledger path must not be a symbolic link")
        self.path.parent.mkdir(parents=True, exist_ok=True)

        if not self.path.exists():
            try:
                descriptor = os.open(
                    self.path,
                    os.O_RDWR | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except FileExistsError:
                pass
            else:
                os.close(descriptor)
        if self.path.is_symlink():
            raise ValueError("disclosure ledger path must not be a symbolic link")

        connection = self._connect(create=True)
        try:
            current_version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            if current_version not in (0, 1, _SCHEMA_VERSION):
                raise DisclosureLedgerIntegrityError(
                    f"unsupported disclosure ledger schema version: {current_version}"
                )
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS disclosure_records (
                    sequence INTEGER PRIMARY KEY,
                    record_id TEXT NOT NULL UNIQUE,
                    scope_sha256 TEXT NOT NULL,
                    receipt_id TEXT NOT NULL UNIQUE,
                    event_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    previous_content_sha256 TEXT,
                    content_sha256 TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS disclosure_records_scope_sequence
                ON disclosure_records(scope_sha256, sequence);

                CREATE TABLE IF NOT EXISTS disclosure_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS disclosure_authorization_claims (
                    record_id TEXT PRIMARY KEY,
                    authorization_id TEXT NOT NULL UNIQUE,
                    receipt_id TEXT NOT NULL,
                    commitment_content_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );

                CREATE TRIGGER IF NOT EXISTS disclosure_records_no_update
                BEFORE UPDATE ON disclosure_records
                BEGIN
                    SELECT RAISE(ABORT, 'disclosure ledger is append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS disclosure_records_no_delete
                BEFORE DELETE ON disclosure_records
                BEGIN
                    SELECT RAISE(ABORT, 'disclosure ledger is append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS disclosure_metadata_no_update
                BEFORE UPDATE ON disclosure_metadata
                BEGIN
                    SELECT RAISE(ABORT, 'disclosure metadata is immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS disclosure_metadata_no_delete
                BEFORE DELETE ON disclosure_metadata
                BEGIN
                    SELECT RAISE(ABORT, 'disclosure metadata is immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS disclosure_authorization_claims_no_update
                BEFORE UPDATE ON disclosure_authorization_claims
                BEGIN
                    SELECT RAISE(ABORT, 'disclosure authorization claims are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS disclosure_authorization_claims_no_delete
                BEFORE DELETE ON disclosure_authorization_claims
                BEGIN
                    SELECT RAISE(ABORT, 'disclosure authorization claims are append-only');
                END;
                """
            )
            if current_version < _SCHEMA_VERSION:
                connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            connection.commit()
        finally:
            connection.close()
        try:
            os.chmod(self.path, 0o600)
        except OSError as exc:
            raise DisclosureLedgerError("unable to secure disclosure ledger permissions") from exc
        return current_version

    def _load_or_create_cohort_key(self, previous_version: int) -> bytes:
        path = self.cohort_key_path
        if path.exists() and path.is_symlink():
            raise DisclosureLedgerIntegrityError("cohort key path must not be a symbolic link")
        path.parent.mkdir(parents=True, exist_ok=True)

        if not path.exists():
            if previous_version >= _SCHEMA_VERSION:
                raise DisclosureLedgerIntegrityError(
                    "cumulative disclosure cohort key is missing"
                )
            key = secrets.token_bytes(_COHORT_KEY_BYTES)
            try:
                descriptor = os.open(
                    path,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except FileExistsError:
                pass
            else:
                try:
                    with os.fdopen(descriptor, "wb") as handle:
                        handle.write(key)
                        handle.flush()
                        os.fsync(handle.fileno())
                except Exception:
                    path.unlink(missing_ok=True)
                    raise

        if path.is_symlink():
            raise DisclosureLedgerIntegrityError("cohort key path must not be a symbolic link")
        try:
            key = path.read_bytes()
        except OSError as exc:
            raise DisclosureLedgerIntegrityError("unable to read cohort HMAC key") from exc
        if len(key) != _COHORT_KEY_BYTES:
            raise DisclosureLedgerIntegrityError("cohort HMAC key has invalid length")
        try:
            os.chmod(path, 0o600)
        except OSError as exc:
            raise DisclosureLedgerError("unable to secure cohort HMAC key permissions") from exc
        return key

    def _bind_cohort_key_fingerprint(self) -> None:
        fingerprint = hashlib.sha256(self._cohort_key).hexdigest()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT value FROM disclosure_metadata WHERE key = ?",
                (_COHORT_KEY_METADATA,),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO disclosure_metadata(key, value) VALUES (?, ?)",
                    (_COHORT_KEY_METADATA, fingerprint),
                )
            elif str(row["value"]) != fingerprint:
                raise DisclosureLedgerIntegrityError(
                    "cohort HMAC key does not match ledger metadata"
                )
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _connect(self, *, create: bool = False) -> sqlite3.Connection:
        if not create and not self.path.exists():
            raise DisclosureLedgerIntegrityError("disclosure ledger database is missing")
        connection = sqlite3.connect(
            self.path,
            timeout=self.busy_timeout_ms / 1000,
            isolation_level=None,
        )
        connection.row_factory = sqlite3.Row
        connection.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> DisclosureRecord:
        try:
            raw = json.loads(str(row["payload_json"]))
            record = DisclosureRecord.model_validate(raw)
            validate_event_composition(record.event)
        except (json.JSONDecodeError, ValueError, DisclosureCompositionError) as exc:
            raise DisclosureLedgerIntegrityError(
                "persisted disclosure record failed validation"
            ) from exc

        indexed = {
            "sequence": int(row["sequence"]),
            "record_id": str(row["record_id"]),
            "scope_sha256": str(row["scope_sha256"]),
            "receipt_id": str(row["receipt_id"]),
            "event_sha256": str(row["event_sha256"]),
            "previous_content_sha256": row["previous_content_sha256"],
            "content_sha256": str(row["content_sha256"]),
        }
        expected = {
            "sequence": record.sequence,
            "record_id": record.record_id,
            "scope_sha256": record.event.scope.scope_sha256,
            "receipt_id": record.event.receipt_id,
            "event_sha256": record.event_sha256,
            "previous_content_sha256": record.previous_content_sha256,
            "content_sha256": record.content_sha256,
        }
        if indexed != expected:
            raise DisclosureLedgerIntegrityError(
                "disclosure ledger index fields do not match payload"
            )
        return record


def _protected_count(records: tuple[DisclosureRecord, ...]) -> int:
    return sum(is_protected_release(record.event.semantic) for record in records)


def _commitment(record: DisclosureRecord) -> DisclosureCommitment:
    return DisclosureCommitment(
        record_id=record.record_id,
        receipt_id=record.event.receipt_id,
        scope_sha256=record.event.scope.scope_sha256,
        event_sha256=record.event_sha256,
        content_sha256=record.content_sha256,
    )


def _same_privacy_scope(left: DisclosureScope, right: DisclosureScope) -> bool:
    """Compare security-partitioning fields while allowing audit dataset/domain rotation."""

    return (
        left.scope_sha256 == right.scope_sha256
        and left.principal_id == right.principal_id
        and left.agent_id == right.agent_id
        and left.subject.namespace_sha256 == right.subject.namespace_sha256
        and left.subject.field_path.casefold() == right.subject.field_path.casefold()
        and left.subject.category == right.subject.category
    )
