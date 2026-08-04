"""Two-phase release state layered over the append-only disclosure ledger.

The base ledger provides immutable, hash-chained disclosure records and authorization
claims. This layer adds an append-only release-state journal so an allowed disclosure
can be reserved before execution without permanently consuming the privacy scope when
execution or post-execution verification fails.

State machine for records created through the runtime gate:

    PENDING -> RELEASED
            -> ABORTED

Legacy records that predate this journal have no transition rows and are conservatively
treated as RELEASED. PENDING records remain active in composition history so concurrent
requests cannot race around the cumulative gate. ABORTED records stay in the audit hash
chain but are excluded from future composition decisions.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone

from toxicjoin.disclosure.composition import (
    DisclosureCompositionError,
    build_composition_metadata,
    evaluate_composition_history,
    validate_event_composition,
)
from toxicjoin.disclosure.ledger import (
    DisclosureLedger as _BaseDisclosureLedger,
    DisclosureLedgerConflict,
    DisclosureLedgerError,
    DisclosureLedgerIntegrityError,
    _commitment,
    _protected_count,
)
from toxicjoin.disclosure.models import (
    CompositionRule,
    DisclosureCommitment,
    DisclosureCompositionDecision,
    DisclosureEvent,
    DisclosureRecord,
)

_PENDING = "PENDING"
_RELEASED = "RELEASED"
_ABORTED = "ABORTED"
_TERMINAL_STATES = {_RELEASED, _ABORTED}


class DisclosureLedger(_BaseDisclosureLedger):
    """Disclosure ledger with atomic reservation and append-only release finalization."""

    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._initialize_release_state_journal()

    def evaluate_and_commit(
        self,
        event: DisclosureEvent,
        *,
        sql: str,
        dialect: str = "duckdb",
    ) -> DisclosureCompositionDecision:
        """Evaluate history and append an allowed release as PENDING.

        PENDING records participate in composition decisions immediately, preserving the
        serialization guarantee across concurrent executions. They do not become durable
        privacy history until ``mark_released`` is called after all verification passes.
        """

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
                commitment = _commitment(existing)
                connection.commit()
                return DisclosureCompositionDecision(
                    allowed=True,
                    rule=CompositionRule.IDEMPOTENT_REPLAY,
                    protected_release=composition.protected_release,
                    prior_protected_count=_protected_count(active_history),
                    commitment=commitment,
                )

            evaluation = evaluate_composition_history(
                active_history,
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
                history=audit_history,
            )
            self._insert_transition_connection(connection, record.record_id, _PENDING)
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
        record = super().verify_commitment(commitment, event, sql=sql, dialect=dialect)
        self._require_pending(commitment)
        return record

    def claim_commitment(
        self,
        commitment: DisclosureCommitment,
        authorization_id: str,
    ) -> None:
        self._require_pending(commitment)
        super().claim_commitment(commitment, authorization_id)

    def verify_authorization_claim(
        self,
        commitment: DisclosureCommitment,
        authorization_id: str,
    ) -> None:
        self._require_pending(commitment)
        super().verify_authorization_claim(commitment, authorization_id)

    def mark_released(self, commitment: DisclosureCommitment) -> None:
        """Finalize a PENDING reservation only after an execution claim exists."""

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._record_for_commitment_connection(connection, commitment)
            state = self._release_state_connection(connection, commitment.record_id)
            if state == _RELEASED:
                connection.commit()
                return
            if state != _PENDING:
                raise DisclosureLedgerIntegrityError(
                    f"cannot release disclosure from state {state}"
                )
            claim = connection.execute(
                "SELECT 1 FROM disclosure_authorization_claims WHERE record_id = ?",
                (commitment.record_id,),
            ).fetchone()
            if claim is None:
                raise DisclosureLedgerIntegrityError(
                    "cannot release disclosure without an execution authorization claim"
                )
            self._insert_transition_connection(connection, commitment.record_id, _RELEASED)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def mark_aborted(self, commitment: DisclosureCommitment) -> None:
        """Finalize a failed PENDING reservation as ABORTED without deleting audit data."""

        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._record_for_commitment_connection(connection, commitment)
            state = self._release_state_connection(connection, commitment.record_id)
            if state == _ABORTED:
                connection.commit()
                return
            if state != _PENDING:
                raise DisclosureLedgerIntegrityError(
                    f"cannot abort disclosure from state {state}"
                )
            self._insert_transition_connection(connection, commitment.record_id, _ABORTED)
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def release_state(self, commitment: DisclosureCommitment) -> str:
        """Return validated release state for diagnostics and regression tests."""

        connection = self._connect()
        try:
            self._record_for_commitment_connection(connection, commitment)
            return self._release_state_connection(connection, commitment.record_id)
        finally:
            connection.close()

    def verify_all(self) -> int:
        count = super().verify_all()
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT record_id FROM disclosure_records ORDER BY sequence"
            ).fetchall()
            for row in rows:
                record_id = str(row["record_id"])
                state = self._release_state_connection(connection, record_id)
                if state == _RELEASED:
                    claim = connection.execute(
                        "SELECT 1 FROM disclosure_authorization_claims WHERE record_id = ?",
                        (record_id,),
                    ).fetchone()
                    # Legacy records have no transition rows and may predate claims.
                    transitions = self._transition_states_connection(connection, record_id)
                    if transitions and claim is None:
                        raise DisclosureLedgerIntegrityError(
                            "released disclosure is missing execution authorization claim"
                        )
        finally:
            connection.close()
        return count

    def _require_pending(self, commitment: DisclosureCommitment) -> None:
        connection = self._connect()
        try:
            self._record_for_commitment_connection(connection, commitment)
            state = self._release_state_connection(connection, commitment.record_id)
        finally:
            connection.close()
        if state != _PENDING:
            raise DisclosureLedgerIntegrityError(
                f"disclosure commitment is not pending: {state}"
            )

    def _active_history_connection(
        self,
        connection: sqlite3.Connection,
        audit_history: tuple[DisclosureRecord, ...],
    ) -> tuple[DisclosureRecord, ...]:
        return tuple(
            record
            for record in audit_history
            if self._release_state_connection(connection, record.record_id) != _ABORTED
        )

    def _release_state_connection(
        self,
        connection: sqlite3.Connection,
        record_id: str,
    ) -> str:
        states = self._transition_states_connection(connection, record_id)
        if not states:
            # Records created before the two-phase journal are conservatively assumed
            # to have been released and therefore remain permanent privacy history.
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

    @staticmethod
    def _transition_states_connection(
        connection: sqlite3.Connection,
        record_id: str,
    ) -> tuple[str, ...]:
        rows = connection.execute(
            """
            SELECT state FROM disclosure_release_transitions
            WHERE record_id = ?
            ORDER BY transition_id ASC
            """,
            (record_id,),
        ).fetchall()
        return tuple(str(row["state"]) for row in rows)

    @staticmethod
    def _insert_transition_connection(
        connection: sqlite3.Connection,
        record_id: str,
        state: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO disclosure_release_transitions(record_id, state, created_at)
            VALUES (?, ?, ?)
            """,
            (record_id, state, datetime.now(timezone.utc).isoformat()),
        )

    def _initialize_release_state_journal(self) -> None:
        connection = self._connect()
        try:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS disclosure_release_transitions (
                    transition_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    record_id TEXT NOT NULL,
                    state TEXT NOT NULL CHECK (state IN ('PENDING', 'RELEASED', 'ABORTED')),
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(record_id) REFERENCES disclosure_records(record_id)
                );

                CREATE INDEX IF NOT EXISTS disclosure_release_transitions_record
                ON disclosure_release_transitions(record_id, transition_id);

                CREATE TRIGGER IF NOT EXISTS disclosure_release_transitions_no_update
                BEFORE UPDATE ON disclosure_release_transitions
                BEGIN
                    SELECT RAISE(ABORT, 'disclosure release transitions are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS disclosure_release_transitions_no_delete
                BEFORE DELETE ON disclosure_release_transitions
                BEGIN
                    SELECT RAISE(ABORT, 'disclosure release transitions are append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS disclosure_release_transition_valid_insert
                BEFORE INSERT ON disclosure_release_transitions
                BEGIN
                    SELECT CASE
                        WHEN NEW.state = 'PENDING' AND EXISTS (
                            SELECT 1 FROM disclosure_release_transitions
                            WHERE record_id = NEW.record_id
                        ) THEN RAISE(ABORT, 'PENDING must be the first release transition')
                        WHEN NEW.state IN ('RELEASED', 'ABORTED') AND NOT EXISTS (
                            SELECT 1 FROM disclosure_release_transitions
                            WHERE record_id = NEW.record_id AND state = 'PENDING'
                        ) THEN RAISE(ABORT, 'terminal release transition requires PENDING')
                        WHEN NEW.state IN ('RELEASED', 'ABORTED') AND EXISTS (
                            SELECT 1 FROM disclosure_release_transitions
                            WHERE record_id = NEW.record_id AND state IN ('RELEASED', 'ABORTED')
                        ) THEN RAISE(ABORT, 'release transition is already terminal')
                    END;
                END;
                """
            )
            connection.commit()
        except sqlite3.DatabaseError as exc:
            connection.rollback()
            raise DisclosureLedgerIntegrityError(
                "unable to initialize disclosure release-state journal"
            ) from exc
        finally:
            connection.close()
