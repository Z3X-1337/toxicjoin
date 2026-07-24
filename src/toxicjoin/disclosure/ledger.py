"""Transactional append-only persistence for disclosure history."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from toxicjoin.disclosure.models import (
    DisclosureEvent,
    DisclosureRecord,
    DisclosureScope,
    compute_event_sha256,
    compute_record_sha256,
)


_SCHEMA_VERSION = 1


class DisclosureLedgerError(RuntimeError):
    """Base error for disclosure-ledger persistence failures."""


class DisclosureLedgerConflict(DisclosureLedgerError):
    """Raised when an idempotency key is reused for different disclosure content."""


class DisclosureLedgerIntegrityError(DisclosureLedgerError):
    """Raised when persisted ledger content or its per-scope hash chain is invalid."""


class DisclosureLedger:
    """SQLite-backed append-only ledger with serialized writer transactions.

    Each append uses ``BEGIN IMMEDIATE`` so a future P2 composition evaluator can read
    history and append the accepted event under one writer lock. P2-A exposes only the
    append/read primitive; it does not yet authorize cumulative disclosure.
    """

    def __init__(self, path: str | Path, *, busy_timeout_ms: int = 5_000) -> None:
        self.path = Path(path)
        if busy_timeout_ms < 1 or busy_timeout_ms > 60_000:
            raise ValueError("busy_timeout_ms must be between 1 and 60000")
        self.busy_timeout_ms = busy_timeout_ms
        self._initialize()

    def append(self, event: DisclosureEvent) -> DisclosureRecord:
        """Append one disclosure event or return its identical prior receipt record."""

        event_sha256 = compute_event_sha256(event)
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing_row = connection.execute(
                "SELECT * FROM disclosure_records WHERE receipt_id = ?",
                (event.receipt_id,),
            ).fetchone()
            if existing_row is not None:
                existing = self._row_to_record(existing_row)
                if existing.event_sha256 != event_sha256 or existing.event != event:
                    raise DisclosureLedgerConflict(
                        "receipt_id already records different disclosure content"
                    )
                connection.commit()
                return existing

            previous_row = connection.execute(
                """
                SELECT content_sha256
                FROM disclosure_records
                WHERE scope_sha256 = ?
                ORDER BY sequence DESC
                LIMIT 1
                """,
                (event.scope.scope_sha256,),
            ).fetchone()
            previous_sha256 = (
                str(previous_row["content_sha256"])
                if previous_row is not None
                else None
            )
            sequence = int(
                connection.execute(
                    "SELECT COALESCE(MAX(sequence), 0) + 1 FROM disclosure_records"
                ).fetchone()[0]
            )
            created_at = datetime.now(timezone.utc)
            record_id = f"dl_{uuid4().hex}"

            provisional = DisclosureRecord.model_construct(
                schema_version="1.0",
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
            connection.commit()
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

        return self.read_receipt(event.receipt_id)

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
            rows = connection.execute(
                """
                SELECT * FROM disclosure_records
                WHERE scope_sha256 = ?
                ORDER BY sequence ASC
                """,
                (scope.scope_sha256,),
            ).fetchall()
        finally:
            connection.close()

        records = tuple(self._row_to_record(row) for row in rows)
        previous: str | None = None
        for record in records:
            if not _same_privacy_scope(record.event.scope, scope):
                raise DisclosureLedgerIntegrityError("scope payload does not match index")
            if record.previous_content_sha256 != previous:
                raise DisclosureLedgerIntegrityError("disclosure scope hash chain is broken")
            previous = record.content_sha256
        return records

    def verify_all(self) -> int:
        """Validate all records, indexes, and per-scope chains; return record count."""

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
            records = self.list_for_scope(scope)
            count += len(records)
        return count

    def _initialize(self) -> None:
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
            if current_version not in (0, _SCHEMA_VERSION):
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
                """
            )
            if current_version == 0:
                connection.execute(f"PRAGMA user_version = {_SCHEMA_VERSION}")
            connection.commit()
        finally:
            connection.close()
        try:
            os.chmod(self.path, 0o600)
        except OSError as exc:
            raise DisclosureLedgerError("unable to secure disclosure ledger permissions") from exc

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
        except (json.JSONDecodeError, ValueError) as exc:
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
