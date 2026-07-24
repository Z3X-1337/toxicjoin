from __future__ import annotations

import os
import re
import sqlite3
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from toxicjoin.auth import RequestIdentity
from toxicjoin.demo import default_fixture_catalog
from toxicjoin.disclosure import (
    DisclosureLedger,
    DisclosureLedgerConflict,
    DisclosureLedgerIntegrityError,
    build_disclosure_event,
)
from toxicjoin.models import ColumnRef
from toxicjoin.sql import analyze_sql


def _identity(
    *,
    credential: str = "credential-a",
    session: str | None = "session-a",
) -> RequestIdentity:
    return RequestIdentity(
        principal_id="principal-a",
        credential_id=credential,
        agent_id="agent-a",
        session_id=session,
    )


def _event(
    index: int,
    *,
    dataset: str = "orders",
    credential: str = "credential-a",
    session: str | None = "session-a",
):
    catalog = default_fixture_catalog()
    if dataset == "orders":
        sql = f"SELECT AVG(o.purchase_amount) AS avg_{index} FROM orders o"
    elif dataset == "customers":
        sql = f"SELECT COUNT(*) AS count_{index} FROM customers c"
    else:
        raise AssertionError(dataset)
    plan = analyze_sql(sql, dialect="duckdb")
    return build_disclosure_event(
        identity=_identity(credential=credential, session=session),
        catalog=catalog,
        query_plan=plan,
        subject_key=ColumnRef(dataset=dataset, field_path="customer_id"),
        receipt_id=f"tj_{index:016x}",
        policy_version="0.2.0",
    )


def test_append_is_hash_chained_and_idempotent_by_receipt(tmp_path: Path) -> None:
    ledger = DisclosureLedger(tmp_path / "disclosures.sqlite3")
    first_event = _event(1)
    second_event = _event(2)

    first = ledger.append(first_event)
    second = ledger.append(second_event)
    replay = ledger.append(first_event)

    assert first.sequence == 1
    assert second.sequence == 2
    assert re.fullmatch(r"dl_[0-9a-f]{32}", first.record_id)
    assert re.fullmatch(r"dl_[0-9a-f]{32}", second.record_id)
    assert first.record_id != second.record_id
    assert first.created_at.tzinfo is not None
    assert second.created_at.tzinfo is not None
    assert first.previous_content_sha256 is None
    assert second.previous_content_sha256 == first.content_sha256
    assert replay == first
    assert ledger.verify_all() == 2


def test_append_does_not_accept_caller_record_identity_or_timestamp(tmp_path: Path) -> None:
    ledger = DisclosureLedger(tmp_path / "disclosures.sqlite3")
    event = _event(30)

    with pytest.raises(TypeError):
        ledger.append(event, record_id="dl_00000000000000000000000000000000")
    with pytest.raises(TypeError):
        ledger.append(event, created_at="2026-07-24T00:00:00Z")

    assert ledger.verify_all() == 0


def test_receipt_reuse_with_different_event_fails_closed(tmp_path: Path) -> None:
    ledger = DisclosureLedger(tmp_path / "disclosures.sqlite3")
    original = _event(3)
    ledger.append(original)

    mutated = original.model_copy(update={"policy_version": "0.2.1"})
    with pytest.raises(DisclosureLedgerConflict, match="different disclosure content"):
        ledger.append(mutated)

    assert ledger.verify_all() == 1


def test_credential_session_and_dataset_rotation_share_privacy_history(
    tmp_path: Path,
) -> None:
    ledger = DisclosureLedger(tmp_path / "disclosures.sqlite3")
    first = _event(4, dataset="customers", credential="credential-a", session="session-a")
    rotated = _event(5, dataset="orders", credential="credential-b", session="session-b")

    assert first.scope.scope_sha256 == rotated.scope.scope_sha256
    ledger.append(first)
    ledger.append(rotated)

    records = ledger.list_for_scope(first.scope)
    assert [record.event.receipt_id for record in records] == [
        first.receipt_id,
        rotated.receipt_id,
    ]
    assert records[0].event.audit_identity.credential_id == "credential-a"
    assert records[1].event.audit_identity.credential_id == "credential-b"
    persisted = (tmp_path / "disclosures.sqlite3").read_bytes()
    assert b"session-a" not in persisted
    assert b"session-b" not in persisted


def test_concurrent_appends_are_serialized_without_lost_records(tmp_path: Path) -> None:
    ledger = DisclosureLedger(tmp_path / "disclosures.sqlite3", busy_timeout_ms=20_000)
    events = tuple(_event(index) for index in range(100, 124))

    with ThreadPoolExecutor(max_workers=8) as pool:
        records = tuple(pool.map(ledger.append, events))

    assert len({record.record_id for record in records}) == len(events)
    assert ledger.verify_all() == len(events)
    scoped = ledger.list_for_scope(events[0].scope)
    assert len(scoped) == len(events)
    assert [record.sequence for record in scoped] == sorted(
        record.sequence for record in scoped
    )


def test_sqlite_update_and_delete_are_rejected_by_append_only_triggers(
    tmp_path: Path,
) -> None:
    path = tmp_path / "disclosures.sqlite3"
    ledger = DisclosureLedger(path)
    event = _event(6)
    ledger.append(event)

    with sqlite3.connect(path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE disclosure_records SET receipt_id = ? WHERE sequence = 1",
                ("tj_ffffffffffffffff",),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM disclosure_records WHERE sequence = 1")

    assert ledger.verify_all() == 1


def test_out_of_band_payload_tamper_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "disclosures.sqlite3"
    ledger = DisclosureLedger(path)
    event = _event(7)
    ledger.append(event)

    # Simulate an attacker who already has filesystem-level database access and can
    # disable the application trigger. The unkeyed content hash still detects naive
    # payload modification; keyed authenticity remains a later roadmap item.
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER disclosure_records_no_update")
        connection.execute(
            """
            UPDATE disclosure_records
            SET payload_json = replace(payload_json, '0.2.0', '9.9.9')
            WHERE sequence = 1
            """
        )

    with pytest.raises(DisclosureLedgerIntegrityError, match="failed validation"):
        ledger.read_receipt(event.receipt_id)


def test_broken_scope_chain_is_detected_after_out_of_band_tamper(tmp_path: Path) -> None:
    path = tmp_path / "disclosures.sqlite3"
    ledger = DisclosureLedger(path)
    first = _event(8)
    second = _event(9)
    ledger.append(first)
    ledger.append(second)

    with sqlite3.connect(path) as connection:
        connection.execute("DROP TRIGGER disclosure_records_no_update")
        row = connection.execute(
            "SELECT payload_json FROM disclosure_records WHERE receipt_id = ?",
            (second.receipt_id,),
        ).fetchone()
        assert row is not None
        payload = row[0].replace(
            f'"previous_content_sha256":"{ledger.read_receipt(first.receipt_id).content_sha256}"',
            '"previous_content_sha256":null',
        )
        connection.execute(
            "UPDATE disclosure_records SET payload_json = ? WHERE receipt_id = ?",
            (payload, second.receipt_id),
        )

    with pytest.raises(DisclosureLedgerIntegrityError):
        ledger.list_for_scope(first.scope)


def test_ledger_never_persists_sql_hash_literal_alias_or_session_values(tmp_path: Path) -> None:
    literal_marker = "RAW_LITERAL_MUST_NOT_ENTER_DISCLOSURE_LEDGER"
    alias_marker = "CALLER_ALIAS_MUST_NOT_ENTER_DISCLOSURE_LEDGER"
    session_marker = "CALLER_SESSION_MUST_NOT_ENTER_DISCLOSURE_LEDGER"
    sql = (
        f"SELECT AVG(o.purchase_amount) AS {alias_marker} "
        f"FROM orders o WHERE o.category = '{literal_marker}'"
    )
    plan = analyze_sql(sql, dialect="duckdb")
    event = build_disclosure_event(
        identity=_identity(session=session_marker),
        catalog=default_fixture_catalog(),
        query_plan=plan,
        subject_key=ColumnRef(dataset="orders", field_path="customer_id"),
        receipt_id="tj_00000000000000aa",
        policy_version="0.2.0",
    )
    path = tmp_path / "disclosures.sqlite3"
    ledger = DisclosureLedger(path)
    ledger.append(event)

    persisted = path.read_bytes()
    assert sql.encode("utf-8") not in persisted
    assert literal_marker.encode("utf-8") not in persisted
    assert alias_marker.encode("utf-8") not in persisted
    assert session_marker.encode("utf-8") not in persisted
    assert b"query_sha256" not in persisted


def test_ledger_file_is_owner_only_and_symlink_target_is_rejected(tmp_path: Path) -> None:
    path = tmp_path / "disclosures.sqlite3"
    DisclosureLedger(path)
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600

    target = tmp_path / "target.sqlite3"
    target.write_bytes(b"")
    symlink = tmp_path / "ledger-link.sqlite3"
    try:
        symlink.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symbolic links are unavailable on this platform")
    with pytest.raises(ValueError, match="symbolic link"):
        DisclosureLedger(symlink)


def test_missing_database_after_initialization_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "disclosures.sqlite3"
    ledger = DisclosureLedger(path)
    path.unlink()

    with pytest.raises(DisclosureLedgerIntegrityError, match="database is missing"):
        ledger.verify_all()
