from __future__ import annotations

import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from toxicjoin.auth import RequestIdentity
from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog
from toxicjoin.disclosure import (
    CompositionRule,
    DisclosureLedger,
    DisclosureLedgerIntegrityError,
    build_composition_metadata,
    build_disclosure_event,
    build_disclosure_event_from_resolver,
    build_semantic_release,
    canonicalize_cohort_sql,
)
from toxicjoin.models import ColumnRef
from toxicjoin.sql import analyze_sql


_KEY = b"k" * 32
_SUBJECT = ColumnRef(dataset="orders", field_path="customer_id")


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
    sql: str,
    receipt_index: int,
    *,
    identity: RequestIdentity | None = None,
):
    catalog = default_fixture_catalog()
    plan = analyze_sql(sql, dialect="duckdb")
    return build_disclosure_event(
        identity=identity or _identity(),
        catalog=catalog,
        query_plan=plan,
        subject_key=_SUBJECT,
        receipt_id=f"tj_{receipt_index:016x}",
        policy_version="0.2.0",
    )


def _sensitive_sql(literal: str, *, alias: str = "avg_purchase") -> str:
    return (
        f"SELECT AVG(o.purchase_amount) AS {alias} "
        f"FROM orders o WHERE o.category = '{literal}' ORDER BY 1"
    )


def test_cohort_identity_ignores_root_output_alias_and_unlimited_order_but_not_predicate() -> None:
    first = _sensitive_sql("alpha", alias="first_alias")
    renamed = (
        "SELECT AVG(o.purchase_amount) AS second_alias "
        "FROM orders o WHERE o.category = 'alpha'"
    )
    changed = _sensitive_sql("beta", alias="first_alias")
    semantic = build_semantic_release(default_fixture_catalog(), analyze_sql(first, dialect="duckdb"))

    assert canonicalize_cohort_sql(first) == canonicalize_cohort_sql(renamed)
    first_metadata = build_composition_metadata(semantic, first, secret_key=_KEY)
    renamed_metadata = build_composition_metadata(semantic, renamed, secret_key=_KEY)
    changed_metadata = build_composition_metadata(semantic, changed, secret_key=_KEY)

    assert first_metadata.cohort_hmac_sha256 == renamed_metadata.cohort_hmac_sha256
    assert first_metadata.cohort_hmac_sha256 != changed_metadata.cohort_hmac_sha256
    assert first_metadata.protected_release is True


def test_cohort_identity_binds_conditional_aggregate_predicates() -> None:
    first = (
        "SELECT COUNT(CASE WHEN o.purchase_amount > 100 THEN 1 END) AS probe "
        "FROM orders o"
    )
    changed = (
        "SELECT COUNT(CASE WHEN o.purchase_amount > 200 THEN 1 END) AS probe "
        "FROM orders o"
    )
    first_plan = analyze_sql(first, dialect="duckdb")
    changed_plan = analyze_sql(changed, dialect="duckdb")
    first_semantic = build_semantic_release(default_fixture_catalog(), first_plan)
    changed_semantic = build_semantic_release(default_fixture_catalog(), changed_plan)

    assert canonicalize_cohort_sql(first) != canonicalize_cohort_sql(changed)
    first_metadata = build_composition_metadata(first_semantic, first, secret_key=_KEY)
    changed_metadata = build_composition_metadata(changed_semantic, changed, secret_key=_KEY)
    assert first_metadata.cohort_hmac_sha256 != changed_metadata.cohort_hmac_sha256


def test_limited_query_order_changes_cohort_identity() -> None:
    ascending = (
        "SELECT o.purchase_amount FROM orders o "
        "WHERE o.category = 'alpha' ORDER BY o.purchase_amount ASC LIMIT 1"
    )
    descending = (
        "SELECT o.purchase_amount FROM orders o "
        "WHERE o.category = 'alpha' ORDER BY o.purchase_amount DESC LIMIT 1"
    )
    semantic = build_semantic_release(
        default_fixture_catalog(), analyze_sql(ascending, dialect="duckdb")
    )

    assert canonicalize_cohort_sql(ascending) != canonicalize_cohort_sql(descending)
    ascending_metadata = build_composition_metadata(semantic, ascending, secret_key=_KEY)
    descending_metadata = build_composition_metadata(semantic, descending, secret_key=_KEY)
    assert ascending_metadata.cohort_hmac_sha256 != descending_metadata.cohort_hmac_sha256


def test_first_protected_release_is_reserved_and_new_identical_release_is_blocked(
    tmp_path: Path,
) -> None:
    ledger = DisclosureLedger(tmp_path / "disclosures.sqlite3")
    first_sql = _sensitive_sql("alpha", alias="first_alias")
    repeat_sql = (
        "SELECT AVG(o.purchase_amount) AS renamed_alias "
        "FROM orders o WHERE o.category = 'alpha'"
    )

    first = ledger.evaluate_and_commit(_event(first_sql, 1), sql=first_sql)
    repeat = ledger.evaluate_and_commit(_event(repeat_sql, 2), sql=repeat_sql)

    assert first.allowed is True
    assert first.rule == CompositionRule.FIRST_PROTECTED_RELEASE
    assert first.commitment is not None
    assert ledger.release_state(first.commitment) == "PENDING"
    assert repeat.allowed is False
    assert repeat.rule == CompositionRule.REPEAT_PROTECTED_RELEASE_BLOCK
    assert repeat.prior_protected_count == 1
    assert repeat.commitment is None
    assert ledger.verify_all() == 1


def test_changed_cohort_is_blocked_without_append(tmp_path: Path) -> None:
    ledger = DisclosureLedger(tmp_path / "disclosures.sqlite3")
    first_sql = _sensitive_sql("alpha")
    changed_sql = _sensitive_sql("beta")
    first_event = _event(first_sql, 3)
    changed_event = _event(changed_sql, 4)

    allowed = ledger.evaluate_and_commit(first_event, sql=first_sql)
    blocked = ledger.evaluate_and_commit(changed_event, sql=changed_sql)

    assert allowed.allowed is True
    assert blocked.allowed is False
    assert blocked.rule == CompositionRule.CUMULATIVE_VARIATION_BLOCK
    assert blocked.commitment is None
    assert ledger.verify_all() == 1
    with pytest.raises(KeyError):
        ledger.read_receipt(changed_event.receipt_id)


def test_changed_sensitive_release_family_is_blocked(tmp_path: Path) -> None:
    ledger = DisclosureLedger(tmp_path / "disclosures.sqlite3")
    first_sql = _sensitive_sql("alpha")
    changed_sql = (
        "SELECT MAX(o.purchase_amount) AS max_purchase "
        "FROM orders o WHERE o.category = 'alpha'"
    )

    first = ledger.evaluate_and_commit(_event(first_sql, 5), sql=first_sql)
    changed = ledger.evaluate_and_commit(_event(changed_sql, 6), sql=changed_sql)

    assert first.allowed is True
    assert changed.allowed is False
    assert changed.rule == CompositionRule.CUMULATIVE_VARIATION_BLOCK
    assert ledger.verify_all() == 1


def test_public_nonaggregate_variation_remains_unprotected(tmp_path: Path) -> None:
    ledger = DisclosureLedger(tmp_path / "disclosures.sqlite3")
    first_sql = "SELECT o.category FROM orders o WHERE o.category = 'alpha'"
    second_sql = "SELECT o.category FROM orders o WHERE o.category = 'beta'"

    first = ledger.evaluate_and_commit(_event(first_sql, 7), sql=first_sql)
    assert first.commitment is not None
    ledger.mark_aborted(first.commitment)
    second = ledger.evaluate_and_commit(_event(second_sql, 8), sql=second_sql)

    assert first.allowed is True
    assert first.rule == CompositionRule.UNPROTECTED_RELEASE
    assert second.allowed is True
    assert second.rule == CompositionRule.UNPROTECTED_RELEASE
    assert ledger.verify_all() == 2


def test_concurrent_different_protected_cohorts_cannot_both_commit(tmp_path: Path) -> None:
    ledger = DisclosureLedger(tmp_path / "disclosures.sqlite3", busy_timeout_ms=20_000)
    sql_a = _sensitive_sql("alpha")
    sql_b = _sensitive_sql("beta")
    event_a = _event(sql_a, 9)
    event_b = _event(sql_b, 10)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = tuple(
            pool.map(
                lambda pair: ledger.evaluate_and_commit(pair[0], sql=pair[1]),
                ((event_a, sql_a), (event_b, sql_b)),
            )
        )

    assert sum(result.allowed for result in results) == 1
    assert sum(result.rule == CompositionRule.CUMULATIVE_VARIATION_BLOCK for result in results) == 1
    assert ledger.verify_all() == 1


def test_history_survives_restart_and_blocks_new_protected_release(
    tmp_path: Path,
) -> None:
    path = tmp_path / "disclosures.sqlite3"
    first_sql = _sensitive_sql("alpha")
    changed_sql = _sensitive_sql("beta")
    ledger = DisclosureLedger(path)
    first = ledger.evaluate_and_commit(_event(first_sql, 11), sql=first_sql)
    assert first.allowed
    key_path = ledger.cohort_key_path

    restarted = DisclosureLedger(path)
    repeat = restarted.evaluate_and_commit(_event(first_sql, 12), sql=first_sql)
    changed = restarted.evaluate_and_commit(_event(changed_sql, 13), sql=changed_sql)
    assert repeat.allowed is False
    assert repeat.rule == CompositionRule.REPEAT_PROTECTED_RELEASE_BLOCK
    assert changed.allowed is False
    assert changed.rule == CompositionRule.CUMULATIVE_VARIATION_BLOCK

    original_key = key_path.read_bytes()
    key_path.unlink()
    with pytest.raises(DisclosureLedgerIntegrityError, match="cohort key is missing"):
        DisclosureLedger(path)

    key_path.write_bytes(os.urandom(32))
    with pytest.raises(DisclosureLedgerIntegrityError, match="does not match ledger metadata"):
        DisclosureLedger(path)

    key_path.write_bytes(original_key)
    assert DisclosureLedger(path).verify_all() == 1


def test_aborted_release_does_not_poison_future_composition(tmp_path: Path) -> None:
    ledger = DisclosureLedger(tmp_path / "disclosures.sqlite3")
    first_sql = _sensitive_sql("alpha")
    second_sql = _sensitive_sql("beta")

    first = ledger.evaluate_and_commit(_event(first_sql, 19), sql=first_sql)
    assert first.commitment is not None
    ledger.mark_aborted(first.commitment)
    assert ledger.release_state(first.commitment) == "ABORTED"

    second = ledger.evaluate_and_commit(_event(second_sql, 20), sql=second_sql)
    assert second.allowed is True
    assert second.rule == CompositionRule.FIRST_PROTECTED_RELEASE
    assert second.commitment is not None
    assert ledger.verify_all() == 2


def test_release_state_journal_is_append_only(tmp_path: Path) -> None:
    path = tmp_path / "disclosures.sqlite3"
    ledger = DisclosureLedger(path)
    sql = _sensitive_sql("alpha")
    decision = ledger.evaluate_and_commit(_event(sql, 21), sql=sql)
    assert decision.commitment is not None

    with sqlite3.connect(path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM disclosure_release_transitions")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE disclosure_release_transitions SET state = 'RELEASED'"
            )


def test_legacy_protected_history_blocks_new_protected_release(tmp_path: Path) -> None:
    ledger = DisclosureLedger(tmp_path / "disclosures.sqlite3")
    first_sql = _sensitive_sql("alpha")
    next_sql = _sensitive_sql("alpha")
    ledger.append(_event(first_sql, 14))

    blocked = ledger.evaluate_and_commit(_event(next_sql, 15), sql=next_sql)

    assert blocked.allowed is False
    assert blocked.rule == CompositionRule.LEGACY_HISTORY_BLOCK
    assert ledger.verify_all() == 1


def test_commitment_verification_rejects_sql_or_event_mutation(tmp_path: Path) -> None:
    ledger = DisclosureLedger(tmp_path / "disclosures.sqlite3")
    sql = _sensitive_sql("alpha")
    event = _event(sql, 16)
    decision = ledger.evaluate_and_commit(event, sql=sql)
    assert decision.commitment is not None

    record = ledger.verify_commitment(decision.commitment, event, sql=sql)
    assert record.event.receipt_id == event.receipt_id

    with pytest.raises(DisclosureLedgerIntegrityError, match="does not match current"):
        ledger.verify_commitment(
            decision.commitment,
            event,
            sql=_sensitive_sql("beta"),
        )

    mutated_event = event.model_copy(update={"policy_version": "9.9.9"})
    with pytest.raises(DisclosureLedgerIntegrityError, match="does not match current"):
        ledger.verify_commitment(decision.commitment, mutated_event, sql=sql)


def test_authorization_claim_is_append_only_and_bound_to_commitment(tmp_path: Path) -> None:
    path = tmp_path / "disclosures.sqlite3"
    ledger = DisclosureLedger(path)
    sql = _sensitive_sql("alpha")
    decision = ledger.evaluate_and_commit(_event(sql, 17), sql=sql)
    assert decision.commitment is not None
    authorization_id = "tj_auth_" + "a" * 32

    ledger.claim_commitment(decision.commitment, authorization_id)
    ledger.verify_authorization_claim(decision.commitment, authorization_id)

    with sqlite3.connect(path) as connection:
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute(
                "UPDATE disclosure_authorization_claims SET authorization_id = ?",
                ("tj_auth_" + "b" * 32,),
            )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM disclosure_authorization_claims")

    ledger.verify_authorization_claim(decision.commitment, authorization_id)
    ledger.mark_released(decision.commitment)
    assert ledger.release_state(decision.commitment) == "RELEASED"
    assert ledger.verify_all() == 1


def test_provider_neutral_event_matches_fixture_semantics_and_scope() -> None:
    catalog = default_fixture_catalog()
    resolver = FixtureContextResolver(catalog)
    sql = _sensitive_sql("alpha")
    plan = analyze_sql(sql, dialect="duckdb")
    resolution = resolver.resolve(plan)
    fixture_event = build_disclosure_event(
        identity=_identity(),
        catalog=catalog,
        query_plan=plan,
        subject_key=_SUBJECT,
        receipt_id="tj_0000000000000011",
        policy_version="0.2.0",
    )
    neutral_event = build_disclosure_event_from_resolver(
        identity=_identity(),
        resolver=resolver,
        resolution=resolution,
        query_plan=plan,
        subject_key=_SUBJECT,
        receipt_id="tj_0000000000000011",
        policy_version="0.2.0",
    )

    assert neutral_event.scope.scope_sha256 == fixture_event.scope.scope_sha256
    assert neutral_event.semantic == fixture_event.semantic


def test_literal_and_raw_sql_are_not_persisted_in_ledger(tmp_path: Path) -> None:
    marker = "LOW_ENTROPY_LITERAL_MUST_NOT_PERSIST"
    sql = _sensitive_sql(marker)
    path = tmp_path / "disclosures.sqlite3"
    ledger = DisclosureLedger(path)
    result = ledger.evaluate_and_commit(_event(sql, 18), sql=sql)
    assert result.allowed is True

    persisted = path.read_bytes()
    assert marker.encode() not in persisted
    assert sql.encode() not in persisted
    assert b"cohort_hmac_sha256" in persisted
