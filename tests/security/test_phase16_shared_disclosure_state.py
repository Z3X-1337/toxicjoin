from __future__ import annotations

from pathlib import Path

from toxicjoin.auth import RequestIdentity
from toxicjoin.demo import default_fixture_catalog
from toxicjoin.disclosure import CompositionRule, DisclosureLedger, build_disclosure_event
from toxicjoin.models import ColumnRef
from toxicjoin.sql import analyze_sql

_SUBJECT = ColumnRef(dataset="orders", field_path="customer_id")


def _identity() -> RequestIdentity:
    return RequestIdentity(
        principal_id="principal-phase16",
        credential_id="credential-phase16",
        agent_id="agent-phase16",
        session_id="session-phase16",
    )


def _event(sql: str, receipt_index: int):
    plan = analyze_sql(sql, dialect="duckdb")
    return build_disclosure_event(
        identity=_identity(),
        catalog=default_fixture_catalog(),
        query_plan=plan,
        subject_key=_SUBJECT,
        receipt_id=f"tj_{receipt_index:016x}",
        policy_version="0.2.0",
    )


def _sensitive_sql(literal: str) -> str:
    return (
        "SELECT AVG(o.purchase_amount) AS avg_purchase "
        f"FROM orders o WHERE o.category = '{literal}' ORDER BY 1"
    )


def test_replica_local_ledgers_cannot_partition_cumulative_privacy_history(tmp_path: Path) -> None:
    """Two replicas must not both authorize a globally conflicting protected release.

    The cohort key and privacy scope are deliberately shared. The only partition is persistent
    disclosure history: each replica owns a different SQLite database. A single authoritative
    ledger proves that alpha -> beta is a cumulative variation and must block beta.
    """

    cohort_key_path = tmp_path / "shared-cohort.key"
    replica_a = DisclosureLedger(
        tmp_path / "replica-a.sqlite3",
        cohort_key_path=cohort_key_path,
    )
    replica_b = DisclosureLedger(
        tmp_path / "replica-b.sqlite3",
        cohort_key_path=cohort_key_path,
    )

    sql_a = _sensitive_sql("alpha")
    sql_b = _sensitive_sql("beta")
    decision_a = replica_a.evaluate_and_commit(_event(sql_a, 1), sql=sql_a)
    decision_b = replica_b.evaluate_and_commit(_event(sql_b, 2), sql=sql_b)

    control = DisclosureLedger(
        tmp_path / "authoritative-control.sqlite3",
        cohort_key_path=cohort_key_path,
    )
    control_a = control.evaluate_and_commit(_event(sql_a, 101), sql=sql_a)
    control_b = control.evaluate_and_commit(_event(sql_b, 102), sql=sql_b)

    assert control_a.allowed is True
    assert control_b.allowed is False
    assert control_b.rule == CompositionRule.CUMULATIVE_VARIATION_BLOCK

    assert decision_a.allowed is True
    assert decision_b.allowed is False, (
        "replica-local SQLite histories partition the cumulative privacy scope: replica B "
        "authorized a protected cohort variation that the same globally composed history blocks"
    )
