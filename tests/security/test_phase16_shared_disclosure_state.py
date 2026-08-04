from __future__ import annotations

from pathlib import Path

import pytest

from toxicjoin.auth import RequestIdentity
from toxicjoin.demo import default_fixture_catalog
from toxicjoin.disclosure import (
    CompositionRule,
    DisclosureBudget,
    DisclosureLedger,
    DisclosureStateTopology,
    DisclosureStateTopologyError,
    build_disclosure_event,
    require_disclosure_state_topology,
    resolve_declared_replica_count,
)
from toxicjoin.disclosure.secure_ledger import DisclosureLedger as SQLiteDisclosureLedger
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


# These regressions were written when the gate permitted exactly one protected release per
# scope for the lifetime of the ledger. That limit is now a configurable budget, so they pin
# the budget to one release and keep testing the same boundary: the release that exceeds the
# allowance is refused, and refused releases never append history.
SINGLE_RELEASE_BUDGET = DisclosureBudget(max_protected_releases=1)



def test_raw_replica_local_sqlite_partitions_cumulative_privacy_history(tmp_path: Path) -> None:
    """Document why the raw SQLite primitive is not a horizontally authoritative backend."""

    cohort_key_path = tmp_path / "shared-cohort.key"
    replica_a = SQLiteDisclosureLedger(
        tmp_path / "replica-a.sqlite3",
        cohort_key_path=cohort_key_path,
        budget=SINGLE_RELEASE_BUDGET,
    )
    replica_b = SQLiteDisclosureLedger(
        tmp_path / "replica-b.sqlite3",
        cohort_key_path=cohort_key_path,
        budget=SINGLE_RELEASE_BUDGET,
    )

    sql_a = _sensitive_sql("alpha")
    sql_b = _sensitive_sql("beta")
    decision_a = replica_a.evaluate_and_commit(_event(sql_a, 1), sql=sql_a)
    decision_b = replica_b.evaluate_and_commit(_event(sql_b, 2), sql=sql_b)

    control = SQLiteDisclosureLedger(
        tmp_path / "authoritative-control.sqlite3",
        cohort_key_path=cohort_key_path,
        budget=SINGLE_RELEASE_BUDGET,
    )
    control_a = control.evaluate_and_commit(_event(sql_a, 101), sql=sql_a)
    control_b = control.evaluate_and_commit(_event(sql_b, 102), sql=sql_b)

    assert decision_a.allowed is True
    assert decision_b.allowed is True
    assert decision_a.rule == CompositionRule.FIRST_PROTECTED_RELEASE
    assert decision_b.rule == CompositionRule.FIRST_PROTECTED_RELEASE

    assert control_a.allowed is True
    assert control_b.allowed is False
    assert control_b.rule == CompositionRule.CUMULATIVE_BUDGET_EXHAUSTED


def test_public_sqlite_authority_rejects_declared_multi_replica_deployment(tmp_path: Path) -> None:
    with pytest.raises(
        DisclosureStateTopologyError,
        match="multi-replica stateful privacy requires a shared authoritative disclosure backend",
    ):
        DisclosureLedger(
            tmp_path / "disclosures.sqlite3",
            deployment_replica_count=2,
            budget=SINGLE_RELEASE_BUDGET,
        )


def test_public_sqlite_authority_honors_replica_count_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("TOXICJOIN_REPLICA_COUNT", "3")

    with pytest.raises(
        DisclosureStateTopologyError,
        match="multi-replica stateful privacy requires a shared authoritative disclosure backend",
    ):
        DisclosureLedger(tmp_path / "disclosures.sqlite3", budget=SINGLE_RELEASE_BUDGET)


def test_single_node_and_future_shared_authoritative_topologies_are_explicit(tmp_path: Path) -> None:
    ledger = DisclosureLedger(
        tmp_path / "disclosures.sqlite3",
        deployment_replica_count=1,
        budget=SINGLE_RELEASE_BUDGET,
    )

    assert ledger.state_topology is DisclosureStateTopology.SINGLE_NODE
    assert ledger.deployment_replica_count == 1
    assert resolve_declared_replica_count("1") == 1

    require_disclosure_state_topology(
        topology=DisclosureStateTopology.SHARED_AUTHORITATIVE,
        replica_count=8,
    )

    with pytest.raises(DisclosureStateTopologyError, match="invalid disclosure deployment replica count"):
        resolve_declared_replica_count(True)
