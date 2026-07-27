from __future__ import annotations

import os
import threading

import pytest

from toxicjoin.auth import RequestIdentity
from toxicjoin.demo import default_fixture_catalog
from toxicjoin.disclosure import CompositionRule, DisclosureStateTopology, build_disclosure_event
from toxicjoin.disclosure.postgres_ledger import PostgresDisclosureLedger
from toxicjoin.models import ColumnRef
from toxicjoin.sql import analyze_sql

_DSN_ENV = "TOXICJOIN_TEST_POSTGRES_DSN"
_SCHEMA = "toxicjoin_phase17"
_COHORT_KEY = b"phase17-shared-cohort-hmac-key-32-bytes!!"
_SUBJECT = ColumnRef(dataset="orders", field_path="customer_id")


def _psycopg():
    return pytest.importorskip("psycopg")


def _dsn() -> str:
    value = os.getenv(_DSN_ENV)
    if not value:
        pytest.skip(f"{_DSN_ENV} is required for PostgreSQL disclosure integration tests")
    return value


def _reset_database() -> None:
    psycopg = _psycopg()
    with psycopg.connect(_dsn(), autocommit=True) as connection:
        connection.execute(f'DROP SCHEMA IF EXISTS "{_SCHEMA}" CASCADE')


def _identity() -> RequestIdentity:
    return RequestIdentity(
        principal_id="principal-phase17",
        credential_id="credential-phase17",
        agent_id="agent-phase17",
        session_id="session-phase17",
    )


def _event(sql: str, receipt_index: int):
    return build_disclosure_event(
        identity=_identity(),
        catalog=default_fixture_catalog(),
        query_plan=analyze_sql(sql, dialect="duckdb"),
        subject_key=_SUBJECT,
        receipt_id=f"tj_{receipt_index:016x}",
        policy_version="0.2.0",
    )


def _sensitive_sql(literal: str) -> str:
    return (
        "SELECT AVG(o.purchase_amount) AS avg_purchase "
        f"FROM orders o WHERE o.category = '{literal}' ORDER BY 1"
    )


def _ledger() -> PostgresDisclosureLedger:
    return PostgresDisclosureLedger(
        _dsn(),
        cohort_hmac_key=_COHORT_KEY,
        schema=_SCHEMA,
        deployment_replica_count=2,
    )


def test_postgres_backend_declares_shared_authoritative_topology() -> None:
    _reset_database()
    ledger = _ledger()

    assert ledger.state_topology is DisclosureStateTopology.SHARED_AUTHORITATIVE
    assert ledger.deployment_replica_count == 2


def test_independent_postgres_replicas_share_cumulative_privacy_history() -> None:
    _reset_database()
    replica_a = _ledger()
    replica_b = _ledger()

    sql_a = _sensitive_sql("alpha")
    sql_b = _sensitive_sql("beta")

    decision_a = replica_a.evaluate_and_commit(_event(sql_a, 1), sql=sql_a)
    decision_b = replica_b.evaluate_and_commit(_event(sql_b, 2), sql=sql_b)

    assert decision_a.allowed is True
    assert decision_a.rule == CompositionRule.FIRST_PROTECTED_RELEASE
    assert decision_b.allowed is False
    assert decision_b.rule == CompositionRule.CUMULATIVE_VARIATION_BLOCK


def test_concurrent_postgres_replicas_serialize_same_privacy_scope() -> None:
    _reset_database()
    replica_a = _ledger()
    replica_b = _ledger()
    barrier = threading.Barrier(2)
    results = []
    errors = []

    def run(ledger: PostgresDisclosureLedger, literal: str, receipt_index: int) -> None:
        try:
            sql = _sensitive_sql(literal)
            barrier.wait(timeout=10)
            results.append(ledger.evaluate_and_commit(_event(sql, receipt_index), sql=sql))
        except BaseException as exc:  # pragma: no cover - surfaced below with full failure context
            errors.append(exc)

    first = threading.Thread(target=run, args=(replica_a, "alpha", 11))
    second = threading.Thread(target=run, args=(replica_b, "beta", 12))
    first.start()
    second.start()
    first.join(timeout=20)
    second.join(timeout=20)

    assert not first.is_alive() and not second.is_alive()
    assert errors == []
    assert len(results) == 2
    assert sum(decision.allowed for decision in results) == 1
    blocked = [decision for decision in results if not decision.allowed]
    assert len(blocked) == 1
    assert blocked[0].rule == CompositionRule.CUMULATIVE_VARIATION_BLOCK
