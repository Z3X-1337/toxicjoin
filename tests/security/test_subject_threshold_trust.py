"""Regressions for the two proven k-anonymity threshold bypasses.

Both attacks satisfied every syntactic gate ToxicJoin enforced while releasing aggregates
over cohorts far below the configured minimum. They share one root cause: the k-anonymity
witness was taken from caller-controlled input instead of being derived from governed
metadata and proven output lineage.

Each test asserts the *released rows*, not only the decision label, because the decision was
never the thing that leaked.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog
from toxicjoin.execute import DuckDBExecutor
from toxicjoin.models import ColumnRef, Decision, ReasonCode
from toxicjoin.pipeline import PipelineRequest, ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import ReceiptMode, ReceiptStore
from toxicjoin.sql import analyze_sql


CUSTOMER_SUBJECT = ColumnRef(dataset="customers", field_path="customer_id", alias="c")
ORDER_SUBJECT = ColumnRef(dataset="orders", field_path="order_id", alias="o")

# Grouping by (age_band, coarse_region) produces cohorts holding as few as four distinct
# customers in the deterministic seed, so any release here is a real k-anonymity failure.
SMALL_COHORT_GROUPING = "GROUP BY c.age_band, c.coarse_region"

FABRICATED_SUBJECT_COUNT_SQL = f"""
SELECT c.age_band, c.coarse_region, AVG(o.purchase_amount) AS avg_spend,
       999 AS subject_count
FROM customers c JOIN orders o ON c.customer_id = o.customer_id
{SMALL_COHORT_GROUPING}
HAVING NOT (COUNT(DISTINCT c.customer_id) >= 20)
""".strip()

ATTACKER_CHOSEN_SUBJECT_SQL = f"""
SELECT c.age_band, c.coarse_region, AVG(o.purchase_amount) AS avg_spend,
       COUNT(DISTINCT o.order_id) AS subject_count
FROM customers c JOIN orders o ON c.customer_id = o.customer_id
{SMALL_COHORT_GROUPING}
HAVING COUNT(DISTINCT o.order_id) >= 20
""".strip()

HONEST_SQL = """
SELECT c.coarse_region, AVG(r.churn_score) AS average_churn,
       COUNT(DISTINCT c.customer_id) AS subject_count
FROM customers c JOIN retention_scores r ON c.customer_id = r.customer_id
GROUP BY c.coarse_region
HAVING COUNT(DISTINCT c.customer_id) >= 20
""".strip()


@pytest.fixture
def pipeline(seeded_database: Path, tmp_path: Path) -> ToxicJoinPipeline:
    return ToxicJoinPipeline(
        context_resolver=FixtureContextResolver(default_fixture_catalog()),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(seeded_database),
    )


def _run(pipeline: ToxicJoinPipeline, sql: str, subject: ColumnRef):
    request = PipelineRequest(task_purpose="threshold trust", sql=sql, subject_key=subject)
    return pipeline.analyze(request), pipeline.execute_safe(request)


def _released_rows(result) -> tuple:
    if result.verification is None or result.verification.execution is None:
        return ()
    return result.verification.execution.rows


# --------------------------------------------------------------------------------------
# Bypass 1: a literal aliased as subject_count, plus a boolean-inverted HAVING.
# --------------------------------------------------------------------------------------


def test_fabricated_subject_count_never_releases_rows(pipeline: ToxicJoinPipeline) -> None:
    analyzed, executed = _run(pipeline, FABRICATED_SUBJECT_COUNT_SQL, CUSTOMER_SUBJECT)

    assert analyzed.effective_decision != Decision.ALLOW
    assert executed.effective_decision != Decision.ALLOW
    assert _released_rows(executed) == ()


def test_inverted_having_is_not_a_trusted_threshold() -> None:
    plan = analyze_sql(FABRICATED_SUBJECT_COUNT_SQL)

    assert plan.minimum_group_size_present is None
    assert plan.minimum_group_size_subject is None
    assert "UNTRUSTED_GROUP_THRESHOLD_NON_CONJUNCTIVE" in plan.analysis_warnings


def test_case_guarded_threshold_is_not_trusted() -> None:
    plan = analyze_sql(
        "SELECT c.coarse_region, AVG(r.churn_score) AS avg_churn "
        "FROM customers c JOIN retention_scores r ON c.customer_id = r.customer_id "
        "GROUP BY c.coarse_region "
        "HAVING CASE WHEN COUNT(DISTINCT c.customer_id) >= 20 THEN FALSE ELSE TRUE END"
    )

    assert plan.minimum_group_size_present is None
    assert "UNTRUSTED_GROUP_THRESHOLD_NON_CONJUNCTIVE" in plan.analysis_warnings


def test_threshold_conjoined_with_other_predicates_stays_trusted() -> None:
    """An AND spine keeps every conjunct binding, so the threshold remains provable."""

    plan = analyze_sql(
        "SELECT c.coarse_region, AVG(r.churn_score) AS avg_churn "
        "FROM customers c JOIN retention_scores r ON c.customer_id = r.customer_id "
        "GROUP BY c.coarse_region "
        "HAVING AVG(r.churn_score) > 0.1 AND (COUNT(DISTINCT c.customer_id) >= 20)"
    )

    assert plan.minimum_group_size_present == 20
    assert plan.minimum_group_size_subject is not None
    assert plan.minimum_group_size_subject.key == "customers.customer_id"
    assert "UNTRUSTED_GROUP_THRESHOLD_NON_CONJUNCTIVE" not in plan.analysis_warnings


def test_subject_count_must_be_proven_by_output_lineage(pipeline: ToxicJoinPipeline) -> None:
    """Isolate the verifier: an honest HAVING still cannot verify a fabricated count column.

    The threshold here is a genuine top-level conjunct, so policy reaches ALLOW and execution
    is attempted. Only the output-lineage binding stands between the literal ``999`` and a
    released result, which is exactly the gate this test pins.
    """

    sql = (
        "SELECT c.age_band, AVG(o.purchase_amount) AS avg_spend, 999 AS subject_count "
        "FROM customers c JOIN orders o ON c.customer_id = o.customer_id "
        "GROUP BY c.age_band "
        "HAVING COUNT(DISTINCT c.customer_id) >= 20"
    )
    analyzed, executed = _run(pipeline, sql, CUSTOMER_SUBJECT)

    assert analyzed.initial_decision.decision == Decision.ALLOW
    assert executed.verification is not None
    named = {check.name: check for check in executed.verification.checks}
    assert not named["subject_count_output"].passed
    assert "not proven by output lineage" in named["subject_count_output"].detail
    assert executed.effective_decision == Decision.BLOCK
    assert _released_rows(executed) == ()


# --------------------------------------------------------------------------------------
# Bypass 2: the caller declares a public column as the privacy subject.
# --------------------------------------------------------------------------------------


def test_attacker_chosen_subject_key_never_releases_rows(
    pipeline: ToxicJoinPipeline,
) -> None:
    analyzed, executed = _run(pipeline, ATTACKER_CHOSEN_SUBJECT_SQL, ORDER_SUBJECT)

    assert analyzed.effective_decision == Decision.BLOCK
    assert executed.effective_decision == Decision.BLOCK
    assert _released_rows(executed) == ()


def test_non_identifier_subject_is_reported_as_the_fault(
    pipeline: ToxicJoinPipeline,
) -> None:
    """The decision must name the bad declaration rather than imply a rewrite could fix it."""

    analyzed, _ = _run(pipeline, ATTACKER_CHOSEN_SUBJECT_SQL, ORDER_SUBJECT)

    assert ReasonCode.UNTRUSTED_SUBJECT_KEY in analyzed.initial_decision.reason_codes
    assert analyzed.initial_decision.evidence["subject_governed_category"] == (
        "PUBLIC_OR_LOW_RISK"
    )
    assert analyzed.initial_decision.evidence["subject_is_governed_identifier"] is False


# --------------------------------------------------------------------------------------
# The fixes must not weaken the legitimate paths the product demonstrates.
# --------------------------------------------------------------------------------------


def test_honest_threshold_still_allows_and_releases(pipeline: ToxicJoinPipeline) -> None:
    analyzed, executed = _run(pipeline, HONEST_SQL, CUSTOMER_SUBJECT)

    assert analyzed.effective_decision == Decision.ALLOW
    assert executed.effective_decision == Decision.ALLOW
    assert len(_released_rows(executed)) == 3


def test_flagship_rewrite_still_reaches_verified_allow(pipeline: ToxicJoinPipeline) -> None:
    sql = (
        "SELECT c.coarse_region, AVG(r.churn_score) AS average_churn, "
        "COUNT(DISTINCT c.customer_id) AS subject_count "
        "FROM customers c JOIN retention_scores r ON c.customer_id = r.customer_id "
        "GROUP BY c.coarse_region"
    )
    analyzed, executed = _run(pipeline, sql, CUSTOMER_SUBJECT)

    assert analyzed.initial_decision.decision == Decision.REWRITE
    assert executed.effective_decision == Decision.ALLOW
    assert len(_released_rows(executed)) == 3
