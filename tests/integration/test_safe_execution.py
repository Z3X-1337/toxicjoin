from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import seed_database
from toxicjoin.execute import DuckDBExecutor, ExecutionError
from toxicjoin.models import ColumnRef, Decision, PolicyDecision, ReasonCode
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.rewrite import enforce_minimum_group_size
from toxicjoin.verify import verify_and_execute


ROOT = Path(__file__).parents[2]
CATALOG = ROOT / "demo" / "fixtures" / "catalog.json"
SUBJECT = ColumnRef(dataset="customers", field_path="customer_id", alias="c")


FLAGSHIP_SQL = """
SELECT
  c.coarse_region,
  AVG(r.churn_score) AS average_churn,
  COUNT(DISTINCT c.customer_id) AS subject_count
FROM customers c
JOIN retention_scores r ON c.customer_id = r.customer_id
GROUP BY c.coarse_region
"""


BLOCKED_SQL = """
SELECT c.customer_id, c.age_band, c.precise_area, s.case_category
FROM customers c
JOIN support_cases s ON c.customer_id = s.customer_id
"""


class FailIfCalledExecutor:
    def __init__(self) -> None:
        self.called = False

    def execute_allowed(self, *_: Any, **__: Any) -> Any:
        self.called = True
        raise AssertionError("executor must not be called")


def _resolver() -> FixtureContextResolver:
    return FixtureContextResolver.from_path(CATALOG)


def _engine() -> PolicyEngine:
    return PolicyEngine(load_policy())


def _allow_decision() -> PolicyDecision:
    return PolicyDecision(
        decision=Decision.ALLOW,
        reason_codes=(ReasonCode.NO_COMPOSITIONAL_RISK,),
        policy_version="test",
        evidence={},
    )


def test_rewritten_flagship_query_executes_and_verifies(tmp_path) -> None:
    database = tmp_path / "demo.duckdb"
    seed_database(database)
    rewrite = enforce_minimum_group_size(
        FLAGSHIP_SQL,
        subject_key=SUBJECT,
        minimum_group_size=20,
    )

    result = verify_and_execute(
        rewrite.safe_sql,
        task_purpose="Find regions with elevated churn risk",
        subject_key=SUBJECT,
        context_resolver=_resolver(),
        policy_engine=_engine(),
        executor=DuckDBExecutor(database),
        required_minimum_group_size=20,
    )

    assert result.passed is True
    assert result.policy_decision is not None
    assert result.policy_decision.decision == Decision.ALLOW
    assert result.execution is not None
    assert result.execution.columns == (
        "coarse_region",
        "average_churn",
        "subject_count",
    )
    assert result.execution.preview_row_count == 3
    assert result.execution.truncated is False
    assert {int(row[2]) for row in result.execution.rows} == {40}
    assert all(check.passed for check in result.checks)


def test_rewrite_decision_never_reaches_executor() -> None:
    executor = FailIfCalledExecutor()

    result = verify_and_execute(
        FLAGSHIP_SQL,
        task_purpose="Find regions with elevated churn risk",
        subject_key=SUBJECT,
        context_resolver=_resolver(),
        policy_engine=_engine(),
        executor=executor,  # type: ignore[arg-type]
        required_minimum_group_size=20,
    )

    assert result.passed is False
    assert result.policy_decision is not None
    assert result.policy_decision.decision == Decision.REWRITE
    assert result.execution is None
    assert executor.called is False


def test_block_decision_never_reaches_executor() -> None:
    executor = FailIfCalledExecutor()

    result = verify_and_execute(
        BLOCKED_SQL,
        task_purpose="Export customers with sensitive support cases",
        subject_key=SUBJECT,
        context_resolver=_resolver(),
        policy_engine=_engine(),
        executor=executor,  # type: ignore[arg-type]
        required_minimum_group_size=20,
    )

    assert result.passed is False
    assert result.policy_decision is not None
    assert result.policy_decision.decision == Decision.BLOCK
    assert result.execution is None
    assert executor.called is False


def test_raw_forbidden_output_stops_before_execution() -> None:
    executor = FailIfCalledExecutor()
    sql = """
    SELECT
      c.coarse_region,
      c.precise_area,
      AVG(r.churn_score) AS average_churn,
      COUNT(DISTINCT c.customer_id) AS subject_count
    FROM customers c
    JOIN retention_scores r ON c.customer_id = r.customer_id
    GROUP BY c.coarse_region, c.precise_area
    HAVING COUNT(DISTINCT c.customer_id) >= 20
    """

    result = verify_and_execute(
        sql,
        task_purpose="Find precise areas with elevated churn risk",
        subject_key=SUBJECT,
        context_resolver=_resolver(),
        policy_engine=_engine(),
        executor=executor,  # type: ignore[arg-type]
        required_minimum_group_size=20,
    )

    assert result.passed is False
    assert any(
        check.name == "no_raw_forbidden_output" and not check.passed
        for check in result.checks
    )
    assert executor.called is False


def test_executor_requires_allow_decision(tmp_path) -> None:
    database = tmp_path / "demo.duckdb"
    seed_database(database)
    executor = DuckDBExecutor(database)
    rewrite_decision = PolicyDecision(
        decision=Decision.REWRITE,
        reason_codes=(ReasonCode.SMALL_GROUP_RISK,),
        policy_version="test",
        evidence={},
        rewrite_required=True,
    )

    with pytest.raises(ExecutionError, match="requires ALLOW"):
        executor.execute_allowed(
            "SELECT c.coarse_region FROM customers c",
            policy_decision=rewrite_decision,
        )


def test_executor_rejects_mutation_even_with_allow_decision(tmp_path) -> None:
    database = tmp_path / "demo.duckdb"
    seed_database(database)

    with pytest.raises(ExecutionError) as captured:
        DuckDBExecutor(database).execute_allowed(
            "DELETE FROM customers",
            policy_decision=_allow_decision(),
        )

    assert captured.value.reason_code == ReasonCode.UNSUPPORTED_STATEMENT


def test_executor_hardens_duckdb_configuration(tmp_path) -> None:
    database = tmp_path / "demo.duckdb"
    seed_database(database)

    result = DuckDBExecutor(database).execute_allowed(
        "SELECT current_setting('enable_external_access') AS external_access",
        policy_decision=_allow_decision(),
    )

    assert result.rows == ((False,),)
    assert result.truncated is False
