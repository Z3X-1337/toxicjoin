from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import seed_database
from toxicjoin.execute import DuckDBExecutor, ExecutionError
from toxicjoin.models import ColumnRef, Decision, ReasonCode
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

    def __getattr__(self, _: str) -> Any:
        self.called = True
        raise AssertionError("executor must not be called")


def _resolver() -> FixtureContextResolver:
    return FixtureContextResolver.from_path(CATALOG)


def _engine() -> PolicyEngine:
    return PolicyEngine(load_policy())


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
    assert result.execution.authorization_id.startswith("tj_auth_")
    assert result.execution.columns == (
        "coarse_region",
        "average_churn",
        "subject_count",
    )
    assert result.execution.preview_row_count == 3
    assert result.execution.truncated is False
    assert {int(row[2]) for row in result.execution.rows} == {40}
    assert all(check.passed for check in result.checks)
    assert any(check.name == "execution_authorization" for check in result.checks)


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


def test_executor_cannot_issue_without_bound_authority(tmp_path) -> None:
    database = tmp_path / "demo.duckdb"
    seed_database(database)
    executor = DuckDBExecutor(database)

    with pytest.raises(ExecutionError, match="no execution authorizer bound"):
        executor.issue_authorization(
            "SELECT c.coarse_region FROM customers c",
            task_purpose="List coarse regions",
            subject_key=SUBJECT,
        )


def test_executor_rejects_post_authorization_sql_mutation(tmp_path) -> None:
    database = tmp_path / "demo.duckdb"
    seed_database(database)
    resolver = _resolver()
    engine = _engine()
    executor = DuckDBExecutor(database)
    executor.bind_authority(context_resolver=resolver, policy_engine=engine)

    sql = "SELECT c.coarse_region FROM customers c LIMIT 5"
    authorization = executor.issue_authorization(
        sql,
        task_purpose="List coarse regions",
        subject_key=SUBJECT,
    )

    with pytest.raises(ExecutionError, match="AUTH_SQL_MISMATCH") as captured:
        executor.execute_authorized(
            sql + " LIMIT 1",
            authorization=authorization,
            task_purpose="List coarse regions",
            subject_key=SUBJECT,
        )

    assert captured.value.reason_code == ReasonCode.VERIFICATION_FAILED


def test_executor_hardens_duckdb_configuration(tmp_path) -> None:
    database = tmp_path / "demo.duckdb"
    seed_database(database)

    result = verify_and_execute(
        "SELECT current_setting('enable_external_access') AS external_access",
        task_purpose="Verify hardened DuckDB execution configuration",
        subject_key=SUBJECT,
        context_resolver=_resolver(),
        policy_engine=_engine(),
        executor=DuckDBExecutor(database),
        required_minimum_group_size=20,
        require_subject_threshold=False,
    )

    assert result.passed is True
    assert result.execution is not None
    assert result.execution.rows == ((False,),)
    assert result.execution.truncated is False
