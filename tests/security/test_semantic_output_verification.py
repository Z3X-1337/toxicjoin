from __future__ import annotations

import hashlib

from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog
from toxicjoin.execute import ExecutionResult
from toxicjoin.models import ColumnRef
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.sql import analyze_sql
from toxicjoin.verify import verify_and_execute


class RecordingExecutor:
    def __init__(self) -> None:
        self.calls = 0

    def bind_authority(self, **_: object) -> None:
        return None

    def issue_authorization(self, *_: object, **__: object) -> object:
        return object()

    def execute_authorized(self, sql: str, **kwargs: object) -> ExecutionResult:
        self.calls += 1
        plan = analyze_sql(sql, dialect=str(kwargs.get("dialect", "duckdb")))
        return ExecutionResult(
            authorization_id="tj_auth_" + "0" * 32,
            query_sha256=hashlib.sha256(sql.encode("utf-8")).hexdigest(),
            query_plan=plan,
            columns=("customer_count",),
            rows=((120,),),
            preview_row_count=1,
            truncated=False,
            elapsed_ms=0.0,
        )


def _verify(sql: str, executor: RecordingExecutor):
    return verify_and_execute(
        sql,
        task_purpose="Semantic output verification regression",
        subject_key=ColumnRef(dataset="customers", field_path="customer_id"),
        context_resolver=FixtureContextResolver(default_fixture_catalog()),
        policy_engine=PolicyEngine(load_policy()),
        executor=executor,  # type: ignore[arg-type]
        required_minimum_group_size=20,
        require_subject_threshold=False,
        forbidden_raw_output_fields=("customer_id",),
    )


def _output_check(result):
    return next(
        check for check in result.checks if check.name == "no_raw_forbidden_output"
    )


def test_wrapped_subject_identifier_is_stopped_before_executor() -> None:
    executor = RecordingExecutor()
    result = _verify(
        """
        SELECT UPPER(c.customer_id) AS subject_token
        FROM customers c
        ORDER BY c.customer_id
        LIMIT 5
        """.strip(),
        executor,
    )

    assert result.passed is False
    assert result.policy_decision is not None
    assert result.policy_decision.decision.value == "ALLOW"
    assert executor.calls == 0
    output_check = _output_check(result)
    assert output_check.passed is False
    assert "customer_id" in output_check.detail


def test_min_subject_identifier_is_stopped_before_executor() -> None:
    executor = RecordingExecutor()
    result = _verify(
        """
        SELECT MIN(c.customer_id) AS min_customer_id
        FROM customers c
        """.strip(),
        executor,
    )

    assert result.passed is False
    assert result.policy_decision is not None
    assert result.policy_decision.decision.value == "ALLOW"
    assert executor.calls == 0
    output_check = _output_check(result)
    assert output_check.passed is False
    assert "customer_id" in output_check.detail


def test_count_of_subject_identifier_is_not_misclassified_as_raw_output() -> None:
    executor = RecordingExecutor()
    result = _verify(
        """
        SELECT COUNT(c.customer_id) AS customer_count
        FROM customers c
        """.strip(),
        executor,
    )

    assert result.passed is True
    assert executor.calls == 1
    assert _output_check(result).passed is True
