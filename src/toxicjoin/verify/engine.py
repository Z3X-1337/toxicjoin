"""Independent verification before and after safe query execution."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

import sqlglot
from sqlglot import exp

from toxicjoin.context.fixture import ContextResolution
from toxicjoin.execute import DuckDBExecutor, ExecutionError, ExecutionResult
from toxicjoin.models import (
    ColumnRef,
    Decision,
    PolicyDecision,
    QueryPlan,
    StrictModel,
)
from toxicjoin.policy import PolicyEngine
from toxicjoin.sql import SqlAnalysisError, analyze_sql


class ContextResolver(Protocol):
    def resolve(self, query_plan: QueryPlan) -> ContextResolution: ...


class VerificationCheck(StrictModel):
    name: str
    passed: bool
    detail: str


class VerificationResult(StrictModel):
    passed: bool
    query_plan: QueryPlan | None
    policy_decision: PolicyDecision | None
    checks: tuple[VerificationCheck, ...]
    execution: ExecutionResult | None = None
    execution_error: str | None = None


def verify_and_execute(
    sql: str,
    *,
    task_purpose: str,
    subject_key: ColumnRef,
    context_resolver: ContextResolver,
    policy_engine: PolicyEngine,
    executor: DuckDBExecutor,
    required_minimum_group_size: int,
    subject_count_column: str = "subject_count",
    forbidden_raw_output_fields: Iterable[str] = (
        "customer_id",
        "email",
        "phone",
        "full_name",
        "precise_area",
    ),
    dialect: str = "duckdb",
) -> VerificationResult:
    """Verify the final SQL, execute only after all preconditions pass, then audit results."""

    checks: list[VerificationCheck] = []
    try:
        query_plan = analyze_sql(sql, dialect=dialect)
    except SqlAnalysisError as exc:
        checks.append(
            VerificationCheck(
                name="sql_analysis",
                passed=False,
                detail=str(exc),
            )
        )
        return _result(
            query_plan=None,
            policy_decision=None,
            checks=checks,
            execution_error=str(exc),
        )

    resolution = context_resolver.resolve(query_plan)
    policy_input = resolution.to_policy_input(
        task_purpose=task_purpose,
        query_plan=query_plan,
        subject_key=subject_key,
    )
    decision = policy_engine.evaluate(policy_input)

    checks.append(
        VerificationCheck(
            name="policy_allow",
            passed=decision.decision == Decision.ALLOW,
            detail=(
                "final deterministic decision is ALLOW"
                if decision.decision == Decision.ALLOW
                else f"final deterministic decision is {decision.decision.value}"
            ),
        )
    )

    threshold_matches = (
        query_plan.minimum_group_size_present is not None
        and query_plan.minimum_group_size_present >= required_minimum_group_size
        and query_plan.minimum_group_size_subject is not None
        and query_plan.minimum_group_size_subject.key == subject_key.key
    )
    checks.append(
        VerificationCheck(
            name="trusted_subject_threshold",
            passed=threshold_matches,
            detail=(
                f"COUNT(DISTINCT {subject_key.key}) >= {required_minimum_group_size}"
                if threshold_matches
                else "required subject-bound minimum group threshold is absent or insufficient"
            ),
        )
    )

    forbidden = {field.lower() for field in forbidden_raw_output_fields}
    bare_outputs = _bare_output_field_names(sql, dialect=dialect)
    leaked_fields = tuple(sorted(forbidden.intersection(bare_outputs)))
    checks.append(
        VerificationCheck(
            name="no_raw_forbidden_output",
            passed=not leaked_fields,
            detail=(
                "no forbidden field is projected as a raw output column"
                if not leaked_fields
                else f"raw forbidden output fields: {', '.join(leaked_fields)}"
            ),
        )
    )

    if not all(check.passed for check in checks):
        return _result(
            query_plan=query_plan,
            policy_decision=decision,
            checks=checks,
        )

    try:
        execution = executor.execute_allowed(
            sql,
            policy_decision=decision,
            dialect=dialect,
        )
    except ExecutionError as exc:
        checks.append(
            VerificationCheck(
                name="execution",
                passed=False,
                detail=str(exc),
            )
        )
        return _result(
            query_plan=query_plan,
            policy_decision=decision,
            checks=checks,
            execution_error=str(exc),
        )

    checks.append(
        VerificationCheck(
            name="complete_result_set",
            passed=not execution.truncated,
            detail=(
                "all result groups were inspected"
                if not execution.truncated
                else "result preview was truncated; all groups could not be verified"
            ),
        )
    )

    normalized_columns = tuple(column.lower() for column in execution.columns)
    count_column_present = subject_count_column.lower() in normalized_columns
    checks.append(
        VerificationCheck(
            name="subject_count_output",
            passed=count_column_present,
            detail=(
                f"result contains {subject_count_column!r}"
                if count_column_present
                else f"result does not contain required {subject_count_column!r} column"
            ),
        )
    )

    group_sizes_valid = False
    group_detail = "group sizes were not evaluated"
    if count_column_present and not execution.truncated:
        index = normalized_columns.index(subject_count_column.lower())
        try:
            group_sizes = tuple(int(row[index]) for row in execution.rows)
        except (IndexError, TypeError, ValueError) as exc:
            group_detail = f"subject counts are not valid integers: {exc}"
        else:
            group_sizes_valid = bool(group_sizes) and min(group_sizes) >= required_minimum_group_size
            group_detail = (
                f"minimum observed group size is {min(group_sizes)}"
                if group_sizes
                else "query returned no groups; usefulness could not be verified"
            )

    checks.append(
        VerificationCheck(
            name="observed_group_sizes",
            passed=group_sizes_valid,
            detail=group_detail,
        )
    )

    return _result(
        query_plan=query_plan,
        policy_decision=decision,
        checks=checks,
        execution=execution,
    )


def _bare_output_field_names(sql: str, *, dialect: str) -> set[str]:
    root = sqlglot.parse_one(sql, read=dialect)
    if not isinstance(root, exp.Select):
        return set()

    names: set[str] = set()
    for projection in root.expressions:
        expression = projection.this if isinstance(projection, exp.Alias) else projection
        if isinstance(expression, exp.Column):
            names.add(expression.name.lower())
    return names


def _result(
    *,
    query_plan: QueryPlan | None,
    policy_decision: PolicyDecision | None,
    checks: list[VerificationCheck],
    execution: ExecutionResult | None = None,
    execution_error: str | None = None,
) -> VerificationResult:
    return VerificationResult(
        passed=bool(checks) and all(check.passed for check in checks),
        query_plan=query_plan,
        policy_decision=policy_decision,
        checks=tuple(checks),
        execution=execution,
        execution_error=execution_error,
    )
