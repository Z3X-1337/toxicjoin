"""Independent verification before and after safe query execution."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from pydantic import model_validator

from toxicjoin.context.fixture import ContextResolution
from toxicjoin.execute import DuckDBExecutor, ExecutionError, ExecutionResult
from toxicjoin.models import (
    ColumnRef,
    Decision,
    PolicyDecision,
    ProjectionExposureKind,
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
    execution_attempted: bool = False
    execution_quarantined: bool = False
    execution_error: str | None = None

    @model_validator(mode="after")
    def failed_verification_never_releases_rows(self) -> "VerificationResult":
        if self.execution is not None:
            if not self.passed:
                raise ValueError("failed verification cannot release execution rows")
            if not self.execution_attempted:
                raise ValueError("released execution requires execution_attempted")
            if self.execution_quarantined:
                raise ValueError("released execution cannot also be quarantined")
        if self.execution_quarantined:
            if not self.execution_attempted:
                raise ValueError("quarantined execution requires execution_attempted")
            if self.passed:
                raise ValueError("successful verification cannot quarantine execution")
        return self


def verify_and_execute(
    sql: str,
    *,
    task_purpose: str,
    subject_key: ColumnRef,
    context_resolver: ContextResolver,
    policy_engine: PolicyEngine,
    executor: DuckDBExecutor,
    required_minimum_group_size: int,
    require_subject_threshold: bool = True,
    subject_count_column: str = "subject_count",
    forbidden_raw_output_fields: Iterable[str] = (
        "customer_id",
        "email",
        "phone",
        "full_name",
        "precise_area",
    ),
    dialect: str = "duckdb",
    rewrite_parent_sql: str | None = None,
) -> VerificationResult:
    """Verify final SQL, execute into quarantine, and release rows only after all checks."""

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
            passed=threshold_matches if require_subject_threshold else True,
            detail=(
                f"COUNT(DISTINCT {subject_key.key}) >= {required_minimum_group_size}"
                if threshold_matches
                else (
                    "subject threshold is not required for this policy outcome"
                    if not require_subject_threshold
                    else "required subject-bound minimum group threshold is absent or insufficient"
                )
            ),
        )
    )

    forbidden = {field.lower() for field in forbidden_raw_output_fields}
    leaked_fields, unresolved_outputs = _semantic_forbidden_outputs(
        query_plan,
        forbidden=forbidden,
    )
    semantic_outputs_safe = not leaked_fields and not unresolved_outputs
    checks.append(
        VerificationCheck(
            name="no_raw_forbidden_output",
            passed=semantic_outputs_safe,
            detail=(
                "no forbidden field is exposed through final-output semantic lineage"
                if semantic_outputs_safe
                else _forbidden_output_detail(leaked_fields, unresolved_outputs)
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
        executor.bind_authority(
            context_resolver=context_resolver,
            policy_engine=policy_engine,
        )
    except ValueError as exc:
        checks.append(
            VerificationCheck(
                name="execution_authorization",
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

    try:
        authorization = executor.issue_authorization(
            sql,
            task_purpose=task_purpose,
            subject_key=subject_key,
            dialect=dialect,
            rewrite_parent_sql=rewrite_parent_sql,
        )
    except ExecutionError as exc:
        checks.append(
            VerificationCheck(
                name="execution_authorization",
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
            name="execution_authorization",
            passed=True,
            detail=(
                "single-use capability issued for exact SQL, plan, governance context, "
                "policy, task, subject, and optional rewrite lineage"
            ),
        )
    )

    try:
        execution = executor.execute_authorized(
            sql,
            authorization=authorization,
            task_purpose=task_purpose,
            subject_key=subject_key,
            dialect=dialect,
            rewrite_parent_sql=rewrite_parent_sql,
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
            execution_attempted=True,
            execution_error=str(exc),
        )

    if require_subject_threshold:
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
                group_sizes_valid = (
                    bool(group_sizes)
                    and min(group_sizes) >= required_minimum_group_size
                )
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
    else:
        checks.append(
            VerificationCheck(
                name="bounded_preview",
                passed=True,
                detail=(
                    f"returned {execution.preview_row_count} preview rows"
                    + (" with truncation" if execution.truncated else " without truncation")
                ),
            )
        )

    return _result(
        query_plan=query_plan,
        policy_decision=decision,
        checks=checks,
        execution=execution,
        execution_attempted=True,
    )


def _semantic_forbidden_outputs(
    query_plan: QueryPlan,
    *,
    forbidden: set[str],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    value_exposing_kinds = {
        ProjectionExposureKind.RAW_VALUE,
        ProjectionExposureKind.TRANSFORMED_RAW_VALUE,
        ProjectionExposureKind.GROUP_KEY,
        ProjectionExposureKind.AGGREGATE_OPERAND,
    }
    leaked_fields = {
        ref.field_path.lower()
        for exposure in query_plan.projected_exposures
        if exposure.kind in value_exposing_kinds
        for ref in exposure.source_columns
        if ref.field_path.lower() in forbidden
    }
    unresolved_outputs = {
        exposure.output_name
        for exposure in query_plan.projected_exposures
        if exposure.kind == ProjectionExposureKind.NESTED_SCOPE
    }
    return tuple(sorted(leaked_fields)), tuple(sorted(unresolved_outputs))


def _forbidden_output_detail(
    leaked_fields: tuple[str, ...],
    unresolved_outputs: tuple[str, ...],
) -> str:
    details: list[str] = []
    if leaked_fields:
        details.append(
            "forbidden source lineage exposed by output: " + ", ".join(leaked_fields)
        )
    if unresolved_outputs:
        details.append(
            "output lineage could not be proven safe: " + ", ".join(unresolved_outputs)
        )
    return "; ".join(details)


def _result(
    *,
    query_plan: QueryPlan | None,
    policy_decision: PolicyDecision | None,
    checks: list[VerificationCheck],
    execution: ExecutionResult | None = None,
    execution_attempted: bool = False,
    execution_error: str | None = None,
) -> VerificationResult:
    passed = bool(checks) and all(check.passed for check in checks)
    execution_quarantined = bool(execution is not None and not passed)
    released_execution = execution if passed else None
    return VerificationResult(
        passed=passed,
        query_plan=query_plan,
        policy_decision=policy_decision,
        checks=tuple(checks),
        execution=released_execution,
        execution_attempted=execution_attempted,
        execution_quarantined=execution_quarantined,
        execution_error=execution_error,
    )
