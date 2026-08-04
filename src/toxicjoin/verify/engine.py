"""Independent verification before and after safe query execution."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol

from pydantic import model_validator

from toxicjoin.auth import current_request_identity
from toxicjoin.context.fixture import ContextResolution
from toxicjoin.disclosure import (
    DisclosureLedger,
    DisclosureLedgerError,
    DisclosureSemanticError,
    build_disclosure_event_from_resolver,
)
from toxicjoin.execute import DuckDBExecutor, ExecutionError, ExecutionResult
from toxicjoin.models import (
    ColumnRef,
    Decision,
    PolicyDecision,
    ProjectionExposureKind,
    QueryPlan,
    ReasonCode,
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
    failure_reason_codes: tuple[ReasonCode, ...] = ()

    @model_validator(mode="after")
    def failed_verification_never_releases_rows(self) -> "VerificationResult":
        if self.execution is not None:
            if not self.passed:
                raise ValueError("failed verification cannot release execution rows")
            if self.execution_quarantined:
                raise ValueError("released execution cannot also be quarantined")
        if self.execution_quarantined:
            if not self.execution_attempted:
                raise ValueError("quarantined execution requires execution_attempted")
            if self.passed:
                raise ValueError("successful verification cannot quarantine execution")
        if self.passed and self.failure_reason_codes:
            raise ValueError("successful verification cannot carry failure reason codes")
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
    disclosure_ledger: DisclosureLedger | None = None,
    receipt_id: str | None = None,
    require_disclosure_commitment: bool = False,
) -> VerificationResult:
    """Verify final SQL, commit privacy state, execute in quarantine, then release rows."""

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

    disclosure_commitment = None
    if disclosure_ledger is not None or require_disclosure_commitment:
        identity = current_request_identity()
        if disclosure_ledger is None or receipt_id is None or identity is None:
            checks.append(
                VerificationCheck(
                    name="cumulative_disclosure",
                    passed=False,
                    detail="required disclosure ledger, receipt identity, or request identity is unavailable",
                )
            )
            return _result(
                query_plan=query_plan,
                policy_decision=decision,
                checks=checks,
                failure_reason_codes=(ReasonCode.DISCLOSURE_STATE_UNAVAILABLE,),
            )

        try:
            disclosure_event = build_disclosure_event_from_resolver(
                identity=identity,
                resolver=context_resolver,
                resolution=resolution,
                query_plan=query_plan,
                subject_key=subject_key,
                receipt_id=receipt_id,
                policy_version=decision.policy_version,
            )
            composition = disclosure_ledger.evaluate_and_commit(
                disclosure_event,
                sql=sql,
                dialect=dialect,
            )
        except (DisclosureLedgerError, DisclosureSemanticError, ValueError):
            checks.append(
                VerificationCheck(
                    name="cumulative_disclosure",
                    passed=False,
                    detail="cumulative disclosure state could not be validated safely",
                )
            )
            return _result(
                query_plan=query_plan,
                policy_decision=decision,
                checks=checks,
                failure_reason_codes=(ReasonCode.DISCLOSURE_STATE_UNAVAILABLE,),
            )

        if not composition.allowed or composition.commitment is None:
            checks.append(
                VerificationCheck(
                    name="cumulative_disclosure",
                    passed=False,
                    detail=(
                        f"blocked by {composition.rule.value}; "
                        f"prior protected releases={composition.prior_protected_count}"
                    ),
                )
            )
            return _result(
                query_plan=query_plan,
                policy_decision=decision,
                checks=checks,
                failure_reason_codes=(ReasonCode.CUMULATIVE_DISCLOSURE_RISK,),
            )

        disclosure_commitment = composition.commitment
        checks.append(
            VerificationCheck(
                name="cumulative_disclosure",
                passed=True,
                detail=(
                    f"release committed by {composition.rule.value}; "
                    f"prior protected releases={composition.prior_protected_count}"
                ),
            )
        )

    try:
        executor.bind_authority(
            context_resolver=context_resolver,
            policy_engine=policy_engine,
            disclosure_ledger=disclosure_ledger,
            require_disclosure_commitment=require_disclosure_commitment,
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
            disclosure_commitment=disclosure_commitment,
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
            failure_reason_codes=(exc.reason_code,),
        )

    checks.append(
        VerificationCheck(
            name="execution_authorization",
            passed=True,
            detail=(
                "single-use capability issued for exact SQL, plan, governance context, "
                "policy, task, subject, identity, rewrite lineage, and disclosure commitment"
                if disclosure_commitment is not None
                else (
                    "single-use capability issued for exact SQL, plan, governance context, "
                    "policy, task, subject, identity, and optional rewrite lineage"
                )
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
            failure_reason_codes=(exc.reason_code,),
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
        # The column name alone proves nothing: `999 AS subject_count` satisfies it while
        # carrying no governed value. Require the output's semantic lineage to be a pure
        # distinct-count over the very subject the threshold claims to protect.
        count_column_proven = count_column_present and _subject_count_is_governed(
            query_plan,
            subject_count_column=subject_count_column,
            subject_key=subject_key,
        )
        checks.append(
            VerificationCheck(
                name="subject_count_output",
                passed=count_column_proven,
                detail=(
                    f"result contains {subject_count_column!r} proven by lineage to be "
                    f"COUNT(DISTINCT {subject_key.key})"
                    if count_column_proven
                    else (
                        f"result does not contain required {subject_count_column!r} column"
                        if not count_column_present
                        else (
                            f"{subject_count_column!r} is not proven by output lineage to "
                            f"count distinct {subject_key.key}"
                        )
                    )
                ),
            )
        )

        group_sizes_valid = False
        group_detail = "group sizes were not evaluated"
        if count_column_proven and not execution.truncated:
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


def _subject_count_is_governed(
    query_plan: QueryPlan,
    *,
    subject_count_column: str,
    subject_key: ColumnRef,
) -> bool:
    """Return whether the declared subject-count output really counts the subject.

    ``ProjectionExposure`` already records, for every root output, the governed columns that
    produced it and how. A fabricated literal produces no exposure at all, and any expression
    other than a pure ``COUNT(DISTINCT subject)`` produces a different exposure kind, so this
    check cannot be satisfied by a caller-chosen alias.
    """

    target = subject_count_column.lower()
    matches = [
        exposure
        for exposure in query_plan.projected_exposures
        if exposure.output_name.lower() == target
    ]
    if len(matches) != 1:
        return False
    exposure = matches[0]
    return (
        exposure.kind == ProjectionExposureKind.AGGREGATE_VALUE
        and len(exposure.source_columns) == 1
        and exposure.source_columns[0].key == subject_key.key
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
    failure_reason_codes: tuple[ReasonCode, ...] = (),
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
        failure_reason_codes=failure_reason_codes,
    )
