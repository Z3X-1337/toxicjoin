"""Governance-bound verification wrapper for live execution.

The core verifier remains provider-neutral. This wrapper strengthens providers that expose
``GovernanceContextBinding`` by atomically capturing the context resolution and binding
before verification, pinning that binding for the verification phase, and forcing the
same binding into execution-authorization issuance. Any freshness failure or snapshot
replacement before authorization fails closed without reaching execution.

This wrapper is also the release boundary for stateful privacy. The disclosure ledger
reserves a PENDING release before execution; only a fully passed verification transitions
that reservation to RELEASED. Every failed or exceptional path transitions it to ABORTED,
so requests that never release rows cannot poison future privacy history.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Any, Protocol

from toxicjoin.context.governance import (
    GovernanceContextBinding,
    GovernanceContextDriftError,
    GovernanceContextStaleError,
    current_governance_binding,
    require_same_governance_binding,
    resolve_with_governance_binding,
)
from toxicjoin.context.models import ContextResolution
from toxicjoin.disclosure import DisclosureCommitment, DisclosureLedger
from toxicjoin.execute import DuckDBExecutor
from toxicjoin.models import ColumnRef, QueryPlan, ReasonCode
from toxicjoin.policy import PolicyEngine
from toxicjoin.sql import SqlAnalysisError, analyze_sql
from toxicjoin.verify.engine import (
    VerificationCheck,
    VerificationResult,
    verify_and_execute as _verify_and_execute,
)


logger = logging.getLogger(__name__)


class ContextResolver(Protocol):
    def resolve(self, query_plan: QueryPlan) -> ContextResolution: ...


class _PinnedGovernanceResolver:
    """Expose exactly one verified snapshot binding for one verifier invocation."""

    def __init__(
        self,
        *,
        resolver: ContextResolver,
        query_plan: QueryPlan,
        resolution: ContextResolution,
        binding: GovernanceContextBinding,
    ) -> None:
        self._resolver = resolver
        self._query_plan = query_plan
        self._resolution = resolution
        self._binding = binding

    @property
    def expected_governance_binding(self) -> GovernanceContextBinding:
        return self._binding

    def resolve(self, query_plan: QueryPlan) -> ContextResolution:
        resolution, _ = self.resolve_with_governance_binding(query_plan)
        return resolution

    def resolve_with_governance_binding(
        self,
        query_plan: QueryPlan,
    ) -> tuple[ContextResolution, GovernanceContextBinding]:
        if query_plan == self._query_plan:
            self._assert_current_binding()
            return self._resolution, self._binding

        resolution, binding = resolve_with_governance_binding(self._resolver, query_plan)
        require_same_governance_binding(self._binding, binding)
        if binding is None:
            raise GovernanceContextDriftError(
                "governance-aware verifier lost snapshot provenance"
            )
        return resolution, binding

    def current_governance_binding(self) -> GovernanceContextBinding:
        binding = self._assert_current_binding()
        if binding is None:
            raise GovernanceContextDriftError(
                "governance-aware verifier lost snapshot provenance"
            )
        return binding

    def _assert_current_binding(self) -> GovernanceContextBinding | None:
        binding = current_governance_binding(self._resolver)
        require_same_governance_binding(self._binding, binding)
        return binding

    def __getattr__(self, name: str) -> Any:
        return getattr(self._resolver, name)


class _GovernanceBoundExecutor:
    """Inject the verifier's captured binding into authorization issuance.

    The underlying DuckDB executor stays bound to the stable application resolver rather
    than this per-request pinning proxy, preserving the existing anti-authority-substitution
    invariant across requests.
    """

    def __init__(
        self,
        *,
        executor: DuckDBExecutor,
        authority_resolver: ContextResolver,
        binding: GovernanceContextBinding,
    ) -> None:
        self._executor = executor
        self._authority_resolver = authority_resolver
        self._binding = binding

    def bind_authority(
        self,
        *,
        context_resolver: Any,
        policy_engine: Any,
        disclosure_ledger: DisclosureLedger | None = None,
        require_disclosure_commitment: bool = False,
    ) -> None:
        del context_resolver
        self._executor.bind_authority(
            context_resolver=self._authority_resolver,
            policy_engine=policy_engine,
            disclosure_ledger=disclosure_ledger,
            require_disclosure_commitment=require_disclosure_commitment,
        )

    def issue_authorization(self, sql: str, **kwargs: Any) -> Any:
        supplied = kwargs.get("expected_governance_binding")
        if supplied is not None and supplied != self._binding:
            raise GovernanceContextDriftError(
                "verifier attempted to substitute a different governance binding"
            )
        kwargs["expected_governance_binding"] = self._binding
        return self._executor.issue_authorization(sql, **kwargs)

    def execute_authorized(self, sql: str, **kwargs: Any) -> Any:
        return self._executor.execute_authorized(sql, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._executor, name)


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
    expected_governance_binding: GovernanceContextBinding | None = None,
) -> VerificationResult:
    """Verify and execute while pinning one live governance snapshot end-to-end."""

    common = {
        "task_purpose": task_purpose,
        "subject_key": subject_key,
        "policy_engine": policy_engine,
        "required_minimum_group_size": required_minimum_group_size,
        "require_subject_threshold": require_subject_threshold,
        "subject_count_column": subject_count_column,
        "forbidden_raw_output_fields": forbidden_raw_output_fields,
        "dialect": dialect,
        "rewrite_parent_sql": rewrite_parent_sql,
        "disclosure_ledger": disclosure_ledger,
        "receipt_id": receipt_id,
        "require_disclosure_commitment": require_disclosure_commitment,
    }

    if not callable(getattr(context_resolver, "resolve_with_governance_binding", None)):
        if expected_governance_binding is not None:
            try:
                query_plan = analyze_sql(sql, dialect=dialect)
            except SqlAnalysisError:
                return _run_core(
                    sql,
                    context_resolver=context_resolver,
                    executor=executor,
                    disclosure_ledger=disclosure_ledger,
                    receipt_id=receipt_id,
                    common=common,
                )
            return _governance_failure(
                query_plan,
                reason=ReasonCode.DATAHUB_CONTEXT_DRIFT,
                detail="expected governance provenance is unavailable from the resolver",
            )
        return _run_core(
            sql,
            context_resolver=context_resolver,
            executor=executor,
            disclosure_ledger=disclosure_ledger,
            receipt_id=receipt_id,
            common=common,
        )

    try:
        query_plan = analyze_sql(sql, dialect=dialect)
    except SqlAnalysisError:
        return _run_core(
            sql,
            context_resolver=context_resolver,
            executor=executor,
            disclosure_ledger=disclosure_ledger,
            receipt_id=receipt_id,
            common=common,
        )

    try:
        resolution, binding = resolve_with_governance_binding(
            context_resolver,
            query_plan,
        )
        if binding is None:
            raise GovernanceContextDriftError(
                "governance-aware resolver returned no provenance binding"
            )
        if expected_governance_binding is not None:
            require_same_governance_binding(expected_governance_binding, binding)
        pinned_resolver = _PinnedGovernanceResolver(
            resolver=context_resolver,
            query_plan=query_plan,
            resolution=resolution,
            binding=binding,
        )
        bound_executor = _GovernanceBoundExecutor(
            executor=executor,
            authority_resolver=context_resolver,
            binding=binding,
        )
        return _run_core(
            sql,
            context_resolver=pinned_resolver,
            executor=bound_executor,
            disclosure_ledger=disclosure_ledger,
            receipt_id=receipt_id,
            common=common,
        )
    except GovernanceContextStaleError as exc:
        return _governance_failure(
            query_plan,
            reason=ReasonCode.DATAHUB_CONTEXT_STALE,
            detail=str(exc),
        )
    except GovernanceContextDriftError as exc:
        return _governance_failure(
            query_plan,
            reason=ReasonCode.DATAHUB_CONTEXT_DRIFT,
            detail=str(exc),
        )


def _run_core(
    sql: str,
    *,
    context_resolver: ContextResolver,
    executor: Any,
    disclosure_ledger: DisclosureLedger | None,
    receipt_id: str | None,
    common: dict[str, Any],
) -> VerificationResult:
    """Run the core verifier and finalize any reserved disclosure state."""

    try:
        result = _verify_and_execute(
            sql,
            context_resolver=context_resolver,
            executor=executor,
            **common,
        )
    except Exception:
        _abort_pending_receipt(disclosure_ledger, receipt_id)
        raise
    result = _sanitize_execution_failure(result)
    return _finalize_release_state(
        result,
        disclosure_ledger=disclosure_ledger,
        receipt_id=receipt_id,
    )


def _finalize_release_state(
    result: VerificationResult,
    *,
    disclosure_ledger: DisclosureLedger | None,
    receipt_id: str | None,
) -> VerificationResult:
    if disclosure_ledger is None or receipt_id is None:
        return result

    commitment = _commitment_for_receipt(disclosure_ledger, receipt_id)
    if commitment is None:
        return result

    try:
        if result.passed and result.execution is not None:
            disclosure_ledger.mark_released(commitment)
        else:
            disclosure_ledger.mark_aborted(commitment)
    except Exception:
        logger.exception("failed to finalize disclosure release state")
        return _disclosure_state_failure(result)
    return result


def _abort_pending_receipt(
    disclosure_ledger: DisclosureLedger | None,
    receipt_id: str | None,
) -> None:
    if disclosure_ledger is None or receipt_id is None:
        return
    commitment = _commitment_for_receipt(disclosure_ledger, receipt_id)
    if commitment is None:
        return
    try:
        disclosure_ledger.mark_aborted(commitment)
    except Exception:
        logger.exception("failed to abort disclosure reservation after verifier exception")


def _commitment_for_receipt(
    disclosure_ledger: DisclosureLedger,
    receipt_id: str,
) -> DisclosureCommitment | None:
    try:
        record = disclosure_ledger.read_receipt(receipt_id)
    except KeyError:
        return None
    return DisclosureCommitment(
        record_id=record.record_id,
        receipt_id=record.event.receipt_id,
        scope_sha256=record.event.scope.scope_sha256,
        event_sha256=record.event_sha256,
        content_sha256=record.content_sha256,
    )


def _sanitize_execution_failure(result: VerificationResult) -> VerificationResult:
    """Keep engine/database exception text server-side and expose stable codes only."""

    failed_execution_checks = {
        check.name
        for check in result.checks
        if not check.passed and check.name in {"execution", "execution_authorization"}
    }
    if not failed_execution_checks and result.execution_error is None:
        return result

    if result.execution_error is not None:
        logger.warning("protected execution failure: %s", result.execution_error)

    code = (
        result.failure_reason_codes[0].value
        if result.failure_reason_codes
        else ReasonCode.VERIFICATION_FAILED.value
    )
    public_detail = f"{code}: protected execution failed"
    checks = tuple(
        check.model_copy(update={"detail": public_detail})
        if check.name in failed_execution_checks
        else check
        for check in result.checks
    )
    return result.model_copy(
        update={
            "checks": checks,
            "execution_error": public_detail if result.execution_error is not None else None,
        }
    )


def _disclosure_state_failure(result: VerificationResult) -> VerificationResult:
    detail = "DISCLOSURE_STATE_UNAVAILABLE: release state could not be finalized safely"
    checks = tuple(result.checks) + (
        VerificationCheck(
            name="disclosure_release_state",
            passed=False,
            detail=detail,
        ),
    )
    reasons = tuple(
        dict.fromkeys(
            result.failure_reason_codes + (ReasonCode.DISCLOSURE_STATE_UNAVAILABLE,)
        )
    )
    return VerificationResult(
        passed=False,
        query_plan=result.query_plan,
        policy_decision=result.policy_decision,
        checks=checks,
        execution=None,
        execution_attempted=result.execution_attempted,
        execution_quarantined=result.execution_attempted,
        execution_error=detail,
        failure_reason_codes=reasons,
    )


def _governance_failure(
    query_plan: QueryPlan,
    *,
    reason: ReasonCode,
    detail: str,
) -> VerificationResult:
    return VerificationResult(
        passed=False,
        query_plan=query_plan,
        policy_decision=None,
        checks=(
            VerificationCheck(
                name="governance_binding",
                passed=False,
                detail=detail,
            ),
        ),
        execution=None,
        execution_attempted=False,
        execution_quarantined=False,
        execution_error=detail,
        failure_reason_codes=(reason,),
    )
