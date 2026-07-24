"""Governance-bound verification wrapper for live execution.

The core verifier remains provider-neutral. This wrapper strengthens providers that expose
``GovernanceContextBinding`` by atomically capturing the context resolution and binding
before verification, pinning that binding for the verification phase, and forcing the
same binding into execution-authorization issuance. Any freshness failure or snapshot
replacement before authorization fails closed without reaching execution.
"""

from __future__ import annotations

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
from toxicjoin.disclosure import DisclosureLedger
from toxicjoin.execute import DuckDBExecutor
from toxicjoin.models import ColumnRef, QueryPlan, ReasonCode
from toxicjoin.policy import PolicyEngine
from toxicjoin.sql import SqlAnalysisError, analyze_sql
from toxicjoin.verify.engine import (
    VerificationCheck,
    VerificationResult,
    verify_and_execute as _verify_and_execute,
)


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
        return _verify_and_execute(
            sql,
            context_resolver=context_resolver,
            executor=executor,
            **common,
        )

    try:
        query_plan = analyze_sql(sql, dialect=dialect)
    except SqlAnalysisError:
        return _verify_and_execute(
            sql,
            context_resolver=context_resolver,
            executor=executor,
            **common,
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
        return _verify_and_execute(
            sql,
            context_resolver=pinned_resolver,
            executor=bound_executor,
            **common,
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
