"""End-to-end ToxicJoin orchestration for analysis and safe execution."""

from __future__ import annotations

from datetime import timedelta
from typing import Protocol

from pydantic import Field

from toxicjoin.context.datahub import DataHubSnapshotContextResolver
from toxicjoin.context.fixture import ContextResolution
from toxicjoin.context.governance import (
    GovernanceContextBinding,
    GovernanceContextDriftError,
    GovernanceContextStaleError,
    require_same_governance_binding,
    resolve_with_governance_binding,
)
from toxicjoin.disclosure import DisclosureLedger
from toxicjoin.execute import DuckDBExecutor
from toxicjoin.models import (
    ColumnContext,
    ColumnRef,
    Decision,
    PolicyDecision,
    QueryPlan,
    ReasonCode,
    SensitivityCategory,
    StrictModel,
)
from toxicjoin.policy import PolicyEngine
from toxicjoin.receipts import (
    DecisionReceipt,
    ReceiptMode,
    ReceiptStore,
    allocate_receipt_id,
    build_receipt,
)
from toxicjoin.rewrite import RewriteError, enforce_minimum_group_size
from toxicjoin.sql import SqlAnalysisError, analyze_sql
from toxicjoin.verify import VerificationResult, verify_and_execute


class ContextResolver(Protocol):
    def resolve(self, query_plan: QueryPlan) -> ContextResolution: ...


class PipelineRequest(StrictModel):
    task_purpose: str = Field(min_length=1, max_length=2000)
    sql: str = Field(min_length=1, max_length=100_000)
    subject_key: ColumnRef
    dialect: str = Field(default="duckdb", pattern=r"^duckdb$")


class PipelineResult(StrictModel):
    original_plan: QueryPlan | None
    initial_decision: PolicyDecision
    safe_sql: str | None = None
    final_plan: QueryPlan | None = None
    final_decision: PolicyDecision | None = None
    verification: VerificationResult | None = None
    governance_binding: GovernanceContextBinding | None = None
    receipt: DecisionReceipt

    @property
    def effective_decision(self) -> Decision:
        return (
            self.final_decision.decision
            if self.final_decision is not None
            else self.initial_decision.decision
        )


class ToxicJoinPipeline:
    """Compose analysis, policy, cumulative privacy, safe execution, and receipts."""

    def __init__(
        self,
        *,
        context_resolver: ContextResolver,
        policy_engine: PolicyEngine,
        receipt_store: ReceiptStore,
        mode: ReceiptMode,
        executor: DuckDBExecutor | None = None,
        disclosure_ledger: DisclosureLedger | None = None,
        stateful_privacy_required: bool | None = None,
        include_sanitized_sql: bool = True,
    ) -> None:
        _validate_runtime_mode(mode, context_resolver)
        if mode == ReceiptMode.LIVE and stateful_privacy_required is False:
            raise ValueError("LIVE mode cannot disable stateful privacy")
        self.context_resolver = context_resolver
        self.policy_engine = policy_engine
        self.receipt_store = receipt_store
        self.mode = mode
        self.executor = executor
        self.stateful_privacy_required = (
            mode == ReceiptMode.LIVE
            if stateful_privacy_required is None
            else bool(stateful_privacy_required)
        )
        self.disclosure_ledger = (
            disclosure_ledger if self.stateful_privacy_required else None
        )
        self.include_sanitized_sql = include_sanitized_sql

    def analyze(self, request: PipelineRequest) -> PipelineResult:
        return self._run(request, execute=False)

    def execute_safe(self, request: PipelineRequest) -> PipelineResult:
        return self._run(request, execute=True)

    def _run(self, request: PipelineRequest, *, execute: bool) -> PipelineResult:
        receipt_id = allocate_receipt_id()
        try:
            original_plan = analyze_sql(request.sql, dialect=request.dialect)
        except SqlAnalysisError as exc:
            context = _empty_context(exc.reason_code)
            initial_decision = _failure_decision(
                reason=exc.reason_code,
                policy_version=self.policy_engine.config.version,
                stage="sql_analysis",
                error_type=type(exc).__name__,
            )
            return self._finalize(
                receipt_id=receipt_id,
                request=request,
                original_plan=None,
                initial_context=context,
                initial_decision=initial_decision,
                include_sanitized_sql=False,
                governance_binding=_receipt_governance_binding(self.context_resolver),
            )

        try:
            initial_context, initial_governance_binding = resolve_with_governance_binding(
                self.context_resolver,
                original_plan,
            )
        except Exception as exc:
            reason = _governance_failure_reason(exc)
            initial_context = _empty_context(reason)
            initial_decision = _failure_decision(
                reason=reason,
                policy_version=self.policy_engine.config.version,
                stage="context_resolution",
                error_type=type(exc).__name__,
            )
            return self._finalize(
                receipt_id=receipt_id,
                request=request,
                original_plan=original_plan,
                initial_context=initial_context,
                initial_decision=initial_decision,
                governance_binding=_receipt_governance_binding(self.context_resolver),
            )

        initial_decision = self.policy_engine.evaluate(
            initial_context.to_policy_input(
                task_purpose=request.task_purpose,
                query_plan=original_plan,
                subject_key=request.subject_key,
            )
        )

        if initial_decision.decision == Decision.BLOCK:
            return self._finalize(
                receipt_id=receipt_id,
                request=request,
                original_plan=original_plan,
                initial_context=initial_context,
                initial_decision=initial_decision,
                governance_binding=initial_governance_binding,
            )

        if initial_decision.decision == Decision.ALLOW:
            return self._handle_allowed(
                receipt_id=receipt_id,
                request=request,
                original_plan=original_plan,
                initial_context=initial_context,
                initial_governance_binding=initial_governance_binding,
                initial_decision=initial_decision,
                execute=execute,
            )

        return self._handle_rewrite(
            receipt_id=receipt_id,
            request=request,
            original_plan=original_plan,
            initial_context=initial_context,
            initial_governance_binding=initial_governance_binding,
            initial_decision=initial_decision,
            execute=execute,
        )

    def _handle_allowed(
        self,
        *,
        receipt_id: str,
        request: PipelineRequest,
        original_plan: QueryPlan,
        initial_context: ContextResolution,
        initial_governance_binding: GovernanceContextBinding | None,
        initial_decision: PolicyDecision,
        execute: bool,
    ) -> PipelineResult:
        if not execute:
            return self._finalize(
                receipt_id=receipt_id,
                request=request,
                original_plan=original_plan,
                initial_context=initial_context,
                initial_decision=initial_decision,
                governance_binding=initial_governance_binding,
            )

        if self.executor is None:
            final_decision = _failure_decision(
                reason=ReasonCode.VERIFICATION_FAILED,
                policy_version=initial_decision.policy_version,
                stage="execution",
                error_type="ExecutorUnavailable",
            )
            return self._finalize(
                receipt_id=receipt_id,
                request=request,
                original_plan=original_plan,
                initial_context=initial_context,
                initial_decision=initial_decision,
                final_decision=final_decision,
                governance_binding=initial_governance_binding,
            )

        verification = verify_and_execute(
            request.sql,
            task_purpose=request.task_purpose,
            subject_key=request.subject_key,
            context_resolver=self.context_resolver,
            policy_engine=self.policy_engine,
            executor=self.executor,
            required_minimum_group_size=self.policy_engine.config.minimum_group_size,
            require_subject_threshold=_requires_subject_threshold(
                original_plan,
                initial_context,
            ),
            dialect=request.dialect,
            disclosure_ledger=self.disclosure_ledger,
            receipt_id=receipt_id,
            require_disclosure_commitment=self.stateful_privacy_required,
            expected_governance_binding=initial_governance_binding,
        )
        final_decision = _verification_outcome(
            verification,
            fallback=initial_decision,
            policy_version=initial_decision.policy_version,
        )
        return self._finalize(
            receipt_id=receipt_id,
            request=request,
            original_plan=original_plan,
            initial_context=initial_context,
            initial_decision=initial_decision,
            final_decision=final_decision,
            verification=verification,
            governance_binding=initial_governance_binding,
        )

    def _handle_rewrite(
        self,
        *,
        receipt_id: str,
        request: PipelineRequest,
        original_plan: QueryPlan,
        initial_context: ContextResolution,
        initial_governance_binding: GovernanceContextBinding | None,
        initial_decision: PolicyDecision,
        execute: bool,
    ) -> PipelineResult:
        try:
            rewrite = enforce_minimum_group_size(
                request.sql,
                subject_key=request.subject_key,
                minimum_group_size=self.policy_engine.config.minimum_group_size,
                dialect=request.dialect,
            )
        except RewriteError as exc:
            final_decision = _failure_decision(
                reason=ReasonCode.REWRITE_FAILED,
                policy_version=initial_decision.policy_version,
                stage="rewrite",
                error_type=type(exc).__name__,
            )
            return self._finalize(
                receipt_id=receipt_id,
                request=request,
                original_plan=original_plan,
                initial_context=initial_context,
                initial_decision=initial_decision,
                final_decision=final_decision,
                governance_binding=initial_governance_binding,
            )

        try:
            final_context, final_governance_binding = resolve_with_governance_binding(
                self.context_resolver,
                rewrite.safe_plan,
            )
            require_same_governance_binding(
                initial_governance_binding,
                final_governance_binding,
            )
        except Exception as exc:
            reason = _governance_failure_reason(exc)
            final_context = _empty_context(reason)
            final_decision = _failure_decision(
                reason=reason,
                policy_version=initial_decision.policy_version,
                stage="rewritten_context_resolution",
                error_type=type(exc).__name__,
            )
            return self._finalize(
                receipt_id=receipt_id,
                request=request,
                original_plan=original_plan,
                initial_context=initial_context,
                initial_decision=initial_decision,
                safe_sql=rewrite.safe_sql,
                final_plan=rewrite.safe_plan,
                final_context=final_context,
                final_decision=final_decision,
                governance_binding=initial_governance_binding,
            )

        final_policy_decision = self.policy_engine.evaluate(
            final_context.to_policy_input(
                task_purpose=request.task_purpose,
                query_plan=rewrite.safe_plan,
                subject_key=request.subject_key,
            )
        )
        if final_policy_decision.decision != Decision.ALLOW or not execute:
            return self._finalize(
                receipt_id=receipt_id,
                request=request,
                original_plan=original_plan,
                initial_context=initial_context,
                initial_decision=initial_decision,
                safe_sql=rewrite.safe_sql,
                final_plan=rewrite.safe_plan,
                final_context=final_context,
                final_decision=final_policy_decision,
                governance_binding=initial_governance_binding,
            )

        if self.executor is None:
            final_decision = _failure_decision(
                reason=ReasonCode.VERIFICATION_FAILED,
                policy_version=initial_decision.policy_version,
                stage="execution",
                error_type="ExecutorUnavailable",
            )
            return self._finalize(
                receipt_id=receipt_id,
                request=request,
                original_plan=original_plan,
                initial_context=initial_context,
                initial_decision=initial_decision,
                safe_sql=rewrite.safe_sql,
                final_plan=rewrite.safe_plan,
                final_context=final_context,
                final_decision=final_decision,
                governance_binding=initial_governance_binding,
            )

        verification = verify_and_execute(
            rewrite.safe_sql,
            task_purpose=request.task_purpose,
            subject_key=request.subject_key,
            context_resolver=self.context_resolver,
            policy_engine=self.policy_engine,
            executor=self.executor,
            required_minimum_group_size=self.policy_engine.config.minimum_group_size,
            require_subject_threshold=True,
            dialect=request.dialect,
            rewrite_parent_sql=request.sql,
            disclosure_ledger=self.disclosure_ledger,
            receipt_id=receipt_id,
            require_disclosure_commitment=self.stateful_privacy_required,
            expected_governance_binding=initial_governance_binding,
        )
        final_decision = _verification_outcome(
            verification,
            fallback=final_policy_decision,
            policy_version=initial_decision.policy_version,
        )
        return self._finalize(
            receipt_id=receipt_id,
            request=request,
            original_plan=original_plan,
            initial_context=initial_context,
            initial_decision=initial_decision,
            safe_sql=rewrite.safe_sql,
            final_plan=rewrite.safe_plan,
            final_context=final_context,
            final_decision=final_decision,
            verification=verification,
            governance_binding=initial_governance_binding,
        )

    def _finalize(
        self,
        *,
        receipt_id: str,
        request: PipelineRequest,
        original_plan: QueryPlan | None,
        initial_context: ContextResolution,
        initial_decision: PolicyDecision,
        safe_sql: str | None = None,
        final_plan: QueryPlan | None = None,
        final_context: ContextResolution | None = None,
        final_decision: PolicyDecision | None = None,
        verification: VerificationResult | None = None,
        include_sanitized_sql: bool | None = None,
        governance_binding: GovernanceContextBinding | None = None,
    ) -> PipelineResult:
        receipt_context = _merge_contexts(initial_context, final_context)
        receipt = build_receipt(
            receipt_id=receipt_id,
            task_purpose=request.task_purpose,
            mode=self.mode,
            original_sql=request.sql,
            safe_sql=safe_sql,
            initial_decision=initial_decision,
            final_decision=final_decision,
            context=receipt_context,
            governance_binding=governance_binding,
            verification=verification,
            include_sanitized_sql=(
                self.include_sanitized_sql
                if include_sanitized_sql is None
                else include_sanitized_sql
            ),
            dialect=request.dialect,
        )
        receipt = self.receipt_store.seal(receipt)
        self.receipt_store.write(receipt)
        return PipelineResult(
            original_plan=original_plan,
            initial_decision=initial_decision,
            safe_sql=safe_sql,
            final_plan=final_plan,
            final_decision=final_decision,
            verification=verification,
            governance_binding=governance_binding,
            receipt=receipt,
        )


def _validate_runtime_mode(mode: ReceiptMode, resolver: ContextResolver) -> None:
    is_live_resolver = isinstance(resolver, DataHubSnapshotContextResolver)
    if mode == ReceiptMode.LIVE and not is_live_resolver:
        raise ValueError("LIVE mode requires a verified DataHub snapshot context resolver")
    if mode in (ReceiptMode.FIXTURE, ReceiptMode.REPLAY) and is_live_resolver:
        raise ValueError(f"{mode.value.upper()} mode cannot use a live DataHub context resolver")


def _empty_context(reason: ReasonCode) -> ContextResolution:
    return ContextResolution(
        projected_context=(),
        all_referenced_context=(),
        failures=(reason,),
    )


def _failure_decision(
    *,
    reason: ReasonCode,
    policy_version: str,
    stage: str,
    error_type: str,
) -> PolicyDecision:
    return PolicyDecision(
        decision=Decision.BLOCK,
        reason_codes=(reason,),
        policy_version=policy_version,
        evidence={
            "stage": stage,
            "error_type": error_type,
            "fail_closed": True,
        },
    )


def _verification_outcome(
    verification: VerificationResult,
    *,
    fallback: PolicyDecision,
    policy_version: str,
) -> PolicyDecision:
    if verification.passed:
        return verification.policy_decision or fallback
    failed_checks = tuple(
        check.name for check in verification.checks if not check.passed
    )
    reason_codes = verification.failure_reason_codes or (ReasonCode.VERIFICATION_FAILED,)
    return PolicyDecision(
        decision=Decision.BLOCK,
        reason_codes=reason_codes,
        policy_version=policy_version,
        evidence={
            "stage": "verification",
            "failed_checks": failed_checks,
            "fail_closed": True,
        },
    )


def _requires_subject_threshold(
    query_plan: QueryPlan,
    context: ContextResolution,
) -> bool:
    return query_plan.is_grouped and any(
        column.category == SensitivityCategory.SENSITIVE_ATTRIBUTE
        for column in context.all_referenced_context
    )


def _merge_contexts(
    first: ContextResolution,
    second: ContextResolution | None,
) -> ContextResolution:
    if second is None:
        return first

    projected: dict[str, ColumnContext] = {
        column.ref.key: column for column in first.projected_context
    }
    referenced: dict[str, ColumnContext] = {
        column.ref.key: column for column in first.all_referenced_context
    }
    for column in second.projected_context:
        projected[column.ref.key] = column
    for column in second.all_referenced_context:
        referenced[column.ref.key] = column

    return ContextResolution(
        projected_context=tuple(projected[key] for key in sorted(projected)),
        all_referenced_context=tuple(referenced[key] for key in sorted(referenced)),
        failures=tuple(dict.fromkeys(first.failures + second.failures)),
    )


def _governance_failure_reason(exc: Exception) -> ReasonCode:
    if isinstance(exc, GovernanceContextStaleError):
        return ReasonCode.DATAHUB_CONTEXT_STALE
    if isinstance(exc, GovernanceContextDriftError):
        return ReasonCode.DATAHUB_CONTEXT_DRIFT
    return ReasonCode.DATAHUB_UNAVAILABLE


def _receipt_governance_binding(
    resolver: ContextResolver,
) -> GovernanceContextBinding | None:
    """Capture provenance for a LIVE failure receipt without asserting freshness.

    A stale snapshot must still be identifiable in the immutable receipt that records why
    the request failed. The normal policy/execution path never uses this helper as authority.
    """

    if not isinstance(resolver, DataHubSnapshotContextResolver):
        return None
    snapshot = resolver.snapshot
    return GovernanceContextBinding(
        source="datahub-mcp",
        snapshot_sha256=snapshot.snapshot_sha256,
        catalog_version=snapshot.catalog.version,
        observed_at=snapshot.observed_at,
        expires_at=snapshot.observed_at + timedelta(seconds=resolver.max_age_seconds),
    )
