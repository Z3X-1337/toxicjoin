"""End-to-end ToxicJoin orchestration for analysis and safe execution."""

from __future__ import annotations

from typing import Protocol

from pydantic import Field

from toxicjoin.context.fixture import ContextResolution
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
    receipt: DecisionReceipt

    @property
    def effective_decision(self) -> Decision:
        return (
            self.final_decision.decision
            if self.final_decision is not None
            else self.initial_decision.decision
        )


class ToxicJoinPipeline:
    """Compose analysis, policy, rewrite, execution, verification, and receipts."""

    def __init__(
        self,
        *,
        context_resolver: ContextResolver,
        policy_engine: PolicyEngine,
        receipt_store: ReceiptStore,
        mode: ReceiptMode,
        executor: DuckDBExecutor | None = None,
        include_sanitized_sql: bool = True,
    ) -> None:
        self.context_resolver = context_resolver
        self.policy_engine = policy_engine
        self.receipt_store = receipt_store
        self.mode = mode
        self.executor = executor
        self.include_sanitized_sql = include_sanitized_sql

    def analyze(self, request: PipelineRequest) -> PipelineResult:
        return self._run(request, execute=False)

    def execute_safe(self, request: PipelineRequest) -> PipelineResult:
        return self._run(request, execute=True)

    def _run(self, request: PipelineRequest, *, execute: bool) -> PipelineResult:
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
                request=request,
                original_plan=None,
                initial_context=context,
                initial_decision=initial_decision,
                include_sanitized_sql=False,
            )

        try:
            initial_context = self.context_resolver.resolve(original_plan)
        except Exception as exc:
            initial_context = _empty_context(ReasonCode.DATAHUB_UNAVAILABLE)
            initial_decision = _failure_decision(
                reason=ReasonCode.DATAHUB_UNAVAILABLE,
                policy_version=self.policy_engine.config.version,
                stage="context_resolution",
                error_type=type(exc).__name__,
            )
            return self._finalize(
                request=request,
                original_plan=original_plan,
                initial_context=initial_context,
                initial_decision=initial_decision,
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
                request=request,
                original_plan=original_plan,
                initial_context=initial_context,
                initial_decision=initial_decision,
            )

        if initial_decision.decision == Decision.ALLOW:
            return self._handle_allowed(
                request=request,
                original_plan=original_plan,
                initial_context=initial_context,
                initial_decision=initial_decision,
                execute=execute,
            )

        return self._handle_rewrite(
            request=request,
            original_plan=original_plan,
            initial_context=initial_context,
            initial_decision=initial_decision,
            execute=execute,
        )

    def _handle_allowed(
        self,
        *,
        request: PipelineRequest,
        original_plan: QueryPlan,
        initial_context: ContextResolution,
        initial_decision: PolicyDecision,
        execute: bool,
    ) -> PipelineResult:
        if not execute:
            return self._finalize(
                request=request,
                original_plan=original_plan,
                initial_context=initial_context,
                initial_decision=initial_decision,
            )

        if self.executor is None:
            final_decision = _failure_decision(
                reason=ReasonCode.VERIFICATION_FAILED,
                policy_version=initial_decision.policy_version,
                stage="execution",
                error_type="ExecutorUnavailable",
            )
            return self._finalize(
                request=request,
                original_plan=original_plan,
                initial_context=initial_context,
                initial_decision=initial_decision,
                final_decision=final_decision,
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
        )
        final_decision = _verification_outcome(
            verification,
            fallback=initial_decision,
            policy_version=initial_decision.policy_version,
        )
        return self._finalize(
            request=request,
            original_plan=original_plan,
            initial_context=initial_context,
            initial_decision=initial_decision,
            final_decision=final_decision,
            verification=verification,
        )

    def _handle_rewrite(
        self,
        *,
        request: PipelineRequest,
        original_plan: QueryPlan,
        initial_context: ContextResolution,
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
                request=request,
                original_plan=original_plan,
                initial_context=initial_context,
                initial_decision=initial_decision,
                final_decision=final_decision,
            )

        try:
            final_context = self.context_resolver.resolve(rewrite.safe_plan)
        except Exception as exc:
            final_context = _empty_context(ReasonCode.DATAHUB_UNAVAILABLE)
            final_decision = _failure_decision(
                reason=ReasonCode.DATAHUB_UNAVAILABLE,
                policy_version=initial_decision.policy_version,
                stage="rewritten_context_resolution",
                error_type=type(exc).__name__,
            )
            return self._finalize(
                request=request,
                original_plan=original_plan,
                initial_context=initial_context,
                initial_decision=initial_decision,
                safe_sql=rewrite.safe_sql,
                final_plan=rewrite.safe_plan,
                final_context=final_context,
                final_decision=final_decision,
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
                request=request,
                original_plan=original_plan,
                initial_context=initial_context,
                initial_decision=initial_decision,
                safe_sql=rewrite.safe_sql,
                final_plan=rewrite.safe_plan,
                final_context=final_context,
                final_decision=final_policy_decision,
            )

        if self.executor is None:
            final_decision = _failure_decision(
                reason=ReasonCode.VERIFICATION_FAILED,
                policy_version=initial_decision.policy_version,
                stage="execution",
                error_type="ExecutorUnavailable",
            )
            return self._finalize(
                request=request,
                original_plan=original_plan,
                initial_context=initial_context,
                initial_decision=initial_decision,
                safe_sql=rewrite.safe_sql,
                final_plan=rewrite.safe_plan,
                final_context=final_context,
                final_decision=final_decision,
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
        )
        final_decision = _verification_outcome(
            verification,
            fallback=final_policy_decision,
            policy_version=initial_decision.policy_version,
        )
        return self._finalize(
            request=request,
            original_plan=original_plan,
            initial_context=initial_context,
            initial_decision=initial_decision,
            safe_sql=rewrite.safe_sql,
            final_plan=rewrite.safe_plan,
            final_context=final_context,
            final_decision=final_decision,
            verification=verification,
        )

    def _finalize(
        self,
        *,
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
    ) -> PipelineResult:
        receipt_context = _merge_contexts(initial_context, final_context)
        receipt = build_receipt(
            task_purpose=request.task_purpose,
            mode=self.mode,
            original_sql=request.sql,
            safe_sql=safe_sql,
            initial_decision=initial_decision,
            final_decision=final_decision,
            context=receipt_context,
            verification=verification,
            include_sanitized_sql=(
                self.include_sanitized_sql
                if include_sanitized_sql is None
                else include_sanitized_sql
            ),
            dialect=request.dialect,
        )
        self.receipt_store.write(receipt)
        return PipelineResult(
            original_plan=original_plan,
            initial_decision=initial_decision,
            safe_sql=safe_sql,
            final_plan=final_plan,
            final_decision=final_decision,
            verification=verification,
            receipt=receipt,
        )


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
    return PolicyDecision(
        decision=Decision.BLOCK,
        reason_codes=(ReasonCode.VERIFICATION_FAILED,),
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
