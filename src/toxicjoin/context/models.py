"""Provider-neutral governed metadata resolution models."""

from __future__ import annotations

from typing import Protocol

from toxicjoin.models import (
    ColumnContext,
    ColumnRef,
    PolicyInput,
    QueryPlan,
    ReasonCode,
    StrictModel,
)


class ContextResolution(StrictModel):
    """Normalized governed context consumed by the deterministic policy engine."""

    projected_context: tuple[ColumnContext, ...]
    all_referenced_context: tuple[ColumnContext, ...]
    failures: tuple[ReasonCode, ...] = ()

    def to_policy_input(
        self,
        *,
        task_purpose: str,
        query_plan: QueryPlan,
        subject_key: ColumnRef | None = None,
        minimum_group_size_present: int | None = None,
    ) -> PolicyInput:
        effective_threshold = (
            minimum_group_size_present
            if minimum_group_size_present is not None
            else query_plan.minimum_group_size_present
        )
        return PolicyInput(
            task_purpose=task_purpose,
            query_plan=query_plan,
            projected_context=self.projected_context,
            all_referenced_context=self.all_referenced_context,
            subject_key=subject_key,
            minimum_group_size_present=effective_threshold,
            upstream_failures=self.failures,
        )


class ContextResolver(Protocol):
    """Synchronous provider contract used by the safety pipeline."""

    def resolve(self, query_plan: QueryPlan) -> ContextResolution: ...
