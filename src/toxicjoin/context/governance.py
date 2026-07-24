"""Provider-neutral governance snapshot binding primitives.

Execution-sensitive paths must bind the exact governance snapshot that produced a
resolution to the authorization and receipt. Providers that support snapshot provenance
implement ``resolve_with_governance_binding`` and ``current_governance_binding``;
fixture/replay resolvers remain binding-free.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Protocol

from pydantic import Field, field_validator, model_validator

from toxicjoin.context.models import ContextResolution
from toxicjoin.models import QueryPlan, StrictModel


class GovernanceContextError(RuntimeError):
    """Base class for governance freshness/provenance failures."""


class GovernanceContextStaleError(GovernanceContextError):
    """Raised when the active governance snapshot exceeded its freshness SLA."""


class GovernanceContextDriftError(GovernanceContextError):
    """Raised when one request observes more than one governance snapshot binding."""


class GovernanceContextBinding(StrictModel):
    """Opaque provenance/freshness identity for one governed context snapshot."""

    source: str = Field(min_length=1, max_length=64)
    snapshot_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    catalog_version: str = Field(min_length=1, max_length=256)
    observed_at: datetime
    expires_at: datetime

    @field_validator("observed_at", "expires_at")
    @classmethod
    def timestamps_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("governance binding timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def expiry_follows_observation(self) -> "GovernanceContextBinding":
        if self.expires_at <= self.observed_at:
            raise ValueError("governance binding expires_at must follow observed_at")
        return self

    def assert_fresh(self, now: datetime) -> None:
        if now.tzinfo is None:
            raise ValueError("freshness clock must be timezone-aware")
        if now.astimezone(timezone.utc) >= self.expires_at:
            raise GovernanceContextStaleError(
                "governance snapshot exceeded its freshness SLA"
            )


class GovernanceBindingResolver(Protocol):
    def resolve_with_governance_binding(
        self,
        query_plan: QueryPlan,
    ) -> tuple[ContextResolution, GovernanceContextBinding]: ...

    def current_governance_binding(self) -> GovernanceContextBinding: ...


def resolve_with_governance_binding(
    resolver: Any,
    query_plan: QueryPlan,
) -> tuple[ContextResolution, GovernanceContextBinding | None]:
    """Resolve query governance and provenance atomically when the provider supports it."""

    method = getattr(resolver, "resolve_with_governance_binding", None)
    if callable(method):
        resolution, binding = method(query_plan)
        if not isinstance(resolution, ContextResolution):
            raise GovernanceContextError("resolver returned invalid governed context")
        if not isinstance(binding, GovernanceContextBinding):
            raise GovernanceContextError("resolver returned invalid governance binding")
        return resolution, binding
    return resolver.resolve(query_plan), None


def current_governance_binding(resolver: Any) -> GovernanceContextBinding | None:
    method = getattr(resolver, "current_governance_binding", None)
    if not callable(method):
        return None
    binding = method()
    if not isinstance(binding, GovernanceContextBinding):
        raise GovernanceContextError("resolver returned invalid governance binding")
    return binding


def require_same_governance_binding(
    expected: GovernanceContextBinding | None,
    actual: GovernanceContextBinding | None,
) -> None:
    """Fail closed when a request crosses governance snapshot boundaries."""

    if expected != actual:
        raise GovernanceContextDriftError(
            "governance snapshot changed during the protected operation"
        )
