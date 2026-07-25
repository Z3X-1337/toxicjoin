"""Deterministic evidence-state resolution for one security-relevant fact."""

from __future__ import annotations

from datetime import datetime, timezone

from toxicjoin.evidence.models import (
    DerivationKind,
    EvidenceClaim,
    EvidencePolicy,
    EvidenceResolution,
    EvidenceSource,
    EvidenceTrustState,
    build_evidence_resolution,
)


class EvidenceResolutionError(RuntimeError):
    """Raised when evidence inputs violate the resolver contract."""


def resolve_evidence(
    *,
    subject: str,
    predicate: str,
    claims: tuple[EvidenceClaim, ...],
    policy: EvidencePolicy,
    now: datetime,
) -> EvidenceResolution:
    """Resolve one fact into a deterministic authorization-facing trust state.

    Only source/derivation pairs admitted by ``policy`` can establish authority.
    Non-admissible claims remain committed to the resolution evidence but cannot
    create or contest trusted authority. This prevents Agent/fuzzy assertions from
    raising privilege while preserving their existence for audit and later policy.
    """

    current_time = _utc(now)
    ordered_claims = tuple(sorted(claims, key=lambda claim: claim.claim_id))
    _require_matching_scope(subject, predicate, ordered_claims)
    claim_ids = tuple(claim.claim_id for claim in ordered_claims)

    if not ordered_claims:
        return _result(
            subject=subject,
            predicate=predicate,
            state=EvidenceTrustState.UNKNOWN,
            value=None,
            claim_ids=claim_ids,
            policy=policy,
        )

    admissible = tuple(claim for claim in ordered_claims if policy.trusts(claim))
    if not admissible:
        state = (
            EvidenceTrustState.AGENT_ASSERTED
            if all(_is_agent_claim(claim) for claim in ordered_claims)
            else EvidenceTrustState.UNKNOWN
        )
        return _result(
            subject=subject,
            predicate=predicate,
            state=state,
            value=None,
            claim_ids=claim_ids,
            policy=policy,
        )

    observed = tuple(
        claim for claim in admissible if not claim.is_not_yet_applicable(current_time)
    )
    fresh = tuple(claim for claim in observed if not claim.is_stale(current_time))
    if not fresh:
        state = EvidenceTrustState.STALE if observed else EvidenceTrustState.UNKNOWN
        return _result(
            subject=subject,
            predicate=predicate,
            state=state,
            value=None,
            claim_ids=claim_ids,
            policy=policy,
        )

    if any(not claim.complete for claim in fresh):
        return _result(
            subject=subject,
            predicate=predicate,
            state=EvidenceTrustState.INCOMPLETE,
            value=None,
            claim_ids=claim_ids,
            policy=policy,
        )

    values = tuple(sorted({claim.value for claim in fresh}))
    if len(values) != 1:
        return _result(
            subject=subject,
            predicate=predicate,
            state=EvidenceTrustState.CONTESTED,
            value=None,
            claim_ids=claim_ids,
            policy=policy,
        )

    return _result(
        subject=subject,
        predicate=predicate,
        state=EvidenceTrustState.TRUSTED,
        value=values[0],
        claim_ids=claim_ids,
        policy=policy,
    )


def require_trusted(resolution: EvidenceResolution) -> str:
    """Return the trusted value or fail closed for every other state."""

    if resolution.state != EvidenceTrustState.TRUSTED or resolution.value is None:
        raise EvidenceResolutionError(
            f"evidence is not authorizable: {resolution.state.value}"
        )
    return resolution.value


def _require_matching_scope(
    subject: str,
    predicate: str,
    claims: tuple[EvidenceClaim, ...],
) -> None:
    mismatched = [
        claim.claim_id
        for claim in claims
        if claim.subject != subject or claim.predicate != predicate
    ]
    if mismatched:
        raise EvidenceResolutionError(
            "resolver received claims for a different subject/predicate"
        )


def _is_agent_claim(claim: EvidenceClaim) -> bool:
    return (
        claim.source == EvidenceSource.AGENT
        or claim.derivation == DerivationKind.AGENT_ASSERTED
    )


def _result(
    *,
    subject: str,
    predicate: str,
    state: EvidenceTrustState,
    value: str | None,
    claim_ids: tuple[str, ...],
    policy: EvidencePolicy,
) -> EvidenceResolution:
    return build_evidence_resolution(
        subject=subject,
        predicate=predicate,
        state=state,
        value=value,
        claim_ids=claim_ids,
        policy_version=policy.version,
    )


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("evidence freshness clock must be timezone-aware")
    return value.astimezone(timezone.utc)
