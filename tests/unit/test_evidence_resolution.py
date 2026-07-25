from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from toxicjoin.evidence import (
    DerivationKind,
    EvidenceClaim,
    EvidenceResolutionError,
    EvidenceSource,
    EvidenceTrustState,
    build_evidence_claim,
    default_evidence_policy,
    require_trusted,
    resolve_evidence,
)


NOW = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)
SUBJECT = "urn:li:dataset:test#customer_id"
PREDICATE = "sensitivity_category"


def _claim(
    value: str,
    *,
    source: EvidenceSource = EvidenceSource.DATAHUB_MCP,
    derivation: DerivationKind = DerivationKind.RUNTIME_OBSERVED,
    observed_at: datetime = NOW,
    expires_at: datetime | None = None,
    complete: bool = True,
) -> EvidenceClaim:
    return build_evidence_claim(
        subject=SUBJECT,
        predicate=PREDICATE,
        value=value,
        source=source,
        derivation=derivation,
        source_identity=f"{source.value.lower()}:test",
        observed_at=observed_at,
        expires_at=expires_at,
        complete=complete,
    )


def _resolve(*claims: EvidenceClaim):
    return resolve_evidence(
        subject=SUBJECT,
        predicate=PREDICATE,
        claims=tuple(claims),
        policy=default_evidence_policy(),
        now=NOW,
    )


def test_no_claims_resolves_unknown() -> None:
    resolution = _resolve()

    assert resolution.state == EvidenceTrustState.UNKNOWN
    assert resolution.value is None
    assert resolution.claim_ids == ()


def test_matching_admissible_claim_resolves_trusted() -> None:
    claim = _claim("STABLE_PSEUDONYM")

    resolution = _resolve(claim)

    assert resolution.state == EvidenceTrustState.TRUSTED
    assert resolution.value == "STABLE_PSEUDONYM"
    assert require_trusted(resolution) == "STABLE_PSEUDONYM"


def test_matching_multiple_authoritative_claims_remain_trusted() -> None:
    datahub = _claim("SENSITIVE_ATTRIBUTE")
    human = _claim(
        "SENSITIVE_ATTRIBUTE",
        source=EvidenceSource.HUMAN_GOVERNANCE,
        derivation=DerivationKind.HUMAN_ASSERTED,
    )

    resolution = _resolve(datahub, human)

    assert resolution.state == EvidenceTrustState.TRUSTED
    assert resolution.value == "SENSITIVE_ATTRIBUTE"
    assert resolution.claim_ids == tuple(sorted((datahub.claim_id, human.claim_id)))


def test_conflicting_authoritative_claims_resolve_contested() -> None:
    datahub = _claim("PUBLIC_OR_LOW_RISK")
    human = _claim(
        "SENSITIVE_ATTRIBUTE",
        source=EvidenceSource.HUMAN_GOVERNANCE,
        derivation=DerivationKind.HUMAN_ASSERTED,
    )

    resolution = _resolve(datahub, human)

    assert resolution.state == EvidenceTrustState.CONTESTED
    assert resolution.value is None
    with pytest.raises(EvidenceResolutionError, match="CONTESTED"):
        require_trusted(resolution)


def test_incomplete_admissible_evidence_fails_closed() -> None:
    complete = _claim("SENSITIVE_ATTRIBUTE")
    incomplete = _claim(
        "SENSITIVE_ATTRIBUTE",
        source=EvidenceSource.HUMAN_GOVERNANCE,
        derivation=DerivationKind.HUMAN_ASSERTED,
        complete=False,
    )

    resolution = _resolve(complete, incomplete)

    assert resolution.state == EvidenceTrustState.INCOMPLETE
    assert resolution.value is None


def test_all_admissible_evidence_stale_resolves_stale() -> None:
    stale = _claim(
        "SENSITIVE_ATTRIBUTE",
        observed_at=NOW - timedelta(minutes=10),
        expires_at=NOW - timedelta(minutes=1),
    )

    resolution = _resolve(stale)

    assert resolution.state == EvidenceTrustState.STALE
    assert resolution.value is None


def test_fresh_authoritative_claim_supersedes_stale_contradiction() -> None:
    stale = _claim(
        "PUBLIC_OR_LOW_RISK",
        observed_at=NOW - timedelta(minutes=10),
        expires_at=NOW - timedelta(minutes=1),
    )
    fresh = _claim("SENSITIVE_ATTRIBUTE")

    resolution = _resolve(stale, fresh)

    assert resolution.state == EvidenceTrustState.TRUSTED
    assert resolution.value == "SENSITIVE_ATTRIBUTE"


def test_agent_only_claim_resolves_agent_asserted() -> None:
    agent = _claim(
        "PUBLIC_OR_LOW_RISK",
        source=EvidenceSource.AGENT,
        derivation=DerivationKind.AGENT_ASSERTED,
    )

    resolution = _resolve(agent)

    assert resolution.state == EvidenceTrustState.AGENT_ASSERTED
    assert resolution.value is None


def test_agent_conflict_cannot_reduce_authoritative_fact_to_agent_choice() -> None:
    trusted = _claim("SENSITIVE_ATTRIBUTE")
    agent = _claim(
        "PUBLIC_OR_LOW_RISK",
        source=EvidenceSource.AGENT,
        derivation=DerivationKind.AGENT_ASSERTED,
    )

    resolution = _resolve(agent, trusted)

    assert resolution.state == EvidenceTrustState.TRUSTED
    assert resolution.value == "SENSITIVE_ATTRIBUTE"
    assert set(resolution.claim_ids) == {agent.claim_id, trusted.claim_id}


def test_fuzzy_inference_cannot_create_authority() -> None:
    fuzzy = _claim(
        "PUBLIC_OR_LOW_RISK",
        source=EvidenceSource.DATAHUB_MCP,
        derivation=DerivationKind.FUZZY_INFERRED,
    )

    resolution = _resolve(fuzzy)

    assert resolution.state == EvidenceTrustState.UNKNOWN
    assert resolution.value is None


def test_resolution_is_order_independent() -> None:
    first = _claim("SENSITIVE_ATTRIBUTE")
    second = _claim(
        "SENSITIVE_ATTRIBUTE",
        source=EvidenceSource.HUMAN_GOVERNANCE,
        derivation=DerivationKind.HUMAN_ASSERTED,
    )

    forward = _resolve(first, second)
    reverse = _resolve(second, first)

    assert forward == reverse
    assert forward.content_sha256 == reverse.content_sha256


def test_claim_hash_tampering_is_rejected() -> None:
    claim = _claim("SENSITIVE_ATTRIBUTE")
    payload = claim.model_dump(mode="json")
    payload["value"] = "PUBLIC_OR_LOW_RISK"

    with pytest.raises(ValidationError, match="content hash mismatch"):
        EvidenceClaim.model_validate(payload)


def test_claim_for_different_fact_is_rejected_by_resolver() -> None:
    claim = build_evidence_claim(
        subject="urn:li:dataset:other#customer_id",
        predicate=PREDICATE,
        value="SENSITIVE_ATTRIBUTE",
        source=EvidenceSource.DATAHUB_MCP,
        derivation=DerivationKind.RUNTIME_OBSERVED,
        source_identity="datahub:test",
        observed_at=NOW,
    )

    with pytest.raises(EvidenceResolutionError, match="different subject/predicate"):
        _resolve(claim)


def test_naive_freshness_clock_is_rejected() -> None:
    claim = _claim("SENSITIVE_ATTRIBUTE")

    with pytest.raises(ValueError, match="timezone-aware"):
        resolve_evidence(
            subject=SUBJECT,
            predicate=PREDICATE,
            claims=(claim,),
            policy=default_evidence_policy(),
            now=datetime(2026, 7, 25, 12, 0),
        )
