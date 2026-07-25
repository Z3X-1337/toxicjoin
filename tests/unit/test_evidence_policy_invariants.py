from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from toxicjoin.evidence import (
    DerivationKind,
    EvidencePolicy,
    EvidenceRule,
    EvidenceSource,
    EvidenceTrustState,
    build_evidence_claim,
    default_evidence_policy,
    resolve_evidence,
)


NOW = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)
SUBJECT = "urn:li:dataset:test#customer_id"
PREDICATE = "sensitivity_category"


def test_policy_cannot_trust_agent_source() -> None:
    with pytest.raises(ValidationError, match="cannot establish trusted authority"):
        EvidencePolicy(
            version="test",
            trusted_rules=(
                EvidenceRule(
                    source=EvidenceSource.AGENT,
                    derivation=DerivationKind.RUNTIME_OBSERVED,
                ),
            ),
        )


def test_policy_cannot_trust_agent_asserted_derivation() -> None:
    with pytest.raises(ValidationError, match="cannot establish trusted authority"):
        EvidencePolicy(
            version="test",
            trusted_rules=(
                EvidenceRule(
                    source=EvidenceSource.DATAHUB_MCP,
                    derivation=DerivationKind.AGENT_ASSERTED,
                ),
            ),
        )


def test_policy_cannot_trust_fuzzy_inference() -> None:
    with pytest.raises(ValidationError, match="cannot establish trusted authority"):
        EvidencePolicy(
            version="test",
            trusted_rules=(
                EvidenceRule(
                    source=EvidenceSource.DATAHUB_MCP,
                    derivation=DerivationKind.FUZZY_INFERRED,
                ),
            ),
        )


def test_future_observation_cannot_establish_current_authority() -> None:
    future = build_evidence_claim(
        subject=SUBJECT,
        predicate=PREDICATE,
        value="SENSITIVE_ATTRIBUTE",
        source=EvidenceSource.DATAHUB_MCP,
        derivation=DerivationKind.RUNTIME_OBSERVED,
        source_identity="datahub:future-observation",
        observed_at=NOW + timedelta(minutes=1),
    )

    resolution = resolve_evidence(
        subject=SUBJECT,
        predicate=PREDICATE,
        claims=(future,),
        policy=default_evidence_policy(),
        now=NOW,
    )

    assert resolution.state == EvidenceTrustState.UNKNOWN
    assert resolution.value is None


def test_future_effective_time_cannot_establish_current_authority() -> None:
    future = build_evidence_claim(
        subject=SUBJECT,
        predicate=PREDICATE,
        value="SENSITIVE_ATTRIBUTE",
        source=EvidenceSource.HUMAN_GOVERNANCE,
        derivation=DerivationKind.HUMAN_ASSERTED,
        source_identity="governance:future-rule",
        observed_at=NOW,
        effective_from=NOW + timedelta(minutes=1),
    )

    resolution = resolve_evidence(
        subject=SUBJECT,
        predicate=PREDICATE,
        claims=(future,),
        policy=default_evidence_policy(),
        now=NOW,
    )

    assert resolution.state == EvidenceTrustState.UNKNOWN
    assert resolution.value is None


def test_expired_effective_interval_resolves_stale() -> None:
    historical = build_evidence_claim(
        subject=SUBJECT,
        predicate=PREDICATE,
        value="SENSITIVE_ATTRIBUTE",
        source=EvidenceSource.HUMAN_GOVERNANCE,
        derivation=DerivationKind.HUMAN_ASSERTED,
        source_identity="governance:historical-rule",
        observed_at=NOW - timedelta(minutes=10),
        effective_from=NOW - timedelta(minutes=9),
        effective_until=NOW - timedelta(minutes=1),
    )

    resolution = resolve_evidence(
        subject=SUBJECT,
        predicate=PREDICATE,
        claims=(historical,),
        policy=default_evidence_policy(),
        now=NOW,
    )

    assert resolution.state == EvidenceTrustState.STALE
    assert resolution.value is None
