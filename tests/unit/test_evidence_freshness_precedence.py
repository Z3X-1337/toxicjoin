from __future__ import annotations

from datetime import datetime, timedelta, timezone

from toxicjoin.evidence import (
    DerivationKind,
    EvidenceSource,
    EvidenceTrustState,
    build_evidence_claim,
    default_evidence_policy,
    resolve_evidence,
)


NOW = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)
SUBJECT = "urn:li:dataset:test#customer_id"
PREDICATE = "sensitivity_category"


def test_stale_incomplete_history_does_not_poison_fresh_authoritative_evidence() -> None:
    stale_incomplete = build_evidence_claim(
        subject=SUBJECT,
        predicate=PREDICATE,
        value="PUBLIC_OR_LOW_RISK",
        source=EvidenceSource.DATAHUB_MCP,
        derivation=DerivationKind.RUNTIME_OBSERVED,
        source_identity="datahub:old-snapshot",
        observed_at=NOW - timedelta(minutes=10),
        expires_at=NOW - timedelta(minutes=1),
        complete=False,
    )
    fresh = build_evidence_claim(
        subject=SUBJECT,
        predicate=PREDICATE,
        value="SENSITIVE_ATTRIBUTE",
        source=EvidenceSource.DATAHUB_MCP,
        derivation=DerivationKind.RUNTIME_OBSERVED,
        source_identity="datahub:current-snapshot",
        observed_at=NOW,
        complete=True,
    )

    resolution = resolve_evidence(
        subject=SUBJECT,
        predicate=PREDICATE,
        claims=(stale_incomplete, fresh),
        policy=default_evidence_policy(),
        now=NOW,
    )

    assert resolution.state == EvidenceTrustState.TRUSTED
    assert resolution.value == "SENSITIVE_ATTRIBUTE"
    assert set(resolution.claim_ids) == {
        stale_incomplete.claim_id,
        fresh.claim_id,
    }
