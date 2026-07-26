from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from toxicjoin.agent.governance_trust import (
    GovernanceFactRequirement,
    GovernanceTrustBinding,
    compute_governance_trust_binding_sha256,
)
from toxicjoin.evidence import build_evidence_resolution
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.evidence.models import EvidenceTrustState
from toxicjoin.evidence.policy import datahub_governance_evidence_policy


NOW = datetime(2026, 7, 27, 1, 0, tzinfo=timezone.utc)


def test_requirement_and_resolution_scope_matching_is_structural_not_delimited_text() -> None:
    policy = datahub_governance_evidence_policy()
    requirement = GovernanceFactRequirement(
        subject="scope",
        predicate="predicate\x00suffix",
        expected_value="trusted-value",
    )
    resolution = build_evidence_resolution(
        subject="scope\x00predicate",
        predicate="suffix",
        state=EvidenceTrustState.TRUSTED,
        value="trusted-value",
        claim_ids=("evc_" + "1" * 32,),
        policy_version=policy.version,
    )
    payload = {
        "evaluation_sha256": "1" * 64,
        "source_snapshot_sha256": "2" * 64,
        "governance_sha256": "3" * 64,
        "evidence_root_sha256": "4" * 64,
        "source_identity": "datahub-mcp:test-source",
        "evidence_policy": policy,
        "evidence_policy_sha256": canonical_json_sha256(policy.model_dump(mode="json")),
        "requirements": (requirement,),
        "resolutions": (resolution,),
        "issued_at": NOW,
        "evidence_expires_at": NOW + timedelta(seconds=300),
        "governance_trusted": True,
        "evidence_trust_resolved": True,
        "prospective_privacy_checked": False,
        "execution_authorized": False,
    }
    provisional = GovernanceTrustBinding.model_construct(
        **payload,
        binding_sha256="0" * 64,
    )
    candidate = provisional.model_copy(
        update={"binding_sha256": compute_governance_trust_binding_sha256(provisional)}
    )

    with pytest.raises(ValueError, match="resolutions do not match required fact scopes"):
        GovernanceTrustBinding.model_validate(candidate.model_dump(mode="json"))
