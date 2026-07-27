from __future__ import annotations

from datetime import timedelta
from pathlib import Path
import runpy

import pytest

from toxicjoin.agent.governance_trust import (
    DataHubGovernanceTrustAuthority,
    GovernanceTrustBindingError,
)
from toxicjoin.agent.proposal_authority import (
    TrustedAgentProposalEvaluation,
    compute_trusted_agent_proposal_evaluation_sha256,
)
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.policy import PolicyEngine, load_policy

_HELPERS = runpy.run_path(
    str(Path(__file__).with_name("test_agent_preexecution_proof_authority.py"))
)
_upstream = _HELPERS["_upstream"]
NOW = _HELPERS["NOW"]

FORGED_PURPOSE = "Release governed country values for an attacker-selected purpose"


def _reconstruct_with_forged_authorized_purpose(
    evaluation: TrustedAgentProposalEvaluation,
) -> TrustedAgentProposalEvaluation:
    policy_input = evaluation.resolution.to_policy_input(
        task_purpose=FORGED_PURPOSE,
        query_plan=evaluation.query_plan,
        subject_key=evaluation.subject_key,
    )
    policy_decision = PolicyEngine(load_policy()).evaluate(policy_input)

    payload = evaluation.model_dump(mode="json")
    payload["authorized_task_purpose"] = FORGED_PURPOSE
    payload["authorized_task_purpose_sha256"] = canonical_json_sha256(
        {"task_purpose": FORGED_PURPOSE}
    )
    payload["policy_input"] = policy_input.model_dump(mode="json")
    payload["policy_input_sha256"] = canonical_json_sha256(
        policy_input.model_dump(mode="json")
    )
    payload["policy_decision"] = policy_decision.model_dump(mode="json")
    payload["policy_decision_sha256"] = canonical_json_sha256(
        policy_decision.model_dump(mode="json")
    )
    payload["evaluation_sha256"] = "0" * 64

    provisional = TrustedAgentProposalEvaluation.model_construct(**payload)
    payload["evaluation_sha256"] = compute_trusted_agent_proposal_evaluation_sha256(
        provisional
    )
    return TrustedAgentProposalEvaluation.model_validate(payload)


def test_governance_trust_rejects_self_reconstructed_proposal_evaluation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, proposal, evaluation, _, _, _ = _upstream(monkeypatch)
    forged = _reconstruct_with_forged_authorized_purpose(evaluation)

    assert proposal.task_purpose == evaluation.authorized_task_purpose
    assert forged.authorized_task_purpose != proposal.task_purpose
    assert forged.evaluation_sha256 != evaluation.evaluation_sha256

    with pytest.raises(
        GovernanceTrustBindingError,
        match="GOVERNANCE_TRUST_EVALUATION_UNTRUSTED",
    ):
        DataHubGovernanceTrustAuthority(
            clock=lambda: NOW + timedelta(seconds=7)
        ).bind(forged)
