"""Independent alignment checks for Governed-Agent PPMC proof provenance."""

from __future__ import annotations

import hmac

from toxicjoin.proofs.models import (
    AgentPpmcProofBinding,
    PreExecutionPrivacyProof,
    compute_agent_ppmc_proof_binding_sha256,
)


class AgentProofProvenanceError(RuntimeError):
    """Stable fail-closed error for proof-bound Agent provenance checks."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def require_agent_ppmc_provenance(
    proof: PreExecutionPrivacyProof,
) -> AgentPpmcProofBinding:
    """Require one internally consistent Agent PPMC provenance binding for ``proof``.

    This function intentionally does not verify the proof HMAC itself.  The strict execution
    authorizer first authenticates the enclosing proof through the ordinary proof verifier, then
    calls this function to ensure the authenticated Agent provenance cannot be rebound to different
    SQL, governance, policy, state, grammar, or PPMC artifacts.
    """

    binding = proof.agent_ppmc_provenance
    if binding is None:
        raise AgentProofProvenanceError(
            "AUTH_PRIVACY_PROOF_AGENT_PROVENANCE_REQUIRED"
        )

    expected_binding_sha256 = compute_agent_ppmc_proof_binding_sha256(binding)
    if not hmac.compare_digest(expected_binding_sha256, binding.binding_sha256):
        raise AgentProofProvenanceError(
            "AUTH_PRIVACY_PROOF_AGENT_PROVENANCE_INVALID"
        )

    expected = {
        "sql_sha256": proof.sql_sha256,
        "query_plan_sha256": proof.query_plan_sha256,
        "task_purpose_sha256": proof.task_purpose_sha256,
        "purpose_commitment_sha256": proof.purpose_commitment_sha256,
        "subject_key_sha256": proof.subject_key_sha256,
        "governance_context_sha256": proof.governance_context_sha256,
        "governance_binding_sha256": proof.governance_binding_sha256,
        "evidence_root_sha256": proof.evidence_root_sha256,
        "evidence_validation_sha256": proof.evidence_validation_sha256,
        "policy_sha256": proof.policy_sha256,
        "policy_decision_sha256": proof.policy_decision_sha256,
        "disclosure_state_sha256": proof.disclosure_state_sha256,
        "grammar_sha256": proof.grammar_sha256,
        "ppmc_governance_binding_sha256": proof.ppmc_governance_binding_sha256,
        "ppmc_result_sha256": proof.ppmc_result_sha256,
    }
    for field_name, expected_value in expected.items():
        if not hmac.compare_digest(getattr(binding, field_name), expected_value):
            raise AgentProofProvenanceError(
                "AUTH_PRIVACY_PROOF_AGENT_PROVENANCE_INVALID"
            )

    if proof.issued_at >= binding.evidence_expires_at:
        raise AgentProofProvenanceError(
            "AUTH_PRIVACY_PROOF_AGENT_PROVENANCE_INVALID"
        )
    if proof.expires_at > binding.evidence_expires_at:
        raise AgentProofProvenanceError(
            "AUTH_PRIVACY_PROOF_AGENT_PROVENANCE_INVALID"
        )
    return binding
