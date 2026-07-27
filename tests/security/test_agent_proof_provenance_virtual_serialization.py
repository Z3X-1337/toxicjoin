from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from toxicjoin.proofs import (
    AgentPpmcProofBinding,
    PreExecutionPrivacyProof,
    compute_agent_ppmc_proof_binding_sha256,
    compute_agent_ppmc_provenance_hmac,
)
from toxicjoin.proofs.agent_provenance import (
    AgentProofProvenanceError,
    compute_agent_bound_proof_core_sha256,
    require_agent_ppmc_provenance,
)
from toxicjoin.prospective.ppmc import build_ppmc_search_config

NOW = datetime(2026, 7, 27, 8, 0, tzinfo=timezone.utc)
PROVENANCE_KEY = b"agent-provenance-virtual-serialization-key!!"


def _proof() -> PreExecutionPrivacyProof:
    config = build_ppmc_search_config(bound=3, max_states=100)
    return PreExecutionPrivacyProof(
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=5),
        request_identity_sha256="1" * 64,
        task_purpose_sha256="2" * 64,
        purpose_commitment_sha256="3" * 64,
        subject_key_sha256="4" * 64,
        sql_sha256="5" * 64,
        query_plan_sha256="6" * 64,
        governance_context_sha256="7" * 64,
        governance_binding_sha256="8" * 64,
        evidence_root_sha256="9" * 64,
        evidence_validation_sha256="a" * 64,
        disclosure_state_sha256="b" * 64,
        warehouse_snapshot_sha256="c" * 64,
        policy_sha256="d" * 64,
        policy_decision_sha256="e" * 64,
        grammar_sha256="f" * 64,
        ppmc_config_sha256=config.config_sha256,
        ppmc_forbidden_policy_sha256="0" * 64,
        ppmc_governance_binding_sha256="1" * 64,
        ppmc_search_transcript_sha256="2" * 64,
        ppmc_result_sha256="3" * 64,
        ppmc_bound=3,
        ppmc_max_states=100,
        privacy_proof_sha256="4" * 64,
        integrity_hmac_sha256="5" * 64,
    )


def _binding_payload(proof: PreExecutionPrivacyProof) -> dict[str, object]:
    return {
        "agent_proposal_sha256": "6" * 64,
        "agent_evaluation_sha256": "7" * 64,
        "agent_ppmc_evaluation_sha256": "8" * 64,
        "f6_clearance_sha256": "9" * 64,
        "proof_core_sha256": compute_agent_bound_proof_core_sha256(proof),
        "request_identity_sha256": proof.request_identity_sha256,
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
        "ppmc_execution_profile": proof.ppmc_execution_profile,
        "ppmc_config_sha256": proof.ppmc_config_sha256,
        "ppmc_forbidden_policy_sha256": proof.ppmc_forbidden_policy_sha256,
        "ppmc_governance_binding_sha256": proof.ppmc_governance_binding_sha256,
        "ppmc_search_transcript_sha256": proof.ppmc_search_transcript_sha256,
        "ppmc_result_sha256": proof.ppmc_result_sha256,
        "ppmc_status": proof.ppmc_status,
        "ppmc_bound": proof.ppmc_bound,
        "ppmc_max_states": proof.ppmc_max_states,
        "evidence_expires_at": proof.expires_at + timedelta(seconds=5),
    }


def _genuine_binding(proof: PreExecutionPrivacyProof) -> AgentPpmcProofBinding:
    payload = _binding_payload(proof)
    provisional = AgentPpmcProofBinding.model_construct(
        **payload,
        binding_sha256="0" * 64,
        authority_hmac_sha256="0" * 64,
    )
    binding_sha256 = compute_agent_ppmc_proof_binding_sha256(provisional)
    unsigned = AgentPpmcProofBinding.model_construct(
        **payload,
        binding_sha256=binding_sha256,
        authority_hmac_sha256="0" * 64,
    )
    return AgentPpmcProofBinding(
        **payload,
        binding_sha256=binding_sha256,
        authority_hmac_sha256=compute_agent_ppmc_provenance_hmac(
            unsigned,
            integrity_key=PROVENANCE_KEY,
        ),
    )


def test_agent_provenance_rejects_subclass_virtual_serialization_spoof() -> None:
    proof = _proof()
    genuine = _genuine_binding(proof)
    forged_result_sha256 = "a" * 64

    class _SpoofedBinding(AgentPpmcProofBinding):
        def model_dump(self, *args, **kwargs):
            return genuine.model_dump(*args, **kwargs)

    forged_payload = _binding_payload(proof)
    forged_payload["ppmc_result_sha256"] = forged_result_sha256
    attacker_binding = _SpoofedBinding.model_construct(
        **forged_payload,
        binding_sha256=genuine.binding_sha256,
        authority_hmac_sha256=genuine.authority_hmac_sha256,
    )
    forged_proof = proof.model_copy(
        update={
            "ppmc_result_sha256": forged_result_sha256,
            "agent_ppmc_provenance": attacker_binding,
        }
    )

    assert attacker_binding.ppmc_result_sha256 == forged_proof.ppmc_result_sha256
    assert attacker_binding.authority_hmac_sha256 == genuine.authority_hmac_sha256

    with pytest.raises(
        AgentProofProvenanceError,
        match="AUTH_PRIVACY_PROOF_AGENT_PROVENANCE_INVALID",
    ):
        require_agent_ppmc_provenance(
            forged_proof,
            integrity_key=PROVENANCE_KEY,
        )


def test_agent_provenance_rejects_privacy_proof_subclass_virtual_serialization() -> None:
    base = _proof()
    genuine = base.model_copy(update={"agent_ppmc_provenance": _genuine_binding(base)})

    class _SpoofedProof(PreExecutionPrivacyProof):
        def model_dump(self, *args, **kwargs):
            return genuine.model_dump(*args, **kwargs)

    attacker = _SpoofedProof.model_construct(
        **genuine.model_dump(),
    )

    with pytest.raises(
        AgentProofProvenanceError,
        match="AUTH_PRIVACY_PROOF_AGENT_PROVENANCE_INVALID",
    ):
        require_agent_ppmc_provenance(
            attacker,
            integrity_key=PROVENANCE_KEY,
        )
