from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from toxicjoin.proofs import (
    AgentPpmcProofBinding,
    PreExecutionPrivacyProof,
    compute_agent_ppmc_proof_binding_sha256,
    compute_agent_ppmc_provenance_hmac,
    compute_preexecution_privacy_proof_hmac,
    compute_preexecution_privacy_proof_sha256,
    verify_preexecution_privacy_proof,
)
from toxicjoin.proofs.agent_provenance import (
    AgentProofProvenanceError,
    compute_agent_bound_proof_core_sha256,
    require_agent_ppmc_provenance,
)
from toxicjoin.prospective.ppmc import build_ppmc_search_config

PROOF_KEY = b"ppmc-metadata-proof-key-distinct-32-bytes!!"
PROVENANCE_KEY = b"ppmc-metadata-provenance-key-distinct-32!!"
NOW = datetime(2026, 7, 27, 2, 30, tzinfo=timezone.utc)
HASH = "d" * 64


def _binding_payload(proof: PreExecutionPrivacyProof) -> dict:
    return {
        "agent_proposal_sha256": "1" * 64,
        "agent_evaluation_sha256": "2" * 64,
        "agent_ppmc_evaluation_sha256": "3" * 64,
        "f6_clearance_sha256": "4" * 64,
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
        "evidence_expires_at": proof.expires_at + timedelta(seconds=20),
    }


def _seal_with_agent_provenance() -> PreExecutionPrivacyProof:
    config = build_ppmc_search_config(bound=3, max_states=100)
    proof = PreExecutionPrivacyProof(
        issued_at=NOW - timedelta(seconds=1),
        expires_at=NOW + timedelta(seconds=4),
        request_identity_sha256=HASH,
        task_purpose_sha256=HASH,
        purpose_commitment_sha256=HASH,
        subject_key_sha256=HASH,
        sql_sha256=HASH,
        query_plan_sha256=HASH,
        governance_context_sha256=HASH,
        governance_binding_sha256=HASH,
        evidence_root_sha256=HASH,
        evidence_validation_sha256=HASH,
        disclosure_state_sha256=HASH,
        warehouse_snapshot_sha256=HASH,
        policy_sha256=HASH,
        policy_decision_sha256=HASH,
        grammar_sha256=HASH,
        ppmc_config_sha256=config.config_sha256,
        ppmc_forbidden_policy_sha256=HASH,
        ppmc_governance_binding_sha256=HASH,
        ppmc_search_transcript_sha256=HASH,
        ppmc_result_sha256=HASH,
        ppmc_bound=3,
        ppmc_max_states=100,
        privacy_proof_sha256="0" * 64,
        integrity_hmac_sha256="0" * 64,
    )
    payload = _binding_payload(proof)
    provisional = AgentPpmcProofBinding.model_construct(
        **payload,
        binding_sha256="0" * 64,
        authority_hmac_sha256="0" * 64,
    )
    binding_sha256 = compute_agent_ppmc_proof_binding_sha256(provisional)
    unsigned_binding = AgentPpmcProofBinding.model_construct(
        **payload,
        binding_sha256=binding_sha256,
        authority_hmac_sha256="0" * 64,
    )
    provenance = AgentPpmcProofBinding(
        **payload,
        binding_sha256=binding_sha256,
        authority_hmac_sha256=compute_agent_ppmc_provenance_hmac(
            unsigned_binding,
            integrity_key=PROVENANCE_KEY,
        ),
    )
    unsigned = proof.model_copy(
        update={
            "agent_ppmc_provenance": provenance,
            "privacy_proof_sha256": "0" * 64,
            "integrity_hmac_sha256": "0" * 64,
        }
    )
    committed = unsigned.model_copy(
        update={"privacy_proof_sha256": compute_preexecution_privacy_proof_sha256(unsigned)}
    )
    return committed.model_copy(
        update={
            "integrity_hmac_sha256": compute_preexecution_privacy_proof_hmac(
                committed,
                integrity_key=PROOF_KEY,
            )
        }
    )


def _reseal_outer_proof(
    proof: PreExecutionPrivacyProof,
    **updates,
) -> PreExecutionPrivacyProof:
    unsigned = proof.model_copy(
        update={
            **updates,
            "privacy_proof_sha256": "0" * 64,
            "integrity_hmac_sha256": "0" * 64,
        }
    )
    committed = unsigned.model_copy(
        update={"privacy_proof_sha256": compute_preexecution_privacy_proof_sha256(unsigned)}
    )
    return committed.model_copy(
        update={
            "integrity_hmac_sha256": compute_preexecution_privacy_proof_hmac(
                committed,
                integrity_key=PROOF_KEY,
            )
        }
    )


def test_proof_key_cannot_rebind_genuine_agent_result_to_different_approved_ppmc_budget() -> None:
    genuine = _seal_with_agent_provenance()
    alternate_config = build_ppmc_search_config(bound=3, max_states=128)
    forged = _reseal_outer_proof(
        genuine,
        ppmc_max_states=128,
        ppmc_config_sha256=alternate_config.config_sha256,
    )

    generic_verification = verify_preexecution_privacy_proof(
        forged,
        integrity_key=PROOF_KEY,
        now=NOW,
    )
    assert generic_verification.valid is True

    with pytest.raises(
        AgentProofProvenanceError,
        match="AUTH_PRIVACY_PROOF_AGENT_PROVENANCE_INVALID",
    ):
        require_agent_ppmc_provenance(
            forged,
            integrity_key=PROVENANCE_KEY,
        )


def test_proof_key_cannot_extend_genuine_agent_proof_lifetime() -> None:
    genuine = _seal_with_agent_provenance()
    forged = _reseal_outer_proof(
        genuine,
        expires_at=genuine.expires_at + timedelta(seconds=5),
    )

    generic_verification = verify_preexecution_privacy_proof(
        forged,
        integrity_key=PROOF_KEY,
        now=NOW,
    )
    assert generic_verification.valid is True

    with pytest.raises(
        AgentProofProvenanceError,
        match="AUTH_PRIVACY_PROOF_AGENT_PROVENANCE_INVALID",
    ):
        require_agent_ppmc_provenance(
            forged,
            integrity_key=PROVENANCE_KEY,
        )
