from __future__ import annotations

import inspect
from datetime import datetime, timedelta, timezone

import pytest

from toxicjoin.agent.proof_handoff import (
    AgentProofHandoffAuthorityError,
    DataHubAgentProofHandoffAuthority,
)
from toxicjoin.proofs.agent_handoff import (
    AgentPreExecutionProofCapsule,
    AgentPreExecutionProofCapsuleError,
    compute_agent_preexecution_proof_capsule_hmac,
    compute_agent_preexecution_proof_capsule_sha256,
    require_agent_preexecution_proof_capsule,
    seal_agent_preexecution_proof_capsule,
)
from toxicjoin.proofs.agent_provenance import (
    compute_agent_bound_proof_core_sha256,
    compute_agent_ppmc_provenance_hmac,
)
from toxicjoin.proofs.models import (
    AgentPpmcProofBinding,
    PreExecutionPrivacyProof,
    compute_agent_ppmc_proof_binding_sha256,
)
from toxicjoin.proofs.preexec import compute_preexecution_privacy_proof_sha256

NOW = datetime(2026, 7, 27, 14, 0, tzinfo=timezone.utc)
PROVENANCE_KEY = b"phase-6-agent-provenance-handoff-key-32-bytes!!"
PROOF_KEY = b"phase-6-proof-integrity-key-distinct-32-bytes!!"


def _hash(char: str) -> str:
    return char * 64


class _ExplosiveAgentPpmcProofBinding(AgentPpmcProofBinding):
    def model_dump(self, *args, **kwargs):
        raise AssertionError("virtual serialization reached")


def _proof(*, identity_char: str = "1", trusted_provenance: bool = True) -> PreExecutionPrivacyProof:
    base = PreExecutionPrivacyProof.model_construct(
        schema_version="1.0",
        proof_version="0.1.0",
        proof_kind="PRE_EXECUTION_PRIVACY_PROOF",
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
        request_identity_sha256=_hash(identity_char),
        task_purpose_sha256=_hash("2"),
        purpose_commitment_sha256=_hash("3"),
        subject_key_sha256=_hash("4"),
        sql_sha256=_hash("5"),
        query_plan_sha256=_hash("6"),
        governance_context_sha256=_hash("7"),
        governance_binding_sha256=_hash("8"),
        evidence_root_sha256=_hash("9"),
        evidence_validation_sha256=_hash("a"),
        disclosure_state_sha256=_hash("b"),
        warehouse_snapshot_sha256=_hash("c"),
        policy_sha256=_hash("d"),
        policy_decision_sha256=_hash("e"),
        grammar_sha256=_hash("f"),
        ppmc_execution_profile="p0-preexec-v1",
        ppmc_config_sha256=_hash("0"),
        ppmc_forbidden_policy_sha256=_hash("1"),
        ppmc_governance_binding_sha256=_hash("2"),
        ppmc_search_transcript_sha256=_hash("3"),
        ppmc_result_sha256=_hash("4"),
        ppmc_status="NO_COUNTEREXAMPLE_WITHIN_BOUND",
        ppmc_bound=3,
        ppmc_max_states=128,
        agent_ppmc_provenance=None,
        repair=None,
        privacy_proof_sha256="0" * 64,
        integrity_hmac_sha256=_hash("a"),
    )
    payload = {
        "agent_proposal_sha256": _hash("5"),
        "agent_evaluation_sha256": _hash("6"),
        "agent_ppmc_evaluation_sha256": _hash("7"),
        "f6_clearance_sha256": _hash("8"),
        "proof_core_sha256": compute_agent_bound_proof_core_sha256(base),
        "request_identity_sha256": base.request_identity_sha256,
        "sql_sha256": base.sql_sha256,
        "query_plan_sha256": base.query_plan_sha256,
        "task_purpose_sha256": base.task_purpose_sha256,
        "purpose_commitment_sha256": base.purpose_commitment_sha256,
        "subject_key_sha256": base.subject_key_sha256,
        "governance_context_sha256": base.governance_context_sha256,
        "governance_binding_sha256": base.governance_binding_sha256,
        "evidence_root_sha256": base.evidence_root_sha256,
        "evidence_validation_sha256": base.evidence_validation_sha256,
        "policy_sha256": base.policy_sha256,
        "policy_decision_sha256": base.policy_decision_sha256,
        "disclosure_state_sha256": base.disclosure_state_sha256,
        "grammar_sha256": base.grammar_sha256,
        "ppmc_execution_profile": base.ppmc_execution_profile,
        "ppmc_config_sha256": base.ppmc_config_sha256,
        "ppmc_forbidden_policy_sha256": base.ppmc_forbidden_policy_sha256,
        "ppmc_governance_binding_sha256": base.ppmc_governance_binding_sha256,
        "ppmc_search_transcript_sha256": base.ppmc_search_transcript_sha256,
        "ppmc_result_sha256": base.ppmc_result_sha256,
        "ppmc_status": base.ppmc_status,
        "ppmc_bound": base.ppmc_bound,
        "ppmc_max_states": base.ppmc_max_states,
        "evidence_expires_at": NOW + timedelta(seconds=40),
    }
    provisional = AgentPpmcProofBinding.model_construct(
        **payload,
        binding_sha256="0" * 64,
        authority_hmac_sha256="0" * 64,
    )
    binding_sha256 = compute_agent_ppmc_proof_binding_sha256(provisional)
    unsigned_provenance = AgentPpmcProofBinding.model_construct(
        **payload,
        binding_sha256=binding_sha256,
        authority_hmac_sha256="0" * 64,
    )
    provenance_hmac = (
        compute_agent_ppmc_provenance_hmac(
            unsigned_provenance,
            integrity_key=PROVENANCE_KEY,
        )
        if trusted_provenance
        else "0" * 64
    )
    provenance = AgentPpmcProofBinding(
        **payload,
        binding_sha256=binding_sha256,
        authority_hmac_sha256=provenance_hmac,
    )
    unsigned = base.model_copy(
        update={
            "agent_ppmc_provenance": provenance,
            "privacy_proof_sha256": "0" * 64,
            "integrity_hmac_sha256": _hash("a"),
        }
    )
    return unsigned.model_copy(
        update={"privacy_proof_sha256": compute_preexecution_privacy_proof_sha256(unsigned)}
    )


def _poison_provenance_virtual_serialization(
    proof: PreExecutionPrivacyProof,
) -> PreExecutionPrivacyProof:
    provenance = proof.agent_ppmc_provenance
    assert provenance is not None
    explosive = _ExplosiveAgentPpmcProofBinding.model_construct(**provenance.__dict__)
    return proof.model_copy(update={"agent_ppmc_provenance": explosive})


def _manually_sealed_capsule(proof: PreExecutionPrivacyProof) -> AgentPreExecutionProofCapsule:
    provenance = proof.agent_ppmc_provenance
    assert provenance is not None
    provisional = AgentPreExecutionProofCapsule(
        proof=proof,
        proof_sha256=proof.privacy_proof_sha256,
        agent_provenance_binding_sha256=provenance.binding_sha256,
        request_identity_sha256=proof.request_identity_sha256,
        issued_at=proof.issued_at,
        expires_at=proof.expires_at,
        capsule_sha256="0" * 64,
        authority_hmac_sha256="0" * 64,
    )
    unsigned = provisional.model_copy(
        update={
            "capsule_sha256": compute_agent_preexecution_proof_capsule_sha256(provisional)
        }
    )
    return unsigned.model_copy(
        update={
            "authority_hmac_sha256": compute_agent_preexecution_proof_capsule_hmac(
                unsigned,
                integrity_key=PROVENANCE_KEY,
            )
        }
    )


def test_capsule_authenticates_exact_proof_handoff_without_proof_hmac_key() -> None:
    proof = _proof()
    capsule = seal_agent_preexecution_proof_capsule(
        proof,
        integrity_key=PROVENANCE_KEY,
    )

    assert capsule.proof_sha256 == proof.privacy_proof_sha256
    assert capsule.request_identity_sha256 == proof.request_identity_sha256
    assert require_agent_preexecution_proof_capsule(
        capsule,
        integrity_key=PROVENANCE_KEY,
    ) is proof


def test_capsule_rejects_swapped_independently_valid_agent_proof() -> None:
    first = _proof(identity_char="1")
    second = _proof(identity_char="9")
    capsule = seal_agent_preexecution_proof_capsule(
        first,
        integrity_key=PROVENANCE_KEY,
    )
    swapped = capsule.model_copy(update={"proof": second})

    with pytest.raises(AgentPreExecutionProofCapsuleError, match="AGENT_PROOF_CAPSULE_INVALID"):
        require_agent_preexecution_proof_capsule(
            swapped,
            integrity_key=PROVENANCE_KEY,
        )


def test_capsule_hmac_does_not_override_untrusted_inner_agent_provenance() -> None:
    proof = _proof(trusted_provenance=False)
    capsule = _manually_sealed_capsule(proof)

    with pytest.raises(
        AgentPreExecutionProofCapsuleError,
        match="AGENT_PROOF_CAPSULE_PROVENANCE_INVALID",
    ):
        require_agent_preexecution_proof_capsule(
            capsule,
            integrity_key=PROVENANCE_KEY,
        )


def test_capsule_rejects_tampered_proof_content_commitment_before_handoff() -> None:
    proof = _proof().model_copy(update={"sql_sha256": _hash("f")})

    with pytest.raises(AgentPreExecutionProofCapsuleError, match="AGENT_PROOF_CAPSULE_INVALID"):
        seal_agent_preexecution_proof_capsule(
            proof,
            integrity_key=PROVENANCE_KEY,
        )


def test_capsule_seal_rejects_provenance_subclass_before_virtual_serialization() -> None:
    poisoned = _poison_provenance_virtual_serialization(_proof())

    with pytest.raises(
        AgentPreExecutionProofCapsuleError,
        match="AGENT_PROOF_CAPSULE_PROVENANCE_INVALID",
    ):
        seal_agent_preexecution_proof_capsule(
            poisoned,
            integrity_key=PROVENANCE_KEY,
        )


def test_capsule_verify_rejects_provenance_subclass_before_virtual_serialization() -> None:
    proof = _proof()
    capsule = seal_agent_preexecution_proof_capsule(
        proof,
        integrity_key=PROVENANCE_KEY,
    )
    poisoned = _poison_provenance_virtual_serialization(proof)
    poisoned_capsule = capsule.model_copy(update={"proof": poisoned})

    with pytest.raises(
        AgentPreExecutionProofCapsuleError,
        match="AGENT_PROOF_CAPSULE_PROVENANCE_INVALID",
    ):
        require_agent_preexecution_proof_capsule(
            poisoned_capsule,
            integrity_key=PROVENANCE_KEY,
        )


def test_handoff_authority_exposes_capsule_issue_not_raw_build() -> None:
    authority = DataHubAgentProofHandoffAuthority(
        integrity_key=PROOF_KEY,
        provenance_integrity_key=PROVENANCE_KEY,
        clock=lambda: NOW,
    )
    parameters = inspect.signature(DataHubAgentProofHandoffAuthority.issue).parameters

    assert not hasattr(authority, "build")
    assert "identity" not in parameters
    assert "integrity_key" not in parameters
    assert "provenance_integrity_key" not in parameters
    assert {"proposal", "evaluation", "ppmc_evaluation", "sql", "state", "grammar"} <= set(
        parameters
    )


def test_handoff_authority_preserves_key_separation_failure() -> None:
    with pytest.raises(
        AgentProofHandoffAuthorityError,
        match="AGENT_PROOF_INTEGRITY_KEY_INVALID",
    ):
        DataHubAgentProofHandoffAuthority(
            integrity_key=PROOF_KEY,
            provenance_integrity_key=PROOF_KEY,
        )
