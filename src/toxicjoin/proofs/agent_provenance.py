"""Independent authentication/alignment checks for Governed-Agent PPMC proof provenance."""

from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Mapping

from toxicjoin.proofs.models import (
    AgentPpmcProofBinding,
    PreExecutionPrivacyProof,
    compute_agent_ppmc_proof_binding_sha256,
)

_AGENT_PROVENANCE_HMAC_DOMAIN = b"toxicjoin:agent-ppmc-proof-provenance:v1\x00"
_MIN_INTEGRITY_KEY_BYTES = 32


class AgentProofProvenanceError(RuntimeError):
    """Stable fail-closed error for proof-bound Agent provenance checks."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def compute_agent_ppmc_provenance_hmac(
    binding_or_payload: AgentPpmcProofBinding | Mapping[str, Any],
    *,
    integrity_key: bytes,
) -> str:
    """Compute the domain-separated authority HMAC for one provenance binding."""

    key = _validated_key(integrity_key)
    if type(binding_or_payload) is AgentPpmcProofBinding:
        payload = binding_or_payload.model_dump(
            mode="json",
            exclude={"authority_hmac_sha256"},
        )
    elif isinstance(binding_or_payload, AgentPpmcProofBinding):
        raise TypeError("Agent PPMC proof provenance must use the exact model type")
    else:
        payload = {
            str(name): value
            for name, value in dict(binding_or_payload).items()
            if name != "authority_hmac_sha256"
        }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=_json_default,
    ).encode("utf-8")
    return hmac.new(
        key,
        _AGENT_PROVENANCE_HMAC_DOMAIN + encoded,
        hashlib.sha256,
    ).hexdigest()


def require_agent_ppmc_provenance(
    proof: PreExecutionPrivacyProof,
    *,
    integrity_key: bytes,
) -> AgentPpmcProofBinding:
    """Require one authentic, internally aligned Agent PPMC provenance binding for ``proof``.

    The enclosing proof HMAC and this provenance HMAC have separate trust roots. The strict
    execution authorizer authenticates the ordinary proof first, then verifies this independent
    authority tag and every duplicated PPMC proof claim before trusting Agent provenance.
    """

    key = _validated_key(integrity_key)
    binding = proof.agent_ppmc_provenance
    if binding is None:
        raise AgentProofProvenanceError(
            "AUTH_PRIVACY_PROOF_AGENT_PROVENANCE_REQUIRED"
        )
    if type(binding) is not AgentPpmcProofBinding:
        raise AgentProofProvenanceError(
            "AUTH_PRIVACY_PROOF_AGENT_PROVENANCE_INVALID"
        )

    try:
        expected_binding_sha256 = compute_agent_ppmc_proof_binding_sha256(binding)
        expected_authority_hmac = compute_agent_ppmc_provenance_hmac(
            binding,
            integrity_key=key,
        )
    except (TypeError, ValueError):
        raise AgentProofProvenanceError(
            "AUTH_PRIVACY_PROOF_AGENT_PROVENANCE_INVALID"
        ) from None

    if not hmac.compare_digest(expected_binding_sha256, binding.binding_sha256):
        raise AgentProofProvenanceError(
            "AUTH_PRIVACY_PROOF_AGENT_PROVENANCE_INVALID"
        )
    if not hmac.compare_digest(
        expected_authority_hmac,
        binding.authority_hmac_sha256,
    ):
        raise AgentProofProvenanceError(
            "AUTH_PRIVACY_PROOF_AGENT_PROVENANCE_UNTRUSTED"
        )

    expected = {
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
    }
    for field_name, expected_value in expected.items():
        if getattr(binding, field_name) != expected_value:
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


def _validated_key(integrity_key: bytes) -> bytes:
    if type(integrity_key) is not bytes or len(integrity_key) < _MIN_INTEGRITY_KEY_BYTES:
        raise ValueError("Agent provenance integrity key must be at least 32 bytes")
    return bytes(integrity_key)


def _json_default(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "isoformat"):
        return value.isoformat()
    raise TypeError(f"unsupported provenance HMAC value: {type(value).__name__}")
