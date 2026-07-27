"""Authenticated handoff capsule for security-owned Governed-Agent pre-execution proofs.

The capsule is not an execution capability. It authenticates that the exact, content-consistent
``PreExecutionPrivacyProof`` was handed off under the existing Agent-provenance trust root. The
strict execution authorizer must still independently verify the proof HMAC key, Agent provenance,
current governed state, and execution bindings.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime
from typing import Literal

from pydantic import Field

from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.models import StrictModel
from toxicjoin.proofs.agent_provenance import (
    AgentProofProvenanceError,
    require_agent_ppmc_provenance,
)
from toxicjoin.proofs.models import PreExecutionPrivacyProof
from toxicjoin.proofs.preexec import compute_preexecution_privacy_proof_sha256

_CAPSULE_HMAC_DOMAIN = b"toxicjoin:agent-preexecution-proof-handoff:v1\x00"
_MIN_INTEGRITY_KEY_BYTES = 32


class AgentPreExecutionProofCapsule(StrictModel):
    """Exact security-owned handoff for one Agent-provenance-bound privacy proof."""

    schema_version: Literal["1.0"] = "1.0"
    proof: PreExecutionPrivacyProof
    proof_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    agent_provenance_binding_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_identity_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at: datetime
    expires_at: datetime
    capsule_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    authority_hmac_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class AgentPreExecutionProofCapsuleError(RuntimeError):
    """Stable fail-closed error for authenticated Agent proof handoff validation."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def seal_agent_preexecution_proof_capsule(
    proof: PreExecutionPrivacyProof,
    *,
    integrity_key: bytes,
) -> AgentPreExecutionProofCapsule:
    """Seal one exact, content-consistent proof under the Agent-provenance trust root."""

    key = _validated_key(integrity_key)
    if type(proof) is not PreExecutionPrivacyProof:
        raise AgentPreExecutionProofCapsuleError("AGENT_PROOF_CAPSULE_INVALID")

    # Authenticate the exact, non-polymorphic Agent provenance before any canonical serialization
    # of the enclosing proof. This preserves the PR #95 virtual-serialization boundary.
    try:
        provenance = require_agent_ppmc_provenance(proof, integrity_key=key)
    except AgentProofProvenanceError:
        raise AgentPreExecutionProofCapsuleError(
            "AGENT_PROOF_CAPSULE_PROVENANCE_INVALID"
        ) from None

    try:
        expected_proof_sha256 = compute_preexecution_privacy_proof_sha256(proof)
    except (TypeError, ValueError):
        raise AgentPreExecutionProofCapsuleError("AGENT_PROOF_CAPSULE_INVALID") from None
    if expected_proof_sha256 != proof.privacy_proof_sha256:
        raise AgentPreExecutionProofCapsuleError("AGENT_PROOF_CAPSULE_INVALID")

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
    content_sha256 = compute_agent_preexecution_proof_capsule_sha256(provisional)
    unsigned = provisional.model_copy(update={"capsule_sha256": content_sha256})
    return unsigned.model_copy(
        update={
            "authority_hmac_sha256": compute_agent_preexecution_proof_capsule_hmac(
                unsigned,
                integrity_key=key,
            )
        }
    )


def compute_agent_preexecution_proof_capsule_sha256(
    capsule: AgentPreExecutionProofCapsule,
) -> str:
    """Commit the exact handoff content without introducing a hash/MAC cycle."""

    if type(capsule) is not AgentPreExecutionProofCapsule:
        raise TypeError("Agent proof capsule must use the exact model type")
    return canonical_json_sha256(
        capsule.model_dump(
            mode="json",
            exclude={"capsule_sha256", "authority_hmac_sha256"},
        )
    )


def compute_agent_preexecution_proof_capsule_hmac(
    capsule: AgentPreExecutionProofCapsule,
    *,
    integrity_key: bytes,
) -> str:
    """Authenticate the exact capsule, including its content commitment."""

    key = _validated_key(integrity_key)
    if type(capsule) is not AgentPreExecutionProofCapsule:
        raise TypeError("Agent proof capsule must use the exact model type")
    payload = capsule.model_dump(mode="json", exclude={"authority_hmac_sha256"})
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hmac.new(key, _CAPSULE_HMAC_DOMAIN + encoded, hashlib.sha256).hexdigest()


def require_agent_preexecution_proof_capsule(
    capsule: AgentPreExecutionProofCapsule,
    *,
    integrity_key: bytes,
) -> PreExecutionPrivacyProof:
    """Authenticate a handoff capsule and return its exact proof only on full alignment."""

    key = _validated_key(integrity_key)
    if type(capsule) is not AgentPreExecutionProofCapsule:
        raise AgentPreExecutionProofCapsuleError("AGENT_PROOF_CAPSULE_INVALID")
    proof = capsule.proof
    if type(proof) is not PreExecutionPrivacyProof:
        raise AgentPreExecutionProofCapsuleError("AGENT_PROOF_CAPSULE_INVALID")

    # Establish exact-type/authentic Agent provenance before serializing the nested proof through
    # capsule hashing/HMAC helpers. A malicious provenance subclass therefore cannot gain virtual
    # dispatch merely by being placed inside an otherwise exact proof/capsule object.
    try:
        provenance = require_agent_ppmc_provenance(proof, integrity_key=key)
    except AgentProofProvenanceError:
        raise AgentPreExecutionProofCapsuleError(
            "AGENT_PROOF_CAPSULE_PROVENANCE_INVALID"
        ) from None

    try:
        expected_proof_sha256 = compute_preexecution_privacy_proof_sha256(proof)
        expected_content = compute_agent_preexecution_proof_capsule_sha256(capsule)
        expected_hmac = compute_agent_preexecution_proof_capsule_hmac(
            capsule,
            integrity_key=key,
        )
    except (TypeError, ValueError):
        raise AgentPreExecutionProofCapsuleError("AGENT_PROOF_CAPSULE_INVALID") from None

    if expected_proof_sha256 != proof.privacy_proof_sha256:
        raise AgentPreExecutionProofCapsuleError("AGENT_PROOF_CAPSULE_INVALID")
    if not hmac.compare_digest(expected_content, capsule.capsule_sha256):
        raise AgentPreExecutionProofCapsuleError("AGENT_PROOF_CAPSULE_INVALID")
    if not hmac.compare_digest(expected_hmac, capsule.authority_hmac_sha256):
        raise AgentPreExecutionProofCapsuleError("AGENT_PROOF_CAPSULE_UNTRUSTED")
    if capsule.proof_sha256 != proof.privacy_proof_sha256:
        raise AgentPreExecutionProofCapsuleError("AGENT_PROOF_CAPSULE_INVALID")
    if capsule.agent_provenance_binding_sha256 != provenance.binding_sha256:
        raise AgentPreExecutionProofCapsuleError("AGENT_PROOF_CAPSULE_INVALID")
    if capsule.request_identity_sha256 != proof.request_identity_sha256:
        raise AgentPreExecutionProofCapsuleError("AGENT_PROOF_CAPSULE_INVALID")
    if capsule.issued_at != proof.issued_at or capsule.expires_at != proof.expires_at:
        raise AgentPreExecutionProofCapsuleError("AGENT_PROOF_CAPSULE_INVALID")
    return proof


def _validated_key(integrity_key: bytes) -> bytes:
    if type(integrity_key) is not bytes or len(integrity_key) < _MIN_INTEGRITY_KEY_BYTES:
        raise ValueError("Agent provenance integrity key must be at least 32 bytes")
    return bytes(integrity_key)
