"""Machine-verifiable privacy proof artifacts."""

from toxicjoin.proofs.agent_handoff import (
    AgentPreExecutionProofCapsule,
    AgentPreExecutionProofCapsuleError,
    compute_agent_preexecution_proof_capsule_hmac,
    compute_agent_preexecution_proof_capsule_sha256,
    require_agent_preexecution_proof_capsule,
)
from toxicjoin.proofs.agent_provenance import compute_agent_ppmc_provenance_hmac
from toxicjoin.proofs.models import (
    AgentPpmcProofBinding,
    PreExecutionPrivacyProof,
    ProofVerificationFailure,
    ProofVerificationResult,
    RepairProofBinding,
    compute_agent_ppmc_proof_binding_sha256,
)
from toxicjoin.proofs.preexec import (
    PreExecutionProofError,
    build_preexecution_privacy_proof,
    compute_preexecution_privacy_proof_hmac,
    compute_preexecution_privacy_proof_sha256,
    verify_preexecution_privacy_proof,
)

__all__ = [
    "AgentPpmcProofBinding",
    "AgentPreExecutionProofCapsule",
    "AgentPreExecutionProofCapsuleError",
    "PreExecutionPrivacyProof",
    "PreExecutionProofError",
    "ProofVerificationFailure",
    "ProofVerificationResult",
    "RepairProofBinding",
    "build_preexecution_privacy_proof",
    "compute_agent_ppmc_proof_binding_sha256",
    "compute_agent_ppmc_provenance_hmac",
    "compute_agent_preexecution_proof_capsule_hmac",
    "compute_agent_preexecution_proof_capsule_sha256",
    "compute_preexecution_privacy_proof_hmac",
    "compute_preexecution_privacy_proof_sha256",
    "require_agent_preexecution_proof_capsule",
    "verify_preexecution_privacy_proof",
]
