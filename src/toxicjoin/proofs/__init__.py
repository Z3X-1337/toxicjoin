"""Machine-verifiable privacy proof artifacts."""

from toxicjoin.proofs.models import (
    PreExecutionPrivacyProof,
    ProofVerificationFailure,
    ProofVerificationResult,
    RepairProofBinding,
)
from toxicjoin.proofs.preexec import (
    PreExecutionProofError,
    build_preexecution_privacy_proof,
    compute_preexecution_privacy_proof_hmac,
    compute_preexecution_privacy_proof_sha256,
    verify_preexecution_privacy_proof,
)

__all__ = [
    "PreExecutionPrivacyProof",
    "PreExecutionProofError",
    "ProofVerificationFailure",
    "ProofVerificationResult",
    "RepairProofBinding",
    "build_preexecution_privacy_proof",
    "compute_preexecution_privacy_proof_hmac",
    "compute_preexecution_privacy_proof_sha256",
    "verify_preexecution_privacy_proof",
]
