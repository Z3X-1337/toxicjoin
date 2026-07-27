"""Strict models for P0 pre-execution privacy proof artifacts."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.models import StrictModel
from toxicjoin.proofs.ppmc_profile import PREEXECUTION_PPMC_PROFILE

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_PROOF_VERSION = "0.1.0"
_MAX_PROOF_TTL_SECONDS = 60.0
Sha256 = Annotated[str, Field(pattern=_HASH_PATTERN)]


class ProofVerificationFailure(StrEnum):
    SCHEMA_INVALID = "PROOF_SCHEMA_INVALID"
    CONTENT_HASH_MISMATCH = "PROOF_CONTENT_HASH_MISMATCH"
    HMAC_MISMATCH = "PROOF_HMAC_MISMATCH"
    PPMC_PROFILE_INVALID = "PROOF_PPMC_PROFILE_INVALID"
    NOT_YET_VALID = "PROOF_NOT_YET_VALID"
    EXPIRED = "PROOF_EXPIRED"


class RepairProofBinding(StrictModel):
    """Commit one selected, fully validated CPCC repair into a privacy proof."""

    schema_version: Literal["1.0"] = "1.0"
    cpcc_model_version: Literal["0.1.0"] = "0.1.0"
    cpcc_result_sha256: Sha256
    remediation_space_sha256: Sha256
    selected_candidate_sha256: Sha256
    selected_validation_sha256: Sha256
    generated_sql_sha256: Sha256
    binding_sha256: Sha256

    @model_validator(mode="after")
    def validate_binding(self) -> "RepairProofBinding":
        if self.binding_sha256 != compute_repair_proof_binding_sha256(self):
            raise ValueError("repair proof binding hash mismatch")
        return self


class AgentPpmcProofBinding(StrictModel):
    """Cryptographically separated Governed-Agent provenance commitment for one proof.

    ``proof_core_sha256`` commits every base-proof field before Agent provenance and the enclosing
    proof hashes are attached. ``binding_sha256`` commits the provenance payload itself, while
    ``authority_hmac_sha256`` authenticates that payload with a key distinct from both the generic
    proof HMAC key and the execution-authorization key. Explicit PPMC fields remain duplicated for
    diagnosability, while the proof-core commitment prevents a generic proof issuer from rewriting
    lifetime, snapshot, repair, profile, or any future base-proof field and retaining genuine Agent
    provenance.
    """

    schema_version: Literal["1.0"] = "1.0"
    agent_proposal_sha256: Sha256
    agent_evaluation_sha256: Sha256
    agent_ppmc_evaluation_sha256: Sha256
    f6_clearance_sha256: Sha256
    proof_core_sha256: Sha256
    request_identity_sha256: Sha256
    sql_sha256: Sha256
    query_plan_sha256: Sha256
    task_purpose_sha256: Sha256
    purpose_commitment_sha256: Sha256
    subject_key_sha256: Sha256
    governance_context_sha256: Sha256
    governance_binding_sha256: Sha256
    evidence_root_sha256: Sha256
    evidence_validation_sha256: Sha256
    policy_sha256: Sha256
    policy_decision_sha256: Sha256
    disclosure_state_sha256: Sha256
    grammar_sha256: Sha256
    ppmc_execution_profile: Literal["p0-preexec-v1"] = PREEXECUTION_PPMC_PROFILE
    ppmc_config_sha256: Sha256
    ppmc_forbidden_policy_sha256: Sha256
    ppmc_governance_binding_sha256: Sha256
    ppmc_search_transcript_sha256: Sha256
    ppmc_result_sha256: Sha256
    ppmc_status: Literal["NO_COUNTEREXAMPLE_WITHIN_BOUND"] = (
        "NO_COUNTEREXAMPLE_WITHIN_BOUND"
    )
    ppmc_bound: int = Field(ge=0, le=5)
    ppmc_max_states: int = Field(ge=1, le=50_000)
    evidence_expires_at: datetime
    binding_sha256: Sha256
    authority_hmac_sha256: Sha256

    @field_validator("evidence_expires_at")
    @classmethod
    def expiry_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("Agent proof provenance expiry must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_binding(self) -> "AgentPpmcProofBinding":
        if type(self) is not AgentPpmcProofBinding:
            raise ValueError("Agent PPMC proof provenance must use the exact model type")
        if self.binding_sha256 != compute_agent_ppmc_proof_binding_sha256(self):
            raise ValueError("Agent PPMC proof provenance hash mismatch")
        return self


class PreExecutionPrivacyProof(StrictModel):
    """HMAC-authenticated commitment to one prospectively accepted execution candidate.

    The model validates structure and internal lifetime constraints. Authenticity/content-hash
    verification deliberately remains in the independent verifier so untrusted artifacts can
    produce stable, explicit failure codes instead of raising opaque validation errors.
    """

    schema_version: Literal["1.0"] = "1.0"
    proof_version: Literal["0.1.0"] = _PROOF_VERSION
    proof_kind: Literal["PRE_EXECUTION_PRIVACY_PROOF"] = "PRE_EXECUTION_PRIVACY_PROOF"
    issued_at: datetime
    expires_at: datetime

    request_identity_sha256: Sha256
    task_purpose_sha256: Sha256
    purpose_commitment_sha256: Sha256
    subject_key_sha256: Sha256
    sql_sha256: Sha256
    query_plan_sha256: Sha256
    governance_context_sha256: Sha256
    governance_binding_sha256: Sha256
    evidence_root_sha256: Sha256
    evidence_validation_sha256: Sha256
    disclosure_state_sha256: Sha256
    warehouse_snapshot_sha256: Sha256 | None = None
    policy_sha256: Sha256
    policy_decision_sha256: Sha256
    grammar_sha256: Sha256
    ppmc_execution_profile: Literal["p0-preexec-v1"] = PREEXECUTION_PPMC_PROFILE
    ppmc_config_sha256: Sha256
    ppmc_forbidden_policy_sha256: Sha256
    ppmc_governance_binding_sha256: Sha256
    ppmc_search_transcript_sha256: Sha256
    ppmc_result_sha256: Sha256
    ppmc_status: Literal["NO_COUNTEREXAMPLE_WITHIN_BOUND"] = (
        "NO_COUNTEREXAMPLE_WITHIN_BOUND"
    )
    ppmc_bound: int = Field(ge=0, le=5)
    ppmc_max_states: int = Field(ge=1, le=50_000)
    agent_ppmc_provenance: AgentPpmcProofBinding | None = None
    repair: RepairProofBinding | None = None

    privacy_proof_sha256: Sha256
    integrity_hmac_sha256: Sha256

    @field_validator("issued_at", "expires_at")
    @classmethod
    def timestamps_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("privacy proof timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_lifetime(self) -> "PreExecutionPrivacyProof":
        if self.expires_at <= self.issued_at:
            raise ValueError("privacy proof expiry must follow issuance")
        lifetime = (self.expires_at - self.issued_at).total_seconds()
        if lifetime > _MAX_PROOF_TTL_SECONDS + 1e-9:
            raise ValueError("privacy proof lifetime exceeds the P0 maximum")
        return self


class ProofVerificationResult(StrictModel):
    """Machine-readable verifier result with stable failure codes."""

    schema_version: Literal["1.0"] = "1.0"
    valid: bool
    privacy_proof_sha256: Sha256 | None = None
    failures: tuple[ProofVerificationFailure, ...] = ()

    @model_validator(mode="after")
    def validate_result(self) -> "ProofVerificationResult":
        canonical = tuple(
            failure
            for failure in ProofVerificationFailure
            if failure in set(self.failures)
        )
        if self.failures != canonical:
            raise ValueError("privacy proof verifier failures must be canonical and unique")
        if self.valid != (not self.failures):
            raise ValueError("privacy proof verifier validity/failure summary mismatch")
        if self.valid and self.privacy_proof_sha256 is None:
            raise ValueError("valid privacy proof verification requires proof commitment")
        return self


def compute_repair_proof_binding_sha256(binding: RepairProofBinding) -> str:
    return canonical_json_sha256(
        binding.model_dump(mode="json", exclude={"binding_sha256"})
    )


def compute_agent_ppmc_proof_binding_sha256(binding: AgentPpmcProofBinding) -> str:
    if type(binding) is not AgentPpmcProofBinding:
        raise TypeError("Agent PPMC proof provenance must use the exact model type")
    return canonical_json_sha256(
        binding.model_dump(
            mode="json",
            exclude={"binding_sha256", "authority_hmac_sha256"},
        )
    )
