"""Execution-bound verification of pre-execution privacy proof commitments."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone

from toxicjoin.auth import RequestIdentity
from toxicjoin.context.governance import GovernanceContextBinding
from toxicjoin.context.models import ContextResolution
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.models import ColumnRef, PolicyDecision, QueryPlan
from toxicjoin.policy import PolicyEngine
from toxicjoin.proofs import (
    PreExecutionPrivacyProof,
    ProofVerificationFailure,
    verify_preexecution_privacy_proof,
)


class ExecutionPrivacyProofBindingError(RuntimeError):
    """Stable failure raised when a proof cannot authorize the exact runtime candidate."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class VerifiedExecutionPrivacyProof:
    privacy_proof_sha256: str
    expires_at: float


def verify_execution_privacy_proof(
    proof: PreExecutionPrivacyProof,
    *,
    integrity_key: bytes,
    now_epoch_seconds: float,
    sql: str,
    query_plan: QueryPlan,
    resolution: ContextResolution,
    governance_binding: GovernanceContextBinding | None,
    policy_engine: PolicyEngine,
    policy_decision: PolicyDecision,
    task_purpose: str,
    identity: RequestIdentity | None,
    subject_key: ColumnRef,
) -> VerifiedExecutionPrivacyProof:
    """Authenticate a proof and bind it to independently recomputed execution state."""

    now = datetime.fromtimestamp(float(now_epoch_seconds), tz=timezone.utc)
    verification = verify_preexecution_privacy_proof(
        proof,
        integrity_key=integrity_key,
        now=now,
    )
    if not verification.valid:
        failures = set(verification.failures)
        if ProofVerificationFailure.EXPIRED in failures:
            raise ExecutionPrivacyProofBindingError("AUTH_PRIVACY_PROOF_EXPIRED")
        if ProofVerificationFailure.NOT_YET_VALID in failures:
            raise ExecutionPrivacyProofBindingError("AUTH_PRIVACY_PROOF_NOT_YET_VALID")
        if ProofVerificationFailure.PPMC_PROFILE_INVALID in failures:
            raise ExecutionPrivacyProofBindingError("AUTH_PRIVACY_PROOF_PROFILE_INVALID")
        raise ExecutionPrivacyProofBindingError("AUTH_PRIVACY_PROOF_INVALID")

    if governance_binding is None:
        raise ExecutionPrivacyProofBindingError(
            "AUTH_PRIVACY_PROOF_GOVERNANCE_BINDING_REQUIRED"
        )
    if identity is None:
        raise ExecutionPrivacyProofBindingError("AUTH_PRIVACY_PROOF_IDENTITY_REQUIRED")

    expected = {
        "sql_sha256": _sha256_text(sql),
        "query_plan_sha256": canonical_json_sha256(query_plan.model_dump(mode="json")),
        "governance_context_sha256": canonical_json_sha256(
            resolution.model_dump(mode="json")
        ),
        "governance_binding_sha256": canonical_json_sha256(
            governance_binding.model_dump(mode="json")
        ),
        "policy_sha256": canonical_json_sha256(
            policy_engine.config.model_dump(mode="json")
        ),
        "policy_decision_sha256": canonical_json_sha256(
            policy_decision.model_dump(mode="json")
        ),
        "task_purpose_sha256": _sha256_text(task_purpose),
        "request_identity_sha256": canonical_json_sha256(
            identity.model_dump(mode="json")
        ),
        "subject_key_sha256": canonical_json_sha256(
            subject_key.model_dump(mode="json")
        ),
    }
    failure_codes = {
        "sql_sha256": "AUTH_PRIVACY_PROOF_SQL_MISMATCH",
        "query_plan_sha256": "AUTH_PRIVACY_PROOF_QUERY_PLAN_MISMATCH",
        "governance_context_sha256": "AUTH_PRIVACY_PROOF_CONTEXT_MISMATCH",
        "governance_binding_sha256": "AUTH_PRIVACY_PROOF_GOVERNANCE_MISMATCH",
        "policy_sha256": "AUTH_PRIVACY_PROOF_POLICY_MISMATCH",
        "policy_decision_sha256": "AUTH_PRIVACY_PROOF_DECISION_MISMATCH",
        "task_purpose_sha256": "AUTH_PRIVACY_PROOF_TASK_MISMATCH",
        "request_identity_sha256": "AUTH_PRIVACY_PROOF_IDENTITY_MISMATCH",
        "subject_key_sha256": "AUTH_PRIVACY_PROOF_SUBJECT_MISMATCH",
    }
    for field_name, expected_value in expected.items():
        if getattr(proof, field_name) != expected_value:
            raise ExecutionPrivacyProofBindingError(failure_codes[field_name])

    return VerifiedExecutionPrivacyProof(
        privacy_proof_sha256=proof.privacy_proof_sha256,
        expires_at=proof.expires_at.timestamp(),
    )


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
