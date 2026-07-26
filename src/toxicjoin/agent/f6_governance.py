"""Security-owned bridge from DataHub governance trust into the prospective F6 gate.

The legacy prospective predicate accepts a compact ``trusted`` governance assertion.  This
module is the only Day-13 path allowed to construct that assertion from Governed Agent
artifacts.  It does not trust serialized hashes or a caller-selected boolean: it independently
rebinds the exact Agent evaluation, DataHub GovernanceTrustBinding, DisclosureState, package
Evidence Policy, required fact set, and EvidenceTrust resolutions before issuing a state-bound
clearance.

A clearance is not a prospective privacy proof and never authorizes execution.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Literal

from pydantic import Field, field_validator, model_validator

from toxicjoin.agent.governance_trust import (
    GovernanceTrustBinding as DataHubGovernanceTrustBinding,
    _required_governance_facts,
)
from toxicjoin.agent.proposal_authority import TrustedAgentProposalEvaluation
from toxicjoin.evidence import EvidenceTrustState, resolve_evidence
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.evidence.policy import datahub_governance_evidence_policy
from toxicjoin.models import StrictModel
from toxicjoin.prospective.forbidden import (
    GovernanceTrustBinding as ProspectiveGovernanceTrustBinding,
    build_governance_trust_binding,
)
from toxicjoin.prospective.twin import DisclosureState

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class F6GovernanceClearanceError(RuntimeError):
    """Stable fail-closed error for the security-owned F6 governance bridge."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class F6GovernanceClearance(StrictModel):
    """State-specific proof-of-rebinding that permits the legacy F6 predicate to clear.

    The nested prospective binding is deliberately narrow.  The surrounding clearance binds it
    to the exact Agent evaluation, DataHub trust artifact, and DisclosureState that were
    independently checked by :class:`DataHubF6GovernanceAuthority`.
    """

    schema_version: Literal["1.0"] = "1.0"
    evaluation_sha256: str = Field(pattern=_HASH_PATTERN)
    governance_trust_binding_sha256: str = Field(pattern=_HASH_PATTERN)
    disclosure_state_sha256: str = Field(pattern=_HASH_PATTERN)
    governance_commitment_sha256: str = Field(pattern=_HASH_PATTERN)
    evidence_root_sha256: str = Field(pattern=_HASH_PATTERN)
    purpose_commitment_sha256: str = Field(pattern=_HASH_PATTERN)
    verified_at: datetime
    evidence_expires_at: datetime
    f6_binding: ProspectiveGovernanceTrustBinding
    f6_governance_clear: Literal[True] = True
    prospective_privacy_checked: Literal[False] = False
    execution_authorized: Literal[False] = False
    clearance_sha256: str = Field(pattern=_HASH_PATTERN)

    @field_validator("verified_at", "evidence_expires_at")
    @classmethod
    def timestamps_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("F6 governance clearance timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_clearance(self) -> "F6GovernanceClearance":
        if self.verified_at >= self.evidence_expires_at:
            raise ValueError("F6 governance clearance cannot outlive trusted evidence")
        if not self.f6_binding.trusted:
            raise ValueError("F6 governance clearance requires trusted prospective binding")
        if self.f6_binding.governance_commitment_sha256 != self.governance_commitment_sha256:
            raise ValueError("F6 governance clearance commitment mismatch")
        if self.f6_binding.trust_evidence_sha256 != self.governance_trust_binding_sha256:
            raise ValueError("F6 governance clearance trust-evidence mismatch")
        if self.clearance_sha256 != compute_f6_governance_clearance_sha256(self):
            raise ValueError("F6 governance clearance hash mismatch")
        return self


class DataHubF6GovernanceAuthority:
    """Rebind one exact DataHub trust artifact before allowing F6 to see ``trusted=True``."""

    def __init__(self, *, clock=None) -> None:
        self._clock = (lambda: datetime.now(timezone.utc)) if clock is None else clock
        self._clock_lock = threading.Lock()
        self._last_clock_sample: datetime | None = None

    def clear(
        self,
        *,
        evaluation: TrustedAgentProposalEvaluation,
        governance_trust: DataHubGovernanceTrustBinding,
        state: DisclosureState,
    ) -> F6GovernanceClearance:
        """Return a state-specific F6 clearance or expose only a stable fail-closed code."""

        stable_code = "F6_GOVERNANCE_INTERNAL_FAILED"
        try:
            return self._clear_impl(
                evaluation=evaluation,
                governance_trust=governance_trust,
                state=state,
            )
        except F6GovernanceClearanceError as error:
            stable_code = error.code
            _detach_exception(error)
        except Exception as error:
            _detach_exception(error)

        evaluation = None  # type: ignore[assignment]
        governance_trust = None  # type: ignore[assignment]
        state = None  # type: ignore[assignment]
        self = None  # type: ignore[assignment]
        raise F6GovernanceClearanceError(stable_code) from None

    def _clear_impl(
        self,
        *,
        evaluation: TrustedAgentProposalEvaluation,
        governance_trust: DataHubGovernanceTrustBinding,
        state: DisclosureState,
    ) -> F6GovernanceClearance:
        if (
            type(evaluation) is not TrustedAgentProposalEvaluation
            or type(governance_trust) is not DataHubGovernanceTrustBinding
            or type(state) is not DisclosureState
        ):
            raise F6GovernanceClearanceError("F6_GOVERNANCE_INPUT_INVALID")

        try:
            trusted_evaluation = TrustedAgentProposalEvaluation.model_validate(
                evaluation.model_dump(mode="json")
            )
            trusted_binding = DataHubGovernanceTrustBinding.model_validate(
                governance_trust.model_dump(mode="json")
            )
            trusted_state = DisclosureState.model_validate(state.model_dump(mode="json"))
        except Exception:
            raise F6GovernanceClearanceError("F6_GOVERNANCE_INPUT_INVALID") from None

        bundle = trusted_evaluation.evidence_bundle
        if (
            trusted_evaluation.governance_binding.catalog_version != bundle.catalog_version
            or trusted_evaluation.governance_binding.observed_at != bundle.observed_at
            or trusted_evaluation.governance_binding.expires_at != bundle.expires_at
        ):
            raise F6GovernanceClearanceError("F6_GOVERNANCE_EVIDENCE_BINDING_MISMATCH")
        if trusted_binding.evaluation_sha256 != trusted_evaluation.evaluation_sha256:
            raise F6GovernanceClearanceError("F6_GOVERNANCE_EVALUATION_MISMATCH")
        if trusted_binding.source_snapshot_sha256 != trusted_evaluation.source_snapshot_sha256:
            raise F6GovernanceClearanceError("F6_GOVERNANCE_SNAPSHOT_MISMATCH")
        if trusted_binding.governance_sha256 != trusted_evaluation.governance_sha256:
            raise F6GovernanceClearanceError("F6_GOVERNANCE_ARTIFACT_MISMATCH")
        if trusted_binding.evidence_root_sha256 != bundle.evidence_root_sha256:
            raise F6GovernanceClearanceError("F6_GOVERNANCE_EVIDENCE_MISMATCH")
        if trusted_binding.source_identity != bundle.source_identity:
            raise F6GovernanceClearanceError("F6_GOVERNANCE_SOURCE_MISMATCH")
        if trusted_binding.evidence_expires_at != bundle.expires_at:
            raise F6GovernanceClearanceError("F6_GOVERNANCE_EXPIRY_MISMATCH")

        expected_policy = datahub_governance_evidence_policy()
        expected_policy_sha256 = canonical_json_sha256(expected_policy.model_dump(mode="json"))
        if (
            trusted_binding.evidence_policy != expected_policy
            or trusted_binding.evidence_policy_sha256 != expected_policy_sha256
        ):
            raise F6GovernanceClearanceError("F6_GOVERNANCE_POLICY_MISMATCH")

        governance_commitment_sha256 = canonical_json_sha256(
            trusted_evaluation.governance_binding.model_dump(mode="json")
        )
        if trusted_state.purpose_commitment_sha256 != trusted_evaluation.authorized_task_purpose_sha256:
            raise F6GovernanceClearanceError("F6_STATE_PURPOSE_MISMATCH")
        if trusted_state.governance_commitment_sha256 != governance_commitment_sha256:
            raise F6GovernanceClearanceError("F6_STATE_GOVERNANCE_MISMATCH")
        if trusted_state.evidence_root_sha256 != bundle.evidence_root_sha256:
            raise F6GovernanceClearanceError("F6_STATE_EVIDENCE_MISMATCH")

        current = self._sample_clock()
        if current < trusted_binding.issued_at:
            raise F6GovernanceClearanceError("F6_GOVERNANCE_BINDING_FROM_FUTURE")
        if current < bundle.observed_at or current < trusted_evaluation.evidence_validation.validated_at:
            raise F6GovernanceClearanceError("F6_GOVERNANCE_EVIDENCE_FROM_FUTURE")
        if (
            current >= bundle.expires_at
            or current >= trusted_evaluation.evidence_validation.evidence_expires_at
            or current >= trusted_evaluation.governance_binding.expires_at
            or current >= trusted_binding.evidence_expires_at
        ):
            raise F6GovernanceClearanceError("F6_GOVERNANCE_STALE")

        claim_ids = {claim.claim_id for claim in bundle.claims}
        if any(
            supporting_claim_id not in claim_ids
            for claim in bundle.claims
            for supporting_claim_id in claim.supporting_claim_ids
        ):
            raise F6GovernanceClearanceError("F6_GOVERNANCE_EVIDENCE_SUPPORT_MISSING")

        expected_requirements = _required_governance_facts(trusted_evaluation)
        if trusted_binding.requirements != expected_requirements:
            raise F6GovernanceClearanceError("F6_GOVERNANCE_REQUIREMENTS_MISMATCH")

        claims_by_scope: dict[tuple[str, str], list] = {}
        for claim in bundle.claims:
            claims_by_scope.setdefault((claim.subject, claim.predicate), []).append(claim)

        expected_resolutions = []
        for requirement in expected_requirements:
            claims = tuple(
                sorted(
                    claims_by_scope.get((requirement.subject, requirement.predicate), ()),
                    key=lambda claim: claim.claim_id,
                )
            )
            if not claims:
                raise F6GovernanceClearanceError("F6_GOVERNANCE_REQUIRED_FACT_MISSING")
            resolution = resolve_evidence(
                subject=requirement.subject,
                predicate=requirement.predicate,
                claims=claims,
                policy=expected_policy,
                now=current,
            )
            if resolution.state != EvidenceTrustState.TRUSTED or resolution.value is None:
                raise F6GovernanceClearanceError("F6_GOVERNANCE_REQUIRED_FACT_NOT_TRUSTED")
            if resolution.value != requirement.expected_value:
                raise F6GovernanceClearanceError("F6_GOVERNANCE_REQUIRED_VALUE_MISMATCH")
            expected_resolutions.append(resolution)

        if trusted_binding.resolutions != tuple(expected_resolutions):
            raise F6GovernanceClearanceError("F6_GOVERNANCE_RESOLUTIONS_MISMATCH")

        f6_binding = build_governance_trust_binding(
            governance_commitment_sha256=governance_commitment_sha256,
            trusted=True,
            trust_evidence_sha256=trusted_binding.binding_sha256,
        )
        payload = {
            "evaluation_sha256": trusted_evaluation.evaluation_sha256,
            "governance_trust_binding_sha256": trusted_binding.binding_sha256,
            "disclosure_state_sha256": trusted_state.state_sha256,
            "governance_commitment_sha256": governance_commitment_sha256,
            "evidence_root_sha256": bundle.evidence_root_sha256,
            "purpose_commitment_sha256": trusted_evaluation.authorized_task_purpose_sha256,
            "verified_at": current,
            "evidence_expires_at": bundle.expires_at,
            "f6_binding": f6_binding,
            "f6_governance_clear": True,
            "prospective_privacy_checked": False,
            "execution_authorized": False,
        }
        provisional = F6GovernanceClearance.model_construct(
            **payload,
            clearance_sha256="0" * 64,
        )
        result = F6GovernanceClearance(
            **payload,
            clearance_sha256=compute_f6_governance_clearance_sha256(provisional),
        )

        returned_at = self._sample_clock()
        if returned_at >= bundle.expires_at:
            raise F6GovernanceClearanceError("F6_GOVERNANCE_STALE_AT_ISSUE")
        return result

    def _sample_clock(self) -> datetime:
        with self._clock_lock:
            try:
                current = self._clock()
                if not isinstance(current, datetime) or current.tzinfo is None:
                    raise ValueError("F6 governance clock must be timezone-aware")
                normalized = current.astimezone(timezone.utc)
            except Exception:
                raise F6GovernanceClearanceError("F6_GOVERNANCE_TIME_INVALID") from None
            if self._last_clock_sample is not None and normalized < self._last_clock_sample:
                raise F6GovernanceClearanceError("F6_GOVERNANCE_TIME_ROLLBACK")
            self._last_clock_sample = normalized
            return normalized


def compute_f6_governance_clearance_sha256(clearance: F6GovernanceClearance) -> str:
    return canonical_json_sha256(
        clearance.model_dump(mode="json", exclude={"clearance_sha256"})
    )


def _detach_exception(error: BaseException) -> None:
    error.__traceback__ = None
    error.__context__ = None
    error.__cause__ = None
    error.__suppress_context__ = True
