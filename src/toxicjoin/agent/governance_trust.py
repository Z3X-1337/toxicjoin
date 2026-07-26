"""Security-owned EvidenceTrust resolution for one grounded Agent evaluation.

This stage is deliberately separate from DataHub derivation replay and from the local
PolicyEngine decision. A positive binding exists only when every governance fact that
can affect the grounded policy context resolves ``TRUSTED`` under the package-owned
DataHub Evidence Policy and matches the exact security-owned context from Day 13.
"""

from __future__ import annotations

import hashlib
import json
import threading
from datetime import datetime, timezone
from typing import Literal

from pydantic import Field, field_validator, model_validator

from toxicjoin.agent.proposal_authority import TrustedAgentProposalEvaluation
from toxicjoin.evidence import (
    EvidencePolicy,
    EvidenceResolution,
    EvidenceTrustState,
    datahub_governance_evidence_policy,
    resolve_evidence,
)
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.models import ColumnContext, SensitivityCategory, StrictModel

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class GovernanceTrustBindingError(RuntimeError):
    """Stable fail-closed error for authorization-facing governance trust resolution."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class GovernanceFactRequirement(StrictModel):
    """One exact governance fact whose trusted value is required by the grounded context."""

    subject: str = Field(min_length=1, max_length=2048)
    predicate: str = Field(min_length=1, max_length=256)
    expected_value: str = Field(min_length=1, max_length=4096)

    @property
    def key(self) -> str:
        return f"{self.subject}\x00{self.predicate}"

    @model_validator(mode="after")
    def validate_canonical_scope(self) -> "GovernanceFactRequirement":
        if self.subject != self.subject.strip() or self.predicate != self.predicate.strip():
            raise ValueError("governance requirement scope must be canonical")
        return self


class GovernanceTrustBinding(StrictModel):
    """Positive authorization-facing trust binding for one exact Agent evaluation.

    Existence of this artifact means only that the declared governance facts resolved
    ``TRUSTED`` under the embedded versioned Evidence Policy at issuance time. It does
    not authorize execution and it does not claim that DataHub metadata is objectively
    true in the real world.
    """

    schema_version: Literal["1.0"] = "1.0"
    evaluation_sha256: str = Field(pattern=_HASH_PATTERN)
    source_snapshot_sha256: str = Field(pattern=_HASH_PATTERN)
    governance_sha256: str = Field(pattern=_HASH_PATTERN)
    evidence_root_sha256: str = Field(pattern=_HASH_PATTERN)
    source_identity: str = Field(min_length=1, max_length=2048)
    evidence_policy: EvidencePolicy
    evidence_policy_sha256: str = Field(pattern=_HASH_PATTERN)
    requirements: tuple[GovernanceFactRequirement, ...] = Field(min_length=1)
    resolutions: tuple[EvidenceResolution, ...] = Field(min_length=1)
    issued_at: datetime
    evidence_expires_at: datetime
    governance_trusted: Literal[True] = True
    evidence_trust_resolved: Literal[True] = True
    prospective_privacy_checked: Literal[False] = False
    execution_authorized: Literal[False] = False
    binding_sha256: str = Field(pattern=_HASH_PATTERN)

    @field_validator("issued_at", "evidence_expires_at")
    @classmethod
    def timestamps_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("governance trust timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_binding(self) -> "GovernanceTrustBinding":
        if self.issued_at >= self.evidence_expires_at:
            raise ValueError("governance trust binding cannot be issued from expired evidence")
        if self.evidence_policy_sha256 != canonical_json_sha256(
            self.evidence_policy.model_dump(mode="json")
        ):
            raise ValueError("governance trust Evidence Policy commitment mismatch")

        requirement_keys = tuple(requirement.key for requirement in self.requirements)
        if requirement_keys != tuple(sorted(set(requirement_keys))):
            raise ValueError("governance trust requirements must be sorted and unique")

        resolution_keys = tuple(
            f"{resolution.subject}\x00{resolution.predicate}"
            for resolution in self.resolutions
        )
        if resolution_keys != requirement_keys:
            raise ValueError("governance trust resolutions do not match required fact scopes")

        for requirement, resolution in zip(self.requirements, self.resolutions, strict=True):
            if resolution.policy_version != self.evidence_policy.version:
                raise ValueError("governance trust resolution policy version mismatch")
            if resolution.state != EvidenceTrustState.TRUSTED or resolution.value is None:
                raise ValueError("governance trust binding contains a non-trusted resolution")
            if resolution.value != requirement.expected_value:
                raise ValueError("governance trust resolution value mismatch")

        if self.binding_sha256 != compute_governance_trust_binding_sha256(self):
            raise ValueError("governance trust binding hash mismatch")
        return self


class DataHubGovernanceTrustAuthority:
    """Resolve the exact grounded DataHub governance facts under security-owned policy."""

    def __init__(self, *, clock=None) -> None:
        policy = datahub_governance_evidence_policy()
        self._policy = EvidencePolicy.model_validate(policy.model_dump(mode="json"))
        self._policy_sha256 = canonical_json_sha256(self._policy.model_dump(mode="json"))
        self._clock = (lambda: datetime.now(timezone.utc)) if clock is None else clock
        self._clock_lock = threading.Lock()
        self._last_clock_sample: datetime | None = None

    def bind(self, evaluation: TrustedAgentProposalEvaluation) -> GovernanceTrustBinding:
        """Return a positive binding or expose only a stable fail-closed error code."""

        stable_code = "GOVERNANCE_TRUST_INTERNAL_FAILED"
        try:
            return self._bind_impl(evaluation)
        except GovernanceTrustBindingError as error:
            stable_code = error.code
            _detach_exception(error)
        except Exception as error:
            _detach_exception(error)

        evaluation = None  # type: ignore[assignment]
        self_ref = self
        self = None  # type: ignore[assignment]
        self_ref = None  # type: ignore[assignment]
        raise GovernanceTrustBindingError(stable_code) from None

    def _bind_impl(
        self,
        evaluation: TrustedAgentProposalEvaluation,
    ) -> GovernanceTrustBinding:
        if type(evaluation) is not TrustedAgentProposalEvaluation:
            raise GovernanceTrustBindingError("GOVERNANCE_TRUST_INPUT_INVALID")
        try:
            trusted = TrustedAgentProposalEvaluation.model_validate(
                evaluation.model_dump(mode="json")
            )
        except Exception:
            raise GovernanceTrustBindingError("GOVERNANCE_TRUST_INPUT_INVALID") from None

        bundle = trusted.evidence_bundle
        current = self._sample_clock()
        if current < bundle.observed_at:
            raise GovernanceTrustBindingError("GOVERNANCE_TRUST_EVIDENCE_FROM_FUTURE")
        if current >= bundle.expires_at:
            raise GovernanceTrustBindingError("GOVERNANCE_TRUST_EVIDENCE_STALE")

        if trusted.resolution.failures:
            raise GovernanceTrustBindingError("GOVERNANCE_TRUST_GROUNDING_INCOMPLETE")
        if (
            trusted.governance_binding.catalog_version != bundle.catalog_version
            or trusted.governance_binding.observed_at != bundle.observed_at
            or trusted.governance_binding.expires_at != bundle.expires_at
        ):
            raise GovernanceTrustBindingError("GOVERNANCE_TRUST_EVIDENCE_BINDING_MISMATCH")

        _require_support_closure(bundle.claims)
        requirements = _required_governance_facts(trusted)
        claims_by_scope: dict[tuple[str, str], list] = {}
        for claim in bundle.claims:
            claims_by_scope.setdefault((claim.subject, claim.predicate), []).append(claim)

        resolutions: list[EvidenceResolution] = []
        for requirement in requirements:
            claims = tuple(
                sorted(
                    claims_by_scope.get((requirement.subject, requirement.predicate), ()),
                    key=lambda claim: claim.claim_id,
                )
            )
            if not claims:
                raise GovernanceTrustBindingError("GOVERNANCE_TRUST_REQUIRED_FACT_MISSING")
            resolution = resolve_evidence(
                subject=requirement.subject,
                predicate=requirement.predicate,
                claims=claims,
                policy=self._policy,
                now=current,
            )
            if resolution.state != EvidenceTrustState.TRUSTED or resolution.value is None:
                raise GovernanceTrustBindingError(
                    "GOVERNANCE_TRUST_REQUIRED_FACT_NOT_TRUSTED"
                )
            if resolution.value != requirement.expected_value:
                raise GovernanceTrustBindingError("GOVERNANCE_TRUST_VALUE_MISMATCH")
            resolutions.append(resolution)

        issued_at = self._sample_clock()
        if issued_at < bundle.observed_at or issued_at >= bundle.expires_at:
            raise GovernanceTrustBindingError("GOVERNANCE_TRUST_STALE_AT_ISSUE")

        payload = {
            "evaluation_sha256": trusted.evaluation_sha256,
            "source_snapshot_sha256": trusted.source_snapshot_sha256,
            "governance_sha256": trusted.governance_sha256,
            "evidence_root_sha256": bundle.evidence_root_sha256,
            "source_identity": bundle.source_identity,
            "evidence_policy": self._policy,
            "evidence_policy_sha256": self._policy_sha256,
            "requirements": requirements,
            "resolutions": tuple(resolutions),
            "issued_at": issued_at,
            "evidence_expires_at": bundle.expires_at,
            "governance_trusted": True,
            "evidence_trust_resolved": True,
            "prospective_privacy_checked": False,
            "execution_authorized": False,
        }
        provisional = GovernanceTrustBinding.model_construct(
            **payload,
            binding_sha256="0" * 64,
        )
        return GovernanceTrustBinding(
            **payload,
            binding_sha256=compute_governance_trust_binding_sha256(provisional),
        )

    def _sample_clock(self) -> datetime:
        with self._clock_lock:
            try:
                current = self._clock()
                if not isinstance(current, datetime) or current.tzinfo is None:
                    raise ValueError("governance trust clock must be timezone-aware")
                normalized = current.astimezone(timezone.utc)
            except Exception:
                raise GovernanceTrustBindingError("GOVERNANCE_TRUST_TIME_INVALID") from None
            if self._last_clock_sample is not None and normalized < self._last_clock_sample:
                raise GovernanceTrustBindingError("GOVERNANCE_TRUST_TIME_ROLLBACK")
            self._last_clock_sample = normalized
            return normalized


def compute_governance_trust_binding_sha256(binding: GovernanceTrustBinding) -> str:
    return canonical_json_sha256(
        binding.model_dump(mode="json", exclude={"binding_sha256"})
    )


def _required_governance_facts(
    evaluation: TrustedAgentProposalEvaluation,
) -> tuple[GovernanceFactRequirement, ...]:
    bundle = evaluation.evidence_bundle
    requirements: dict[str, GovernanceFactRequirement] = {}

    def add(subject: str, predicate: str, expected_value: str) -> None:
        requirement = GovernanceFactRequirement(
            subject=subject,
            predicate=predicate,
            expected_value=expected_value,
        )
        existing = requirements.get(requirement.key)
        if existing is not None and existing.expected_value != expected_value:
            raise GovernanceTrustBindingError("GOVERNANCE_TRUST_REQUIREMENT_CONFLICT")
        requirements[requirement.key] = requirement

    add(bundle.source_identity, "datahub.snapshot_sha256", evaluation.source_snapshot_sha256)
    add(bundle.source_identity, "datahub.catalog_version", bundle.catalog_version)

    contexts: dict[str, ColumnContext] = {}
    for context in (
        *evaluation.resolution.projected_context,
        *evaluation.resolution.all_referenced_context,
    ):
        existing = contexts.get(context.ref.key)
        if existing is not None and existing != context:
            raise GovernanceTrustBindingError("GOVERNANCE_TRUST_GROUNDING_CONFLICT")
        contexts[context.ref.key] = context

    for context in (contexts[key] for key in sorted(contexts)):
        if (
            not context.resolved
            or context.datahub_urn is None
            or context.category == SensitivityCategory.UNCLASSIFIED
        ):
            raise GovernanceTrustBindingError("GOVERNANCE_TRUST_GROUNDING_INCOMPLETE")
        field_subject = f"{context.datahub_urn}#{context.ref.field_path}"
        add(context.datahub_urn, "datahub.logical_name", context.ref.dataset)
        add(field_subject, "datahub.tags", _compact_metadata(context.tags))
        add(
            field_subject,
            "datahub.glossary_terms",
            _compact_metadata(context.glossary_terms),
        )
        add(field_subject, "toxicjoin.sensitivity_category", context.category.value)
        add(field_subject, "datahub.lineage_transport_complete", "true")
        add(field_subject, "toxicjoin.lineage_governance_complete", "true")

        for source in sorted(context.lineage_sources, key=lambda item: item.ref.key):
            if source.category == SensitivityCategory.UNCLASSIFIED:
                raise GovernanceTrustBindingError("GOVERNANCE_TRUST_GROUNDING_INCOMPLETE")
            edge_subject = _lineage_edge_subject(field_subject, source.ref.key)
            add(edge_subject, "datahub.lineage_source_ref", source.ref.key)
            add(
                edge_subject,
                "toxicjoin.lineage_source_category",
                source.category.value,
            )
            if source.datahub_urn is not None:
                add(edge_subject, "datahub.lineage_source_urn", source.datahub_urn)

    return tuple(requirements[key] for key in sorted(requirements))


def _require_support_closure(claims) -> None:
    claim_ids = {claim.claim_id for claim in claims}
    for claim in claims:
        if any(supporting not in claim_ids for supporting in claim.supporting_claim_ids):
            raise GovernanceTrustBindingError("GOVERNANCE_TRUST_EVIDENCE_SUPPORT_MISSING")


def _compact_metadata(values: tuple[str, ...]) -> str:
    return json.dumps(list(values), ensure_ascii=True, separators=(",", ":"))


def _lineage_edge_subject(target_subject: str, source_ref: str) -> str:
    digest = hashlib.sha256(
        f"{target_subject}\x00{source_ref}".encode("utf-8")
    ).hexdigest()[:32]
    return f"{target_subject}::lineage::{digest}"


def _detach_exception(error: BaseException) -> None:
    error.__traceback__ = None
    error.__context__ = None
    error.__cause__ = None
    error.__suppress_context__ = True
