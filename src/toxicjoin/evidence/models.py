"""Strict deterministic models for evidence-aware governance context."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.models import StrictModel


_HASH_PATTERN = r"^[0-9a-f]{64}$"
_CLAIM_ID_PATTERN = r"^evc_[0-9a-f]{32}$"
_RESOLUTION_ID_PATTERN = r"^evr_[0-9a-f]{32}$"


class EvidenceSource(StrEnum):
    """Origin that supplied one evidence claim."""

    DATAHUB_MCP = "DATAHUB_MCP"
    WAREHOUSE_RUNTIME = "WAREHOUSE_RUNTIME"
    STATIC_MANIFEST = "STATIC_MANIFEST"
    SQL_ANALYZER = "SQL_ANALYZER"
    HUMAN_GOVERNANCE = "HUMAN_GOVERNANCE"
    AGENT = "AGENT"


class DerivationKind(StrEnum):
    """How the claim value was obtained from its source."""

    RUNTIME_OBSERVED = "RUNTIME_OBSERVED"
    EXPLICIT_MAPPING = "EXPLICIT_MAPPING"
    SQL_DERIVED = "SQL_DERIVED"
    STRICT_NAME_MATCH = "STRICT_NAME_MATCH"
    FUZZY_INFERRED = "FUZZY_INFERRED"
    HUMAN_ASSERTED = "HUMAN_ASSERTED"
    AGENT_ASSERTED = "AGENT_ASSERTED"


class EvidenceTrustState(StrEnum):
    """Deterministic authorization-facing trust state."""

    TRUSTED = "TRUSTED"
    CONTESTED = "CONTESTED"
    UNKNOWN = "UNKNOWN"
    STALE = "STALE"
    INCOMPLETE = "INCOMPLETE"
    AGENT_ASSERTED = "AGENT_ASSERTED"


class EvidenceRule(StrictModel):
    """One source/derivation pair eligible to establish trusted evidence."""

    source: EvidenceSource
    derivation: DerivationKind

    @property
    def key(self) -> str:
        return f"{self.source.value}:{self.derivation.value}"


class EvidencePolicy(StrictModel):
    """Versioned deterministic rules defining admissible evidence pairs."""

    version: str = Field(min_length=1, max_length=128)
    trusted_rules: tuple[EvidenceRule, ...] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def trusted_rules_are_canonical(self) -> "EvidencePolicy":
        keys = tuple(rule.key for rule in self.trusted_rules)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("trusted_rules must be sorted and unique")
        return self

    def trusts(self, claim: "EvidenceClaim") -> bool:
        key = f"{claim.source.value}:{claim.derivation.value}"
        return any(rule.key == key for rule in self.trusted_rules)


class EvidenceClaim(StrictModel):
    """Canonical evidence-backed assertion used by authorization logic."""

    schema_version: Literal["1.0"] = "1.0"
    claim_id: str = Field(pattern=_CLAIM_ID_PATTERN)
    subject: str = Field(min_length=1, max_length=2048)
    predicate: str = Field(min_length=1, max_length=256)
    value: str = Field(min_length=1, max_length=4096)
    source: EvidenceSource
    derivation: DerivationKind
    source_identity: str = Field(min_length=1, max_length=2048)
    observed_at: datetime
    expires_at: datetime | None = None
    effective_from: datetime | None = None
    effective_until: datetime | None = None
    complete: bool = True
    supporting_claim_ids: tuple[str, ...] = Field(default=(), max_length=128)
    content_sha256: str = Field(pattern=_HASH_PATTERN)

    @field_validator("observed_at", "expires_at", "effective_from", "effective_until")
    @classmethod
    def timestamps_must_be_utc(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            raise ValueError("evidence timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_claim(self) -> "EvidenceClaim":
        if self.expires_at is not None and self.expires_at <= self.observed_at:
            raise ValueError("expires_at must follow observed_at")
        if (
            self.effective_from is not None
            and self.effective_until is not None
            and self.effective_until <= self.effective_from
        ):
            raise ValueError("effective_until must follow effective_from")
        if self.supporting_claim_ids != tuple(sorted(set(self.supporting_claim_ids))):
            raise ValueError("supporting_claim_ids must be sorted and unique")
        expected_hash = compute_claim_sha256(self)
        if self.content_sha256 != expected_hash:
            raise ValueError("evidence claim content hash mismatch")
        if self.claim_id != f"evc_{expected_hash[:32]}":
            raise ValueError("evidence claim id mismatch")
        return self

    def is_stale(self, now: datetime) -> bool:
        if now.tzinfo is None:
            raise ValueError("evidence freshness clock must be timezone-aware")
        if self.expires_at is None:
            return False
        return now.astimezone(timezone.utc) >= self.expires_at


class EvidenceResolution(StrictModel):
    """Deterministic resolved state for one subject/predicate pair."""

    schema_version: Literal["1.0"] = "1.0"
    resolution_id: str = Field(pattern=_RESOLUTION_ID_PATTERN)
    subject: str = Field(min_length=1, max_length=2048)
    predicate: str = Field(min_length=1, max_length=256)
    state: EvidenceTrustState
    value: str | None = Field(default=None, max_length=4096)
    claim_ids: tuple[str, ...] = Field(default=(), max_length=256)
    policy_version: str = Field(min_length=1, max_length=128)
    content_sha256: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_resolution(self) -> "EvidenceResolution":
        if self.claim_ids != tuple(sorted(set(self.claim_ids))):
            raise ValueError("claim_ids must be sorted and unique")
        if self.state == EvidenceTrustState.TRUSTED and self.value is None:
            raise ValueError("trusted evidence resolution requires a value")
        if self.state != EvidenceTrustState.TRUSTED and self.value is not None:
            raise ValueError("only trusted evidence resolution may expose an authority value")
        expected_hash = compute_resolution_sha256(self)
        if self.content_sha256 != expected_hash:
            raise ValueError("evidence resolution content hash mismatch")
        if self.resolution_id != f"evr_{expected_hash[:32]}":
            raise ValueError("evidence resolution id mismatch")
        return self


def build_evidence_claim(
    *,
    subject: str,
    predicate: str,
    value: str,
    source: EvidenceSource,
    derivation: DerivationKind,
    source_identity: str,
    observed_at: datetime,
    expires_at: datetime | None = None,
    effective_from: datetime | None = None,
    effective_until: datetime | None = None,
    complete: bool = True,
    supporting_claim_ids: tuple[str, ...] = (),
) -> EvidenceClaim:
    """Build one canonical self-validating evidence claim."""

    normalized_observed = _utc(observed_at)
    normalized_expires = _utc(expires_at) if expires_at is not None else None
    normalized_effective_from = _utc(effective_from) if effective_from is not None else None
    normalized_effective_until = _utc(effective_until) if effective_until is not None else None
    canonical_supporting = tuple(sorted(set(supporting_claim_ids)))
    payload = {
        "schema_version": "1.0",
        "subject": subject,
        "predicate": predicate,
        "value": value,
        "source": source.value,
        "derivation": derivation.value,
        "source_identity": source_identity,
        "observed_at": normalized_observed.isoformat(),
        "expires_at": normalized_expires.isoformat() if normalized_expires else None,
        "effective_from": (
            normalized_effective_from.isoformat() if normalized_effective_from else None
        ),
        "effective_until": (
            normalized_effective_until.isoformat() if normalized_effective_until else None
        ),
        "complete": complete,
        "supporting_claim_ids": list(canonical_supporting),
    }
    digest = canonical_json_sha256(payload)
    return EvidenceClaim(
        claim_id=f"evc_{digest[:32]}",
        content_sha256=digest,
        subject=subject,
        predicate=predicate,
        value=value,
        source=source,
        derivation=derivation,
        source_identity=source_identity,
        observed_at=normalized_observed,
        expires_at=normalized_expires,
        effective_from=normalized_effective_from,
        effective_until=normalized_effective_until,
        complete=complete,
        supporting_claim_ids=canonical_supporting,
    )


def build_evidence_resolution(
    *,
    subject: str,
    predicate: str,
    state: EvidenceTrustState,
    value: str | None,
    claim_ids: tuple[str, ...],
    policy_version: str,
) -> EvidenceResolution:
    """Build one canonical self-validating evidence resolution."""

    canonical_claims = tuple(sorted(set(claim_ids)))
    payload = {
        "schema_version": "1.0",
        "subject": subject,
        "predicate": predicate,
        "state": state.value,
        "value": value,
        "claim_ids": list(canonical_claims),
        "policy_version": policy_version,
    }
    digest = canonical_json_sha256(payload)
    return EvidenceResolution(
        resolution_id=f"evr_{digest[:32]}",
        content_sha256=digest,
        subject=subject,
        predicate=predicate,
        state=state,
        value=value,
        claim_ids=canonical_claims,
        policy_version=policy_version,
    )


def compute_claim_sha256(claim: EvidenceClaim) -> str:
    payload = claim.model_dump(
        mode="json",
        exclude={"claim_id", "content_sha256"},
    )
    return canonical_json_sha256(payload)


def compute_resolution_sha256(resolution: EvidenceResolution) -> str:
    payload = resolution.model_dump(
        mode="json",
        exclude={"resolution_id", "content_sha256"},
    )
    return canonical_json_sha256(payload)


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("evidence timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)
