"""Independent replay validation for DataHub-derived EvidenceClaims.

The validator deliberately remains outside authorization. It replays the deterministic
DataHub evidence adapter from the exact trusted local snapshot, configured MCP read path,
and trusted freshness policy, then requires semantic and cryptographic identity with the
candidate bundle before issuing a canonical validation commitment.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from toxicjoin.context.datahub import DataHubSnapshot
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.evidence.datahub import (
    DataHubEvidenceBundle,
    DataHubEvidenceError,
    build_datahub_evidence_bundle,
    datahub_source_identity,
)
from toxicjoin.evidence.models import DerivationKind, EvidenceClaim
from toxicjoin.integrations.datahub_mcp import DataHubMcpSettings
from toxicjoin.models import StrictModel


_HASH_PATTERN = r"^[0-9a-f]{64}$"
_CLAIM_ID_PATTERN = r"^evc_[0-9a-f]{32}$"
_VALIDATOR_VERSION = "1.0"
_DEFAULT_MAX_AGE_SECONDS = 300.0
_MAX_MAX_AGE_SECONDS = 3600.0
ClaimId = Annotated[str, Field(pattern=_CLAIM_ID_PATTERN)]
ClaimKey = tuple[str, str]


class DataHubDerivationValidationError(RuntimeError):
    """Raised when a DataHub evidence bundle cannot be replay-validated safely."""


class DataHubDerivationValidation(StrictModel):
    """Canonical commitment proving deterministic replay matched one evidence bundle.

    This artifact is a local validation commitment, not remote attestation and not an
    authorization decision. A later integration layer may require this artifact before
    considering mapped evidence, but this module does not alter EvidencePolicy.
    """

    schema_version: Literal["1.0"] = "1.0"
    validator_version: Literal["1.0"] = _VALIDATOR_VERSION
    evidence_root_sha256: str = Field(pattern=_HASH_PATTERN)
    snapshot_sha256: str = Field(pattern=_HASH_PATTERN)
    source_identity: str = Field(min_length=1, max_length=2048)
    evidence_observed_at: datetime
    evidence_expires_at: datetime
    freshness_policy_seconds: float = Field(gt=0, le=_MAX_MAX_AGE_SECONDS)
    validated_at: datetime
    observed_claim_ids: tuple[ClaimId, ...] = Field(min_length=1)
    mapped_claim_ids: tuple[ClaimId, ...] = Field(min_length=1)
    validation_sha256: str = Field(pattern=_HASH_PATTERN)

    @field_validator("evidence_observed_at", "evidence_expires_at", "validated_at")
    @classmethod
    def timestamps_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("DataHub derivation validation timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_commitment(self) -> "DataHubDerivationValidation":
        if self.evidence_expires_at <= self.evidence_observed_at:
            raise ValueError("evidence_expires_at must follow evidence_observed_at")
        declared_lifetime = (
            self.evidence_expires_at - self.evidence_observed_at
        ).total_seconds()
        if round(declared_lifetime, 6) != round(self.freshness_policy_seconds, 6):
            raise ValueError("evidence lifetime must match freshness_policy_seconds")
        if self.validated_at < self.evidence_observed_at:
            raise ValueError("validated_at cannot precede evidence observation")
        if self.validated_at >= self.evidence_expires_at:
            raise ValueError("validated_at must precede evidence expiry")
        if self.observed_claim_ids != tuple(sorted(set(self.observed_claim_ids))):
            raise ValueError("observed_claim_ids must be sorted and unique")
        if self.mapped_claim_ids != tuple(sorted(set(self.mapped_claim_ids))):
            raise ValueError("mapped_claim_ids must be sorted and unique")
        if set(self.observed_claim_ids).intersection(self.mapped_claim_ids):
            raise ValueError("observed and mapped claim sets must be disjoint")
        expected = compute_datahub_derivation_validation_sha256(self)
        if self.validation_sha256 != expected:
            raise ValueError("DataHub derivation validation hash mismatch")
        return self


def validate_datahub_evidence_derivations(
    bundle: DataHubEvidenceBundle,
    snapshot: DataHubSnapshot,
    settings: DataHubMcpSettings,
    *,
    max_age_seconds: float = _DEFAULT_MAX_AGE_SECONDS,
    now: datetime | None = None,
) -> DataHubDerivationValidation:
    """Replay the DataHub evidence adapter and require an exact deterministic match.

    The caller supplies the locally trusted ``DataHubSnapshot``, configured MCP settings,
    and freshness policy. Serialized bundle content is never allowed to choose those trust
    anchors. Validation fails closed for future or expired evidence.
    """

    try:
        current = _utc(now or datetime.now(timezone.utc))
        observed_at = _utc(bundle.observed_at)
        expires_at = _utc(bundle.expires_at)
        snapshot_observed_at = _utc(snapshot.observed_at)
    except ValueError as exc:
        raise DataHubDerivationValidationError(
            "DataHub derivation validation requires timezone-aware timestamps"
        ) from exc

    if observed_at > current:
        raise DataHubDerivationValidationError(
            "DataHub evidence was observed in the future relative to validation time"
        )
    if current >= expires_at:
        raise DataHubDerivationValidationError("DataHub evidence is stale at validation time")

    snapshot_sha256 = snapshot.snapshot_sha256
    if bundle.snapshot_sha256 != snapshot_sha256:
        raise DataHubDerivationValidationError(
            "DataHub evidence snapshot commitment does not match the trusted snapshot"
        )
    if bundle.catalog_version != snapshot.catalog.version:
        raise DataHubDerivationValidationError(
            "DataHub evidence catalog version does not match the trusted snapshot"
        )
    if observed_at != snapshot_observed_at:
        raise DataHubDerivationValidationError(
            "DataHub evidence observation time does not match the trusted snapshot"
        )

    try:
        expected_source_identity = datahub_source_identity(settings)
    except DataHubEvidenceError as exc:
        raise DataHubDerivationValidationError(
            "configured DataHub source identity cannot be validated"
        ) from exc
    if bundle.source_identity != expected_source_identity:
        raise DataHubDerivationValidationError(
            "DataHub evidence source identity does not match configured MCP settings"
        )

    try:
        expected = build_datahub_evidence_bundle(
            snapshot,
            settings,
            max_age_seconds=max_age_seconds,
        )
    except (DataHubEvidenceError, ValueError) as exc:
        raise DataHubDerivationValidationError(
            "trusted DataHub evidence freshness policy is invalid"
        ) from exc

    expected_expires_at = _utc(expected.expires_at)
    if expires_at != expected_expires_at:
        raise DataHubDerivationValidationError(
            "DataHub evidence freshness window does not match trusted validator policy"
        )

    candidate_by_key = _index_claims(bundle.claims, label="candidate")
    expected_by_key = _index_claims(expected.claims, label="expected")

    candidate_keys = set(candidate_by_key)
    expected_keys = set(expected_by_key)
    if candidate_keys != expected_keys:
        missing = sorted(expected_keys - candidate_keys)
        unexpected = sorted(candidate_keys - expected_keys)
        details: list[str] = []
        if missing:
            details.append(
                "missing=" + ",".join(_render_claim_key(key) for key in missing)
            )
        if unexpected:
            details.append(
                "unexpected=" + ",".join(_render_claim_key(key) for key in unexpected)
            )
        raise DataHubDerivationValidationError(
            "DataHub evidence claim set does not match deterministic replay"
            + (": " + "; ".join(details) if details else "")
        )

    for key in sorted(expected_by_key):
        candidate_claim = candidate_by_key[key]
        expected_claim = expected_by_key[key]
        if (
            candidate_claim.claim_id != expected_claim.claim_id
            or candidate_claim.content_sha256 != expected_claim.content_sha256
        ):
            raise DataHubDerivationValidationError(
                "DataHub evidence claim content does not match deterministic replay: "
                + _render_claim_key(key)
            )

    if bundle.evidence_root_sha256 != expected.evidence_root_sha256:
        raise DataHubDerivationValidationError(
            "DataHub evidence root does not match deterministic replay"
        )

    observed_claim_ids = tuple(
        sorted(
            claim.claim_id
            for claim in bundle.claims
            if claim.derivation == DerivationKind.RUNTIME_OBSERVED
        )
    )
    mapped_claim_ids = tuple(
        sorted(
            claim.claim_id
            for claim in bundle.claims
            if claim.derivation == DerivationKind.EXPLICIT_MAPPING
        )
    )
    if len(observed_claim_ids) + len(mapped_claim_ids) != len(bundle.claims):
        raise DataHubDerivationValidationError(
            "DataHub evidence contains a derivation outside the validated partition"
        )

    freshness_policy_seconds = (
        expected.evidence_expires_at - expected.evidence_observed_at
        if isinstance(expected, DataHubDerivationValidation)
        else expected.expires_at - expected.observed_at
    ).total_seconds()
    payload = {
        "schema_version": "1.0",
        "validator_version": _VALIDATOR_VERSION,
        "evidence_root_sha256": bundle.evidence_root_sha256,
        "snapshot_sha256": bundle.snapshot_sha256,
        "source_identity": bundle.source_identity,
        "evidence_observed_at": _json_datetime(observed_at),
        "evidence_expires_at": _json_datetime(expires_at),
        "freshness_policy_seconds": freshness_policy_seconds,
        "validated_at": _json_datetime(current),
        "observed_claim_ids": list(observed_claim_ids),
        "mapped_claim_ids": list(mapped_claim_ids),
    }
    digest = canonical_json_sha256(payload)
    return DataHubDerivationValidation(
        evidence_root_sha256=bundle.evidence_root_sha256,
        snapshot_sha256=bundle.snapshot_sha256,
        source_identity=bundle.source_identity,
        evidence_observed_at=observed_at,
        evidence_expires_at=expires_at,
        freshness_policy_seconds=freshness_policy_seconds,
        validated_at=current,
        observed_claim_ids=observed_claim_ids,
        mapped_claim_ids=mapped_claim_ids,
        validation_sha256=digest,
    )


def compute_datahub_derivation_validation_sha256(
    validation: DataHubDerivationValidation,
) -> str:
    """Recompute the canonical content hash for a validation artifact."""

    payload = validation.model_dump(mode="json", exclude={"validation_sha256"})
    return canonical_json_sha256(payload)


def _index_claims(
    claims: tuple[EvidenceClaim, ...],
    *,
    label: str,
) -> dict[ClaimKey, EvidenceClaim]:
    indexed: dict[ClaimKey, EvidenceClaim] = {}
    for claim in claims:
        key = _claim_key(claim)
        if key in indexed:
            raise DataHubDerivationValidationError(
                f"{label} DataHub evidence contains duplicate semantic claim: "
                + _render_claim_key(key)
            )
        indexed[key] = claim
    return indexed


def _claim_key(claim: EvidenceClaim) -> ClaimKey:
    return claim.subject, claim.predicate


def _render_claim_key(key: ClaimKey) -> str:
    subject, predicate = key
    return f"{subject!r}/{predicate!r}"


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("DataHub derivation validation timestamps must be timezone-aware")
    return value.astimezone(timezone.utc)


def _json_datetime(value: datetime) -> str:
    return _utc(value).isoformat().replace("+00:00", "Z")
