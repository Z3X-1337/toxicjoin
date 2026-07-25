"""Deterministic EvidenceClaim issuance from validated DataHub snapshots.

This module is intentionally an adapter, not an authorization path. It converts the
already-normalized ``DataHubSnapshot`` into canonical evidence artifacts while binding
all derived claims to one exact snapshot commitment and one redacted configured source
identity. The resulting bundle is suitable for later deterministic resolution, but this
module does not itself authorize execution.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Literal
from urllib.parse import urlsplit, urlunsplit

from pydantic import Field, field_validator, model_validator

from toxicjoin.context.datahub import DataHubSnapshot
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.evidence.models import (
    DerivationKind,
    EvidenceClaim,
    EvidenceSource,
    build_evidence_claim,
)
from toxicjoin.integrations.datahub_mcp import DataHubMcpSettings
from toxicjoin.models import SensitivityCategory, StrictModel


_HASH_PATTERN = r"^[0-9a-f]{64}$"
_DEFAULT_EVIDENCE_TTL_SECONDS = 300.0
_MAX_EVIDENCE_TTL_SECONDS = 3600.0
_MAX_CLAIM_VALUE_LENGTH = 4096
_ALLOWED_DERIVATIONS = {
    DerivationKind.RUNTIME_OBSERVED,
    DerivationKind.EXPLICIT_MAPPING,
}


class DataHubEvidenceError(RuntimeError):
    """Raised when a DataHub snapshot cannot be represented safely as evidence."""


class DataHubEvidenceBundle(StrictModel):
    """Canonical claims issued from one exact DataHub governance snapshot."""

    schema_version: Literal["1.0"] = "1.0"
    source_identity: str = Field(min_length=1, max_length=2048)
    snapshot_sha256: str = Field(pattern=_HASH_PATTERN)
    catalog_version: str = Field(min_length=1, max_length=512)
    observed_at: datetime
    expires_at: datetime
    claims: tuple[EvidenceClaim, ...] = Field(min_length=1)
    evidence_root_sha256: str = Field(pattern=_HASH_PATTERN)

    @field_validator("observed_at", "expires_at")
    @classmethod
    def timestamps_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("DataHub evidence timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_bundle(self) -> "DataHubEvidenceBundle":
        if self.expires_at <= self.observed_at:
            raise ValueError("DataHub evidence expires_at must follow observed_at")

        ordered = tuple(sorted(self.claims, key=lambda claim: claim.claim_id))
        if self.claims != ordered:
            raise ValueError("DataHub evidence claims must be sorted by claim_id")
        if len({claim.claim_id for claim in self.claims}) != len(self.claims):
            raise ValueError("DataHub evidence claims must be unique")

        roots = [
            claim
            for claim in self.claims
            if claim.subject == self.source_identity
            and claim.predicate == "datahub.snapshot_sha256"
            and claim.value == self.snapshot_sha256
            and claim.derivation == DerivationKind.RUNTIME_OBSERVED
        ]
        if len(roots) != 1:
            raise ValueError("DataHub evidence requires exactly one snapshot root claim")
        root = roots[0]

        for claim in self.claims:
            if claim.source != EvidenceSource.DATAHUB_MCP:
                raise ValueError("DataHub evidence bundle contains a non-DataHub source")
            if claim.derivation not in _ALLOWED_DERIVATIONS:
                raise ValueError("DataHub evidence claim uses an unsupported derivation")
            if claim.source_identity != self.source_identity:
                raise ValueError("DataHub evidence source identity mismatch")
            if claim.observed_at != self.observed_at or claim.expires_at != self.expires_at:
                raise ValueError("DataHub evidence claim freshness binding mismatch")
            if claim.claim_id == root.claim_id:
                if claim.supporting_claim_ids:
                    raise ValueError("DataHub snapshot root claim must not depend on another claim")
            elif root.claim_id not in claim.supporting_claim_ids:
                raise ValueError("DataHub evidence claims must depend on the snapshot root claim")

        expected_root = compute_datahub_evidence_root(self)
        if self.evidence_root_sha256 != expected_root:
            raise ValueError("DataHub evidence root hash mismatch")
        return self


def datahub_source_identity(settings: DataHubMcpSettings) -> str:
    """Return a redacted commitment to the configured DataHub read path.

    The identity commits to the normalized GMS endpoint plus MCP launcher command and
    arguments while exposing neither the endpoint nor the GMS token. It is a local
    configuration identity, not remote-code attestation or proof that DataHub metadata is
    objectively true.
    """

    endpoint = _normalize_gms_endpoint(settings.gms_url)
    endpoint_sha256 = canonical_json_sha256({"gms_endpoint": endpoint})
    launcher_sha256 = canonical_json_sha256(
        {
            "command": settings.command,
            "args": list(settings.args),
        }
    )
    return (
        "datahub-mcp:"
        f"gms_sha256={endpoint_sha256}|launcher_sha256={launcher_sha256}"
    )


def build_datahub_evidence_bundle(
    snapshot: DataHubSnapshot,
    settings: DataHubMcpSettings,
    *,
    max_age_seconds: float = _DEFAULT_EVIDENCE_TTL_SECONDS,
) -> DataHubEvidenceBundle:
    """Issue canonical evidence claims from one validated DataHub snapshot."""

    if max_age_seconds <= 0 or max_age_seconds > _MAX_EVIDENCE_TTL_SECONDS:
        raise ValueError(
            "DataHub evidence max age must be in "
            f"(0, {_MAX_EVIDENCE_TTL_SECONDS:g}] seconds"
        )

    source_identity = datahub_source_identity(settings)
    observed_at = snapshot.observed_at.astimezone(timezone.utc)
    expires_at = observed_at + timedelta(seconds=float(max_age_seconds))

    root = build_evidence_claim(
        subject=source_identity,
        predicate="datahub.snapshot_sha256",
        value=snapshot.snapshot_sha256,
        source=EvidenceSource.DATAHUB_MCP,
        derivation=DerivationKind.RUNTIME_OBSERVED,
        source_identity=source_identity,
        observed_at=observed_at,
        expires_at=expires_at,
    )

    claims: list[EvidenceClaim] = [root]
    root_support = (root.claim_id,)
    claims.append(
        _claim(
            subject=source_identity,
            predicate="datahub.catalog_version",
            value=snapshot.catalog.version,
            source_identity=source_identity,
            observed_at=observed_at,
            expires_at=expires_at,
            supporting_claim_ids=root_support,
        )
    )

    for logical_name, dataset in sorted(snapshot.catalog.datasets.items()):
        dataset_subject = dataset.urn
        claims.append(
            _claim(
                subject=dataset_subject,
                predicate="datahub.logical_name",
                value=logical_name,
                source_identity=source_identity,
                observed_at=observed_at,
                expires_at=expires_at,
                supporting_claim_ids=root_support,
                derivation=DerivationKind.EXPLICIT_MAPPING,
            )
        )
        if dataset.owner is not None:
            claims.append(
                _claim(
                    subject=dataset_subject,
                    predicate="datahub.owner",
                    value=dataset.owner,
                    source_identity=source_identity,
                    observed_at=observed_at,
                    expires_at=expires_at,
                    supporting_claim_ids=root_support,
                )
            )
        if dataset.domain is not None:
            claims.append(
                _claim(
                    subject=dataset_subject,
                    predicate="datahub.domain",
                    value=dataset.domain,
                    source_identity=source_identity,
                    observed_at=observed_at,
                    expires_at=expires_at,
                    supporting_claim_ids=root_support,
                )
            )

        for field_path, field in sorted(dataset.fields.items()):
            field_subject = f"{dataset.urn}#{field_path}"
            tags_claim = _claim(
                subject=field_subject,
                predicate="datahub.tags",
                value=_compact_json(field.tags),
                source_identity=source_identity,
                observed_at=observed_at,
                expires_at=expires_at,
                supporting_claim_ids=root_support,
            )
            glossary_claim = _claim(
                subject=field_subject,
                predicate="datahub.glossary_terms",
                value=_compact_json(field.glossary_terms),
                source_identity=source_identity,
                observed_at=observed_at,
                expires_at=expires_at,
                supporting_claim_ids=root_support,
            )
            claims.extend((tags_claim, glossary_claim))

            classification_complete = field.category != SensitivityCategory.UNCLASSIFIED
            classification_support = tuple(
                sorted((root.claim_id, tags_claim.claim_id, glossary_claim.claim_id))
            )
            claims.append(
                _claim(
                    subject=field_subject,
                    predicate="toxicjoin.sensitivity_category",
                    value=field.category.value,
                    source_identity=source_identity,
                    observed_at=observed_at,
                    expires_at=expires_at,
                    supporting_claim_ids=classification_support,
                    complete=classification_complete,
                    derivation=DerivationKind.EXPLICIT_MAPPING,
                )
            )

            transport_complete = all(
                source.ref.dataset != "@datahub-lineage"
                for source in field.lineage_sources
            )
            governance_complete = all(
                source.category != SensitivityCategory.UNCLASSIFIED
                for source in field.lineage_sources
            )
            claims.append(
                _claim(
                    subject=field_subject,
                    predicate="datahub.lineage_transport_complete",
                    value=_bool_value(transport_complete),
                    source_identity=source_identity,
                    observed_at=observed_at,
                    expires_at=expires_at,
                    supporting_claim_ids=root_support,
                    derivation=DerivationKind.EXPLICIT_MAPPING,
                )
            )
            claims.append(
                _claim(
                    subject=field_subject,
                    predicate="toxicjoin.lineage_governance_complete",
                    value=_bool_value(governance_complete),
                    source_identity=source_identity,
                    observed_at=observed_at,
                    expires_at=expires_at,
                    supporting_claim_ids=root_support,
                    derivation=DerivationKind.EXPLICIT_MAPPING,
                )
            )

            for lineage_source in sorted(
                field.lineage_sources,
                key=lambda source: source.ref.key,
            ):
                edge_subject = _lineage_edge_subject(field_subject, lineage_source.ref.key)
                lineage_complete = (
                    lineage_source.category != SensitivityCategory.UNCLASSIFIED
                )
                claims.append(
                    _claim(
                        subject=edge_subject,
                        predicate="datahub.lineage_source_ref",
                        value=lineage_source.ref.key,
                        source_identity=source_identity,
                        observed_at=observed_at,
                        expires_at=expires_at,
                        supporting_claim_ids=root_support,
                        complete=lineage_complete,
                    )
                )
                claims.append(
                    _claim(
                        subject=edge_subject,
                        predicate="toxicjoin.lineage_source_category",
                        value=lineage_source.category.value,
                        source_identity=source_identity,
                        observed_at=observed_at,
                        expires_at=expires_at,
                        supporting_claim_ids=root_support,
                        complete=lineage_complete,
                        derivation=DerivationKind.EXPLICIT_MAPPING,
                    )
                )
                if lineage_source.datahub_urn is not None:
                    claims.append(
                        _claim(
                            subject=edge_subject,
                            predicate="datahub.lineage_source_urn",
                            value=lineage_source.datahub_urn,
                            source_identity=source_identity,
                            observed_at=observed_at,
                            expires_at=expires_at,
                            supporting_claim_ids=root_support,
                            complete=lineage_complete,
                        )
                    )

    ordered_claims = tuple(sorted(claims, key=lambda claim: claim.claim_id))
    payload = {
        "schema_version": "1.0",
        "source_identity": source_identity,
        "snapshot_sha256": snapshot.snapshot_sha256,
        "catalog_version": snapshot.catalog.version,
        "observed_at": _json_datetime(observed_at),
        "expires_at": _json_datetime(expires_at),
        "claim_sha256s": [claim.content_sha256 for claim in ordered_claims],
    }
    evidence_root = canonical_json_sha256(payload)
    return DataHubEvidenceBundle(
        source_identity=source_identity,
        snapshot_sha256=snapshot.snapshot_sha256,
        catalog_version=snapshot.catalog.version,
        observed_at=observed_at,
        expires_at=expires_at,
        claims=ordered_claims,
        evidence_root_sha256=evidence_root,
    )


def compute_datahub_evidence_root(bundle: DataHubEvidenceBundle) -> str:
    """Recompute the canonical evidence-root commitment for a bundle."""

    payload = {
        "schema_version": bundle.schema_version,
        "source_identity": bundle.source_identity,
        "snapshot_sha256": bundle.snapshot_sha256,
        "catalog_version": bundle.catalog_version,
        "observed_at": _json_datetime(bundle.observed_at),
        "expires_at": _json_datetime(bundle.expires_at),
        "claim_sha256s": [claim.content_sha256 for claim in bundle.claims],
    }
    return canonical_json_sha256(payload)


def _claim(
    *,
    subject: str,
    predicate: str,
    value: str,
    source_identity: str,
    observed_at: datetime,
    expires_at: datetime,
    supporting_claim_ids: tuple[str, ...],
    complete: bool = True,
    derivation: DerivationKind = DerivationKind.RUNTIME_OBSERVED,
) -> EvidenceClaim:
    if len(value) > _MAX_CLAIM_VALUE_LENGTH:
        raise DataHubEvidenceError(
            f"DataHub evidence value for {predicate} exceeds model limit"
        )
    return build_evidence_claim(
        subject=subject,
        predicate=predicate,
        value=value,
        source=EvidenceSource.DATAHUB_MCP,
        derivation=derivation,
        source_identity=source_identity,
        observed_at=observed_at,
        expires_at=expires_at,
        complete=complete,
        supporting_claim_ids=supporting_claim_ids,
    )


def _normalize_gms_endpoint(value: str) -> str:
    parts = urlsplit(value)
    if parts.username is not None or parts.password is not None:
        raise DataHubEvidenceError("DataHub GMS URL must not contain userinfo")
    if parts.query or parts.fragment:
        raise DataHubEvidenceError("DataHub GMS URL must not contain query or fragment")
    hostname = parts.hostname
    if hostname is None:
        raise DataHubEvidenceError("DataHub GMS URL must contain a hostname")
    try:
        port = parts.port
    except ValueError as exc:
        raise DataHubEvidenceError("DataHub GMS URL contains an invalid port") from exc

    host = hostname.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    default_port = 443 if parts.scheme.lower() == "https" else 80
    netloc = host if port is None or port == default_port else f"{host}:{port}"
    path = parts.path.rstrip("/")
    return urlunsplit((parts.scheme.lower(), netloc, path, "", ""))


def _compact_json(values: tuple[str, ...]) -> str:
    rendered = json.dumps(
        list(values),
        ensure_ascii=True,
        separators=(",", ":"),
    )
    if len(rendered) > _MAX_CLAIM_VALUE_LENGTH:
        raise DataHubEvidenceError("DataHub metadata list exceeds evidence value limit")
    return rendered


def _lineage_edge_subject(target_subject: str, source_ref: str) -> str:
    digest = hashlib.sha256(
        f"{target_subject}\x00{source_ref}".encode("utf-8")
    ).hexdigest()[:32]
    subject = f"{target_subject}::lineage::{digest}"
    if len(subject) > 2048:
        raise DataHubEvidenceError("DataHub lineage evidence subject exceeds model limit")
    return subject


def _bool_value(value: bool) -> str:
    return "true" if value else "false"


def _json_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
