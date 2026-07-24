"""Strict models for persistent cross-request disclosure history.

The ledger records governed semantic metadata only. Raw rows, SQL text, raw-query
hashes, literal values, API keys, task prompts, output aliases, and caller-controlled
session identifiers do not belong in this layer.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any, Literal

from pydantic import Field, field_validator, model_validator

from toxicjoin.models import ProjectionExposureKind, SensitivityCategory, StrictModel


_HASH_PATTERN = r"^[0-9a-f]{64}$"
_RECORD_ID_PATTERN = r"^dl_[0-9a-f]{32}$"
_RECEIPT_ID_PATTERN = r"^tj_[0-9a-f]{16}$"
_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$"
_SUBJECT_CATEGORIES = {
    SensitivityCategory.DIRECT_IDENTIFIER,
    SensitivityCategory.STABLE_PSEUDONYM,
}


class CompositionRule(StrEnum):
    UNPROTECTED_RELEASE = "UNPROTECTED_RELEASE"
    FIRST_PROTECTED_RELEASE = "FIRST_PROTECTED_RELEASE"
    REPEAT_IDENTICAL_RELEASE = "REPEAT_IDENTICAL_RELEASE"
    IDEMPOTENT_REPLAY = "IDEMPOTENT_REPLAY"
    CUMULATIVE_VARIATION_BLOCK = "CUMULATIVE_VARIATION_BLOCK"
    LEGACY_HISTORY_BLOCK = "LEGACY_HISTORY_BLOCK"


class GovernedColumn(StrictModel):
    """One governed source column without raw warehouse values."""

    dataset_urn: str = Field(min_length=1, max_length=2048)
    field_path: str = Field(min_length=1, max_length=512)
    category: SensitivityCategory

    @property
    def key(self) -> str:
        return f"{self.dataset_urn}#{self.field_path}"


class GovernedSubjectDomain(StrictModel):
    """Conservative subject namespace shared across datasets for the same identifier."""

    field_path: str = Field(min_length=1, max_length=512)
    category: SensitivityCategory
    dataset_urns: tuple[str, ...] = Field(min_length=1, max_length=64)
    governance_domains: tuple[str, ...] = Field(default=(), max_length=64)
    namespace_sha256: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_subject_domain(self) -> "GovernedSubjectDomain":
        if self.category not in _SUBJECT_CATEGORIES:
            raise ValueError("subject domain must be a governed identifier category")
        if self.dataset_urns != tuple(sorted(set(self.dataset_urns))):
            raise ValueError("dataset_urns must be sorted and unique")
        if self.governance_domains != tuple(sorted(set(self.governance_domains))):
            raise ValueError("governance_domains must be sorted and unique")
        expected = compute_subject_namespace_sha256(self.field_path, self.category)
        if self.namespace_sha256 != expected:
            raise ValueError("subject namespace hash mismatch")
        return self


class DisclosureScope(StrictModel):
    """Privacy-history scope. Credentials and sessions intentionally do not partition it."""

    principal_id: str = Field(pattern=_IDENTIFIER_PATTERN)
    agent_id: str | None = Field(default=None, pattern=_IDENTIFIER_PATTERN)
    subject: GovernedSubjectDomain
    scope_sha256: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_scope_hash(self) -> "DisclosureScope":
        expected = compute_scope_sha256(
            principal_id=self.principal_id,
            agent_id=self.agent_id,
            subject_namespace_sha256=self.subject.namespace_sha256,
        )
        if self.scope_sha256 != expected:
            raise ValueError("disclosure scope hash mismatch")
        return self


class DisclosureAuditIdentity(StrictModel):
    """Administrator-controlled credential audit metadata outside privacy partitioning."""

    credential_id: str = Field(pattern=_IDENTIFIER_PATTERN)


class SemanticOutput(StrictModel):
    """One released semantic exposure and its governed source lineage."""

    kind: ProjectionExposureKind
    sources: tuple[GovernedColumn, ...] = Field(default=(), max_length=128)

    @model_validator(mode="after")
    def sources_are_canonical(self) -> "SemanticOutput":
        keys = tuple(source.key for source in self.sources)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("semantic output sources must be sorted and unique")
        return self


class DisclosureSemanticRelease(StrictModel):
    """Semantic information released by one query, independent of caller-controlled names."""

    source_dataset_urns: tuple[str, ...] = Field(min_length=1, max_length=64)
    outputs: tuple[SemanticOutput, ...] = Field(default=(), max_length=256)
    referenced_columns: tuple[GovernedColumn, ...] = Field(default=(), max_length=512)
    join_columns: tuple[GovernedColumn, ...] = Field(default=(), max_length=128)
    group_keys: tuple[GovernedColumn, ...] = Field(default=(), max_length=128)
    aggregate_functions: tuple[str, ...] = Field(default=(), max_length=64)
    minimum_group_size_present: int | None = Field(default=None, ge=1)
    semantic_sha256: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_semantic_release(self) -> "DisclosureSemanticRelease":
        if self.source_dataset_urns != tuple(sorted(set(self.source_dataset_urns))):
            raise ValueError("source_dataset_urns must be sorted and unique")
        for name, columns in (
            ("referenced_columns", self.referenced_columns),
            ("join_columns", self.join_columns),
            ("group_keys", self.group_keys),
        ):
            keys = tuple(column.key for column in columns)
            if keys != tuple(sorted(set(keys))):
                raise ValueError(f"{name} must be sorted and unique")
        normalized_aggregates = tuple(
            sorted(set(value.strip().upper() for value in self.aggregate_functions))
        )
        if self.aggregate_functions != normalized_aggregates:
            raise ValueError("aggregate_functions must be normalized, sorted, and unique")
        expected = compute_semantic_sha256(self)
        if self.semantic_sha256 != expected:
            raise ValueError("semantic release hash mismatch")
        return self


class DisclosureComposition(StrictModel):
    """Keyed cohort identity and semantic family used by the cumulative-release gate."""

    protected_release: bool
    release_family_sha256: str = Field(pattern=_HASH_PATTERN)
    cohort_hmac_sha256: str = Field(pattern=_HASH_PATTERN)


class DisclosureEvent(StrictModel):
    """Minimal governed payload eligible for append-only persistence."""

    scope: DisclosureScope
    audit_identity: DisclosureAuditIdentity
    receipt_id: str = Field(pattern=_RECEIPT_ID_PATTERN)
    policy_version: str = Field(min_length=1, max_length=128)
    semantic: DisclosureSemanticRelease
    composition: DisclosureComposition | None = None

    @model_validator(mode="after")
    def composition_matches_semantic_family(self) -> "DisclosureEvent":
        if (
            self.composition is not None
            and self.composition.release_family_sha256 != self.semantic.semantic_sha256
        ):
            raise ValueError("composition release family must match semantic release hash")
        return self


class DisclosureRecord(StrictModel):
    """Persisted append-only ledger record with per-scope hash chaining."""

    schema_version: Literal["1.0", "1.1"] = "1.1"
    record_id: str = Field(pattern=_RECORD_ID_PATTERN)
    sequence: int = Field(ge=1)
    created_at: datetime
    event: DisclosureEvent
    event_sha256: str = Field(pattern=_HASH_PATTERN)
    previous_content_sha256: str | None = Field(default=None, pattern=_HASH_PATTERN)
    content_sha256: str = Field(pattern=_HASH_PATTERN)

    @field_validator("created_at")
    @classmethod
    def created_at_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_hashes(self) -> "DisclosureRecord":
        if self.event_sha256 != compute_event_sha256(self.event):
            raise ValueError("disclosure event hash mismatch")
        if self.content_sha256 != compute_record_sha256(self):
            raise ValueError("disclosure record content hash mismatch")
        return self


class DisclosureCommitment(StrictModel):
    """Opaque proof that one exact governed release was committed before execution."""

    record_id: str = Field(pattern=_RECORD_ID_PATTERN)
    receipt_id: str = Field(pattern=_RECEIPT_ID_PATTERN)
    scope_sha256: str = Field(pattern=_HASH_PATTERN)
    event_sha256: str = Field(pattern=_HASH_PATTERN)
    content_sha256: str = Field(pattern=_HASH_PATTERN)


class DisclosureCompositionDecision(StrictModel):
    """Result of atomic cumulative-history evaluation and optional append."""

    allowed: bool
    rule: CompositionRule
    protected_release: bool
    prior_protected_count: int = Field(ge=0)
    commitment: DisclosureCommitment | None = None

    @model_validator(mode="after")
    def commitment_matches_allow_state(self) -> "DisclosureCompositionDecision":
        if self.allowed != (self.commitment is not None):
            raise ValueError("allowed composition decisions require exactly one commitment")
        return self


def compute_subject_namespace_sha256(
    field_path: str,
    category: SensitivityCategory,
) -> str:
    """Hash the conservative cross-dataset subject namespace."""

    return _hash_json(
        {
            "field_path": field_path.casefold(),
            "category": category.value,
        }
    )


def compute_scope_sha256(
    *,
    principal_id: str,
    agent_id: str | None,
    subject_namespace_sha256: str,
) -> str:
    """Hash privacy scope without credential/session IDs to prevent rotation bypasses."""

    return _hash_json(
        {
            "principal_id": principal_id,
            "agent_id": agent_id or "@principal",
            "subject_namespace_sha256": subject_namespace_sha256,
        }
    )


def compute_semantic_sha256(release: DisclosureSemanticRelease) -> str:
    """Hash governed release semantics without caller-controlled output aliases."""

    output_signatures = {
        _hash_json(
            {
                "kind": output.kind.value,
                "sources": [_column_payload(source) for source in output.sources],
            }
        )
        for output in release.outputs
    }
    payload = {
        "source_dataset_urns": list(release.source_dataset_urns),
        "outputs": sorted(output_signatures),
        "referenced_columns": [
            _column_payload(column) for column in release.referenced_columns
        ],
        "join_columns": [_column_payload(column) for column in release.join_columns],
        "group_keys": [_column_payload(column) for column in release.group_keys],
        "aggregate_functions": list(release.aggregate_functions),
        "minimum_group_size_present": release.minimum_group_size_present,
    }
    return _hash_json(payload)


def compute_event_sha256(event: DisclosureEvent) -> str:
    return _hash_json(event.model_dump(mode="json"))


def compute_record_sha256(record: DisclosureRecord) -> str:
    payload = record.model_dump(mode="json", exclude={"content_sha256"})
    return _hash_json(payload)


def _column_payload(column: GovernedColumn) -> dict[str, str]:
    return {
        "dataset_urn": column.dataset_urn,
        "field_path": column.field_path,
        "category": column.category.value,
    }


def _hash_json(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
