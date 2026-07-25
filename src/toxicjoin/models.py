"""Core domain models for ToxicJoin.

The policy engine consumes these models and returns deterministic, auditable
outcomes. They intentionally contain metadata and query structure only; raw
warehouse rows do not belong in this layer.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    """Base model that rejects unknown fields to keep receipts trustworthy."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class Decision(StrEnum):
    ALLOW = "ALLOW"
    REWRITE = "REWRITE"
    BLOCK = "BLOCK"


class SensitivityCategory(StrEnum):
    DIRECT_IDENTIFIER = "DIRECT_IDENTIFIER"
    STABLE_PSEUDONYM = "STABLE_PSEUDONYM"
    QUASI_IDENTIFIER = "QUASI_IDENTIFIER"
    SENSITIVE_ATTRIBUTE = "SENSITIVE_ATTRIBUTE"
    PUBLIC_OR_LOW_RISK = "PUBLIC_OR_LOW_RISK"
    UNCLASSIFIED = "UNCLASSIFIED"


class ReasonCode(StrEnum):
    DIRECT_SENSITIVE_LINKAGE = "DIRECT_SENSITIVE_LINKAGE"
    COMPOSITIONAL_REIDENTIFICATION_RISK = "COMPOSITIONAL_REIDENTIFICATION_RISK"
    CUMULATIVE_DISCLOSURE_RISK = "CUMULATIVE_DISCLOSURE_RISK"
    DISCLOSURE_STATE_UNAVAILABLE = "DISCLOSURE_STATE_UNAVAILABLE"
    SMALL_GROUP_RISK = "SMALL_GROUP_RISK"
    UNRESOLVED_DATASET = "UNRESOLVED_DATASET"
    UNRESOLVED_COLUMN = "UNRESOLVED_COLUMN"
    UNCLASSIFIED_COLUMN = "UNCLASSIFIED_COLUMN"
    UNSUPPORTED_STATEMENT = "UNSUPPORTED_STATEMENT"
    MULTIPLE_STATEMENTS = "MULTIPLE_STATEMENTS"
    AMBIGUOUS_COLUMN = "AMBIGUOUS_COLUMN"
    QUERY_COMPLEXITY_LIMIT = "QUERY_COMPLEXITY_LIMIT"
    RESULT_SIZE_LIMIT = "RESULT_SIZE_LIMIT"
    DATAHUB_UNAVAILABLE = "DATAHUB_UNAVAILABLE"
    DATAHUB_CONTEXT_STALE = "DATAHUB_CONTEXT_STALE"
    DATAHUB_CONTEXT_DRIFT = "DATAHUB_CONTEXT_DRIFT"
    REWRITE_FAILED = "REWRITE_FAILED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    NO_COMPOSITIONAL_RISK = "NO_COMPOSITIONAL_RISK"


class ColumnRef(StrictModel):
    dataset: str = Field(min_length=1)
    field_path: str = Field(min_length=1)
    alias: str | None = None

    @property
    def key(self) -> str:
        return f"{self.dataset}.{self.field_path}"


class LineageSource(StrictModel):
    """Governed upstream source that contributes to a materialized field."""

    ref: ColumnRef
    category: SensitivityCategory
    datahub_urn: str | None = None


class ProjectionExposureKind(StrEnum):
    """How a final projected value exposes its governed source lineage."""

    RAW_VALUE = "RAW_VALUE"
    TRANSFORMED_RAW_VALUE = "TRANSFORMED_RAW_VALUE"
    GROUP_KEY = "GROUP_KEY"
    AGGREGATE_OPERAND = "AGGREGATE_OPERAND"
    AGGREGATE_VALUE = "AGGREGATE_VALUE"
    CONDITIONAL_AGGREGATE = "CONDITIONAL_AGGREGATE"
    FILTER_ONLY = "FILTER_ONLY"
    JOIN_ONLY = "JOIN_ONLY"
    NESTED_SCOPE = "NESTED_SCOPE"


class ProjectionExposure(StrictModel):
    """Semantic lineage for one final output expression."""

    output_name: str = Field(min_length=1)
    kind: ProjectionExposureKind
    source_columns: tuple[ColumnRef, ...] = ()


class ColumnContext(StrictModel):
    ref: ColumnRef
    category: SensitivityCategory
    datahub_urn: str | None = None
    tags: tuple[str, ...] = ()
    glossary_terms: tuple[str, ...] = ()
    lineage_sources: tuple[LineageSource, ...] = ()
    resolved: bool = True

    @model_validator(mode="after")
    def validate_governed_context(self) -> "ColumnContext":
        if not self.resolved and self.category != SensitivityCategory.UNCLASSIFIED:
            raise ValueError("unresolved columns must use the UNCLASSIFIED category")
        source_keys = [source.ref.key for source in self.lineage_sources]
        if len(source_keys) != len(set(source_keys)):
            raise ValueError("lineage_sources must not contain duplicate governed columns")
        return self


class QueryPlan(StrictModel):
    statement_type: str
    source_datasets: tuple[str, ...]
    projected_columns: tuple[ColumnRef, ...]
    projected_exposures: tuple[ProjectionExposure, ...] = ()
    referenced_columns: tuple[ColumnRef, ...] = ()
    join_columns: tuple[ColumnRef, ...] = ()
    group_by_columns: tuple[ColumnRef, ...] = ()
    aggregate_functions: tuple[str, ...] = ()
    minimum_group_size_present: int | None = Field(default=None, ge=1)
    minimum_group_size_subject: ColumnRef | None = None
    is_grouped: bool = False
    contains_wildcard: bool = False
    analysis_warnings: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_query_plan_consistency(self) -> "QueryPlan":
        referenced = {column.key for column in self.referenced_columns}
        structural = {
            column.key
            for collection in (
                self.projected_columns,
                self.join_columns,
                self.group_by_columns,
            )
            for column in collection
        }
        if referenced and not structural.issubset(referenced):
            missing = sorted(structural - referenced)
            raise ValueError(
                "referenced_columns must include projected/join/group columns; "
                f"missing={missing}"
            )
        projected = {column.key for column in self.projected_columns}
        exposure_sources = {
            column.key
            for exposure in self.projected_exposures
            for column in exposure.source_columns
        }
        if projected and not exposure_sources.issubset(projected):
            missing = sorted(exposure_sources - projected)
            raise ValueError(
                "projected_exposures must reference projected_columns; "
                f"missing={missing}"
            )
        if (self.minimum_group_size_present is None) != (
            self.minimum_group_size_subject is None
        ):
            raise ValueError(
                "minimum_group_size_present and minimum_group_size_subject must be set together"
            )
        return self


class PolicyInput(StrictModel):
    task_purpose: str = Field(min_length=1)
    query_plan: QueryPlan
    projected_context: tuple[ColumnContext, ...]
    all_referenced_context: tuple[ColumnContext, ...]
    subject_key: ColumnRef | None = None
    minimum_group_size_present: int | None = Field(default=None, ge=1)
    upstream_failures: tuple[ReasonCode, ...] = ()


class PolicyDecision(StrictModel):
    decision: Decision
    reason_codes: tuple[ReasonCode, ...]
    policy_version: str
    evidence: dict[str, Any]
    rewrite_required: bool = False

    @model_validator(mode="after")
    def decision_and_rewrite_flag_match(self) -> "PolicyDecision":
        if self.decision == Decision.REWRITE and not self.rewrite_required:
            raise ValueError("REWRITE decisions must set rewrite_required=true")
        if self.decision != Decision.REWRITE and self.rewrite_required:
            raise ValueError("only REWRITE decisions may require a rewrite")
        return self
