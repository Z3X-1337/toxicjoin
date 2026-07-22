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
    SMALL_GROUP_RISK = "SMALL_GROUP_RISK"
    UNRESOLVED_DATASET = "UNRESOLVED_DATASET"
    UNRESOLVED_COLUMN = "UNRESOLVED_COLUMN"
    UNCLASSIFIED_COLUMN = "UNCLASSIFIED_COLUMN"
    UNSUPPORTED_STATEMENT = "UNSUPPORTED_STATEMENT"
    MULTIPLE_STATEMENTS = "MULTIPLE_STATEMENTS"
    AMBIGUOUS_COLUMN = "AMBIGUOUS_COLUMN"
    DATAHUB_UNAVAILABLE = "DATAHUB_UNAVAILABLE"
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


class ColumnContext(StrictModel):
    ref: ColumnRef
    category: SensitivityCategory
    datahub_urn: str | None = None
    tags: tuple[str, ...] = ()
    glossary_terms: tuple[str, ...] = ()
    resolved: bool = True

    @model_validator(mode="after")
    def unresolved_columns_are_unclassified(self) -> "ColumnContext":
        if not self.resolved and self.category != SensitivityCategory.UNCLASSIFIED:
            raise ValueError("unresolved columns must use the UNCLASSIFIED category")
        return self


class QueryPlan(StrictModel):
    statement_type: str
    source_datasets: tuple[str, ...]
    projected_columns: tuple[ColumnRef, ...]
    referenced_columns: tuple[ColumnRef, ...] = ()
    join_columns: tuple[ColumnRef, ...] = ()
    group_by_columns: tuple[ColumnRef, ...] = ()
    aggregate_functions: tuple[str, ...] = ()
    minimum_group_size_present: int | None = Field(default=None, ge=1)
    is_grouped: bool = False
    contains_wildcard: bool = False
    analysis_warnings: tuple[str, ...] = ()

    @model_validator(mode="after")
    def referenced_columns_cover_structural_columns(self) -> "QueryPlan":
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
