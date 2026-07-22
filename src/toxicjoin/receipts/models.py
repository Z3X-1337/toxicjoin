"""Strict schema for immutable ToxicJoin decision receipts.

Receipts contain governed metadata and deterministic execution summaries only. Raw
query rows, warehouse values, secrets, unredacted literals, and variable timing data
are intentionally absent.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import Field, field_validator, model_validator

from toxicjoin.models import Decision, ReasonCode, SensitivityCategory, StrictModel


class ReceiptMode(StrEnum):
    FIXTURE = "fixture"
    LIVE = "live"
    REPLAY = "replay"


class WritebackState(StrEnum):
    NOT_ATTEMPTED = "not_attempted"
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"


class ReceiptSqlEvidence(StrictModel):
    original_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    safe_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    sanitized_original: str | None = None
    sanitized_safe: str | None = None

    @model_validator(mode="after")
    def safe_fields_are_consistent(self) -> "ReceiptSqlEvidence":
        if self.safe_sha256 is None and self.sanitized_safe is not None:
            raise ValueError("sanitized_safe requires safe_sha256")
        return self


class ReceiptColumnEvidence(StrictModel):
    dataset: str = Field(min_length=1)
    field_path: str = Field(min_length=1)
    category: SensitivityCategory
    datahub_urn: str | None = None
    tags: tuple[str, ...] = ()
    glossary_terms: tuple[str, ...] = ()
    resolved: bool

    @property
    def key(self) -> str:
        return f"{self.dataset}.{self.field_path}"


class ReceiptVerificationCheck(StrictModel):
    name: str = Field(min_length=1)
    passed: bool
    detail: str = Field(min_length=1)


class ReceiptExecutionSummary(StrictModel):
    query_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    columns: tuple[str, ...]
    preview_row_count: int = Field(ge=0)
    truncated: bool


class ReceiptWriteback(StrictModel):
    state: WritebackState = WritebackState.NOT_ATTEMPTED
    target_urns: tuple[str, ...] = ()
    document_urn: str | None = None
    verified_at: datetime | None = None
    error_code: str | None = None

    @field_validator("verified_at")
    @classmethod
    def verified_at_must_be_timezone_aware(
        cls,
        value: datetime | None,
    ) -> datetime | None:
        if value is not None and value.tzinfo is None:
            raise ValueError("verified_at must be timezone-aware")
        return value

    @model_validator(mode="after")
    def state_fields_are_consistent(self) -> "ReceiptWriteback":
        if self.state == WritebackState.VERIFIED and self.verified_at is None:
            raise ValueError("verified write-back requires verified_at")
        if self.state == WritebackState.FAILED and not self.error_code:
            raise ValueError("failed write-back requires error_code")
        if self.state != WritebackState.FAILED and self.error_code is not None:
            raise ValueError("error_code is valid only for failed write-back")
        return self


class DecisionReceipt(StrictModel):
    schema_version: str = "1.0"
    receipt_id: str = Field(pattern=r"^tj_[0-9a-f]{16}$")
    created_at: datetime
    mode: ReceiptMode
    task_purpose: str = Field(min_length=1)
    initial_decision: Decision
    initial_reason_codes: tuple[ReasonCode, ...]
    initial_evidence: dict[str, Any] = Field(default_factory=dict)
    final_decision: Decision | None = None
    final_reason_codes: tuple[ReasonCode, ...] = ()
    final_evidence: dict[str, Any] = Field(default_factory=dict)
    policy_version: str = Field(min_length=1)
    sql: ReceiptSqlEvidence
    columns: tuple[ReceiptColumnEvidence, ...]
    verification: tuple[ReceiptVerificationCheck, ...] = ()
    execution: ReceiptExecutionSummary | None = None
    writeback: ReceiptWriteback = Field(default_factory=ReceiptWriteback)
    content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("created_at")
    @classmethod
    def created_at_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def lifecycle_is_consistent(self) -> "DecisionReceipt":
        effective_decision = self.final_decision or self.initial_decision
        if self.final_decision is None and (self.final_reason_codes or self.final_evidence):
            raise ValueError("final reason codes and evidence require final_decision")
        if (
            self.initial_decision == Decision.REWRITE
            and effective_decision == Decision.ALLOW
            and self.sql.safe_sha256 is None
        ):
            raise ValueError("successful REWRITE receipts require safe SQL evidence")
        if self.execution is not None:
            if effective_decision != Decision.ALLOW:
                raise ValueError("execution summary is allowed only for an effective ALLOW")
            if not self.verification or not all(check.passed for check in self.verification):
                raise ValueError("execution summary requires all verification checks to pass")
        return self
