"""Stable public API contracts for ToxicJoin."""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from toxicjoin.models import (
    ColumnRef,
    Decision,
    PolicyDecision,
    QueryPlan,
    StrictModel,
)
from toxicjoin.pipeline import PipelineRequest, PipelineResult
from toxicjoin.receipts import DecisionReceipt, ReceiptMode
from toxicjoin.verify import VerificationResult


class HealthResponse(StrictModel):
    status: Literal["ok", "degraded"]
    version: str
    mode: ReceiptMode
    policy_version: str
    database_ready: bool
    receipt_store_ready: bool


class PipelineResponse(StrictModel):
    effective_decision: Decision
    initial_decision: PolicyDecision
    final_decision: PolicyDecision | None = None
    safe_sql: str | None = None
    original_plan: QueryPlan | None = None
    final_plan: QueryPlan | None = None
    verification: VerificationResult | None = None
    receipt: DecisionReceipt

    @classmethod
    def from_result(cls, result: PipelineResult) -> "PipelineResponse":
        return cls(
            effective_decision=result.effective_decision,
            initial_decision=result.initial_decision,
            final_decision=result.final_decision,
            safe_sql=result.safe_sql,
            original_plan=result.original_plan,
            final_plan=result.final_plan,
            verification=result.verification,
            receipt=result.receipt,
        )


class DemoScenario(StrictModel):
    scenario_id: str = Field(pattern=r"^[a-z0-9-]+$")
    title: str
    description: str
    request: PipelineRequest
    expected_initial_decision: Decision
    expected_effective_decision: Decision


class DemoScenarioList(StrictModel):
    scenarios: tuple[DemoScenario, ...]


class ReceiptLookup(StrictModel):
    receipt_id: str = Field(pattern=r"^tj_[0-9a-f]{16}$")


DEFAULT_SUBJECT_KEY = ColumnRef(
    dataset="customers",
    field_path="customer_id",
    alias="c",
)
