"""The Governed Agent loop on the executable path.

The security property is not that the agent writes good SQL — it is that a bad proposal
cannot become a release. These tests drive real decisions through the real pipeline and assert
on rows, not on labels.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from toxicjoin.agent.governed import AgentProposalError
from toxicjoin.agent.models import AgentDraft
from toxicjoin.agent.runtime import (
    GovernedAgentSession,
    build_agent_context_from_catalog,
)
from toxicjoin.api import create_app
from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog
from toxicjoin.execute import DuckDBExecutor
from toxicjoin.models import ColumnRef, Decision, ReasonCode, SensitivityCategory
from toxicjoin.pipeline import ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import ReceiptMode, ReceiptStore


SUBJECT = ColumnRef(dataset="customers", field_path="customer_id", alias="c")


@pytest.fixture
def pipeline(seeded_database: Path, tmp_path: Path) -> ToxicJoinPipeline:
    return ToxicJoinPipeline(
        context_resolver=FixtureContextResolver(default_fixture_catalog()),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(seeded_database),
    )


def _session(pipeline: ToxicJoinPipeline, planner=None) -> GovernedAgentSession:
    return GovernedAgentSession(
        pipeline=pipeline,
        catalog=default_fixture_catalog(),
        planner=planner,
    )


def test_planning_context_carries_governance_but_no_values() -> None:
    context = build_agent_context_from_catalog(default_fixture_catalog())

    assert context.security_authoritative is False
    names = {dataset.logical_name for dataset in context.datasets}
    assert {"customers", "orders", "retention_scores"} <= names

    customers = next(d for d in context.datasets if d.logical_name == "customers")
    subject = next(f for f in customers.fields if f.field_path == "customer_id")
    assert subject.category is SensitivityCategory.STABLE_PSEUDONYM
    assert all(field.security_authoritative is False for field in customers.fields)


def test_agent_is_refused_then_adapts_to_a_verified_release(
    pipeline: ToxicJoinPipeline,
) -> None:
    result = _session(pipeline).run(
        goal="Find regions with elevated churn risk",
        subject_key=SUBJECT,
    )

    assert result.succeeded is True
    assert result.final_decision == Decision.ALLOW
    assert len(result.attempts) >= 2

    first, last = result.attempts[0], result.attempts[-1]
    assert first.decision == Decision.BLOCK
    assert first.released_row_count is None
    assert ReasonCode.COMPOSITIONAL_REIDENTIFICATION_RISK in first.reason_codes
    assert last.decision == Decision.ALLOW
    assert last.released_row_count == 3


def test_every_attempt_produces_its_own_receipt(pipeline: ToxicJoinPipeline) -> None:
    """A refused attempt is still auditable; the agent cannot act without leaving a record."""

    result = _session(pipeline).run(
        goal="Find regions with elevated churn risk",
        subject_key=SUBJECT,
    )

    receipt_ids = [attempt.receipt_id for attempt in result.attempts]
    assert len(receipt_ids) == len(set(receipt_ids))
    assert all(receipt_id.startswith("tj_") for receipt_id in receipt_ids)


class _RelentlessPlanner:
    """A planner that never remediates, to prove refusal is terminal rather than negotiable."""

    UNSAFE_SQL = (
        "SELECT c.customer_id, c.age_band, c.precise_area, s.case_category "
        "FROM customers c JOIN support_cases s ON c.customer_id = s.customer_id"
    )

    def propose(self, *, goal, context) -> AgentDraft:
        del context
        return AgentDraft(task_purpose=goal.goal, sql=self.UNSAFE_SQL)

    def adapt(self, *, goal, context, previous, feedback) -> AgentDraft:
        del context, previous, feedback
        return AgentDraft(task_purpose=goal.goal, sql=self.UNSAFE_SQL)


def test_agent_that_never_remediates_exhausts_its_budget_without_releasing(
    pipeline: ToxicJoinPipeline,
) -> None:
    result = _session(pipeline, planner=_RelentlessPlanner()).run(
        goal="Export customers with sensitive support cases",
        subject_key=SUBJECT,
    )

    assert result.succeeded is False
    assert result.exhausted_attempts is True
    assert result.final_decision == Decision.BLOCK
    assert all(attempt.released_row_count is None for attempt in result.attempts)


class _MalformedPlanner:
    def propose(self, *, goal, context):
        del goal, context
        return {"task_purpose": "", "sql": ""}

    def adapt(self, *, goal, context, previous, feedback):
        del goal, context, previous, feedback
        return {"task_purpose": "", "sql": ""}


def test_malformed_planner_output_is_rejected_at_the_boundary(
    pipeline: ToxicJoinPipeline,
) -> None:
    with pytest.raises(AgentProposalError):
        _session(pipeline, planner=_MalformedPlanner()).run(
            goal="anything",
            subject_key=SUBJECT,
        )


def test_agent_endpoint_returns_the_full_attempt_chain(
    seeded_database: Path,
    tmp_path: Path,
) -> None:
    pipeline = ToxicJoinPipeline(
        context_resolver=FixtureContextResolver(default_fixture_catalog()),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(seeded_database),
    )
    with TestClient(create_app(pipeline, web_dist=tmp_path / "absent")) as client:
        response = client.post(
            "/api/agent/run",
            json={"goal": "Find regions with elevated churn risk"},
        )

    assert response.status_code == 200
    body = response.json()
    assert body["succeeded"] is True
    assert body["final_decision"] == "ALLOW"
    assert [attempt["decision"] for attempt in body["attempts"]][0] == "BLOCK"
    assert body["attempts"][-1]["decision"] == "ALLOW"


def test_agent_endpoint_rejects_a_blank_goal(
    seeded_database: Path,
    tmp_path: Path,
) -> None:
    pipeline = ToxicJoinPipeline(
        context_resolver=FixtureContextResolver(default_fixture_catalog()),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(seeded_database),
    )
    with TestClient(create_app(pipeline, web_dist=tmp_path / "absent")) as client:
        response = client.post("/api/agent/run", json={"goal": "   "})

    assert response.status_code == 422
