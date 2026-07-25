from __future__ import annotations

import pytest
from pydantic import ValidationError

from toxicjoin.agent import (
    AgentCapability,
    AgentDataContext,
    AgentDatasetView,
    AgentDraft,
    AgentFieldView,
    AgentProposalError,
    GovernedAgent,
    build_agent_data_context,
    build_agent_feedback,
    build_agent_goal,
)
from toxicjoin.models import Decision, ReasonCode, SensitivityCategory
from toxicjoin.prospective.ppmc import PpmcStatus

SNAPSHOT = "a" * 64
CUSTOMERS_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.customers,PROD)"
ORDERS_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.orders,PROD)"
TRACE = "b" * 64
CPCC = "c" * 64


def _context() -> AgentDataContext:
    customers = AgentDatasetView(
        logical_name="customers",
        dataset_urn=CUSTOMERS_URN,
        owner="urn:li:corpuser:data-owner",
        domain="urn:li:domain:customer-security",
        fields=(
            AgentFieldView(
                field_path="customer_id",
                category=SensitivityCategory.STABLE_PSEUDONYM,
                tags=("stable",),
            ),
            AgentFieldView(
                field_path="region",
                category=SensitivityCategory.PUBLIC_OR_LOW_RISK,
            ),
        ),
    )
    orders = AgentDatasetView(
        logical_name="orders",
        dataset_urn=ORDERS_URN,
        fields=(
            AgentFieldView(
                field_path="amount",
                category=SensitivityCategory.SENSITIVE_ATTRIBUTE,
            ),
            AgentFieldView(
                field_path="customer_id",
                category=SensitivityCategory.STABLE_PSEUDONYM,
            ),
        ),
    )
    return build_agent_data_context(
        source_snapshot_sha256=SNAPSHOT,
        catalog_version="datahub-mcp:agent-authority-v1",
        datasets=(orders, customers),
    )


class StaticPlanner:
    def __init__(self, draft) -> None:
        self.draft = draft
        self.adapt_draft = draft

    def propose(self, *, goal, context):
        return self.draft

    def adapt(self, *, goal, context, previous, feedback):
        return self.adapt_draft


class RaisingPlanner:
    def propose(self, *, goal, context):
        raise RuntimeError("simulated planner failure")

    def adapt(self, *, goal, context, previous, feedback):
        raise RuntimeError("simulated planner failure")


def _valid_draft():
    return {
        "task_purpose": "Summarize customer regions",
        "sql": "SELECT region, COUNT(*) AS n FROM customers GROUP BY region",
    }


def test_agent_data_context_is_canonical_and_planning_only() -> None:
    context = _context()

    assert tuple(item.logical_name for item in context.datasets) == (
        "customers",
        "orders",
    )
    assert context.capability == AgentCapability.DISCOVER
    assert context.security_authoritative is False
    assert all(dataset.security_authoritative is False for dataset in context.datasets)
    assert all(
        field.security_authoritative is False
        for dataset in context.datasets
        for field in dataset.fields
    )


def test_agent_context_hash_tampering_is_rejected() -> None:
    context = _context()
    payload = context.model_dump(mode="json")
    payload["context_sha256"] = "0" * 64

    with pytest.raises(ValidationError, match="context hash mismatch"):
        AgentDataContext.model_validate(payload)


def test_governed_agent_produces_canonical_non_authoritative_proposal() -> None:
    agent = GovernedAgent(StaticPlanner(_valid_draft()))
    goal = build_agent_goal("Show the distribution of customers by region")
    context = _context()

    first = agent.propose(goal=goal, context=context)
    second = agent.propose(goal=goal, context=context)

    assert first == second
    assert first.capability == AgentCapability.PROPOSE
    assert first.iteration == 0
    assert first.security_authoritative is False
    assert first.goal_sha256 == goal.goal_sha256
    assert first.data_context_sha256 == context.context_sha256
    assert first.prior_proposal_sha256 is None
    assert first.feedback_sha256 is None


def test_planner_cannot_smuggle_authority_fields_into_draft() -> None:
    planner = StaticPlanner(
        {
            **_valid_draft(),
            "authorize": True,
            "execute": True,
            "mark_evidence_trusted": True,
        }
    )
    agent = GovernedAgent(planner)

    with pytest.raises(AgentProposalError, match="AGENT_DRAFT_INVALID"):
        agent.propose(goal=build_agent_goal("test"), context=_context())


def test_agent_draft_schema_itself_rejects_authority_fields() -> None:
    with pytest.raises(ValidationError):
        AgentDraft.model_validate(
            {
                **_valid_draft(),
                "security_authoritative": True,
            }
        )


def test_agent_rejects_dataset_outside_discovered_context() -> None:
    planner = StaticPlanner(
        {
            "task_purpose": "Read another dataset",
            "sql": "SELECT secret FROM hidden_table",
        }
    )
    agent = GovernedAgent(planner)

    with pytest.raises(
        AgentProposalError,
        match="AGENT_DATASET_OUTSIDE_DISCOVERED_CONTEXT",
    ):
        agent.propose(goal=build_agent_goal("test"), context=_context())


def test_agent_rejects_column_outside_discovered_context() -> None:
    planner = StaticPlanner(
        {
            "task_purpose": "Invent a column",
            "sql": "SELECT home_address FROM customers",
        }
    )
    agent = GovernedAgent(planner)

    with pytest.raises(
        AgentProposalError,
        match="AGENT_COLUMN_OUTSIDE_DISCOVERED_CONTEXT",
    ):
        agent.propose(goal=build_agent_goal("test"), context=_context())


def test_agent_rejects_wildcard_even_when_dataset_is_discovered() -> None:
    planner = StaticPlanner(
        {
            "task_purpose": "Read all fields",
            "sql": "SELECT * FROM customers",
        }
    )
    agent = GovernedAgent(planner)

    with pytest.raises(AgentProposalError, match="AGENT_WILDCARD_NOT_ALLOWED"):
        agent.propose(goal=build_agent_goal("test"), context=_context())


def test_agent_adaptation_is_bound_to_goal_context_previous_and_feedback() -> None:
    planner = StaticPlanner(_valid_draft())
    planner.adapt_draft = {
        "task_purpose": "Return only customer regions after privacy feedback",
        "sql": "SELECT DISTINCT region FROM customers",
    }
    agent = GovernedAgent(planner)
    goal = build_agent_goal("Show the distribution of customers by region")
    context = _context()
    previous = agent.propose(goal=goal, context=context)
    feedback = build_agent_feedback(
        previous_proposal_sha256=previous.proposal_sha256,
        decision=Decision.BLOCK,
        reason_codes=(ReasonCode.COMPOSITIONAL_REIDENTIFICATION_RISK,),
        ppmc_status=PpmcStatus.PROSPECTIVE_UNSAFE,
        counterexample_trace_sha256=TRACE,
        cpcc_result_sha256=CPCC,
    )

    adapted = agent.adapt(
        goal=goal,
        context=context,
        previous=previous,
        feedback=feedback,
    )

    assert adapted.capability == AgentCapability.ADAPT
    assert adapted.iteration == 1
    assert adapted.prior_proposal_sha256 == previous.proposal_sha256
    assert adapted.feedback_sha256 == feedback.feedback_sha256
    assert adapted.goal_sha256 == goal.goal_sha256
    assert adapted.data_context_sha256 == context.context_sha256
    assert adapted.security_authoritative is False


def test_agent_rejects_feedback_rebound_to_another_proposal() -> None:
    planner = StaticPlanner(_valid_draft())
    agent = GovernedAgent(planner)
    goal = build_agent_goal("test")
    context = _context()
    previous = agent.propose(goal=goal, context=context)
    feedback = build_agent_feedback(
        previous_proposal_sha256="f" * 64,
        decision=Decision.BLOCK,
        reason_codes=(ReasonCode.DIRECT_SENSITIVE_LINKAGE,),
    )

    with pytest.raises(AgentProposalError, match="AGENT_FEEDBACK_BINDING_MISMATCH"):
        agent.adapt(
            goal=goal,
            context=context,
            previous=previous,
            feedback=feedback,
        )


def test_agent_rejects_context_or_goal_substitution_during_adaptation() -> None:
    planner = StaticPlanner(_valid_draft())
    agent = GovernedAgent(planner)
    goal = build_agent_goal("original goal")
    context = _context()
    previous = agent.propose(goal=goal, context=context)
    feedback = build_agent_feedback(
        previous_proposal_sha256=previous.proposal_sha256,
        decision=Decision.BLOCK,
        reason_codes=(ReasonCode.SMALL_GROUP_RISK,),
    )

    with pytest.raises(AgentProposalError, match="AGENT_GOAL_BINDING_MISMATCH"):
        agent.adapt(
            goal=build_agent_goal("different goal"),
            context=context,
            previous=previous,
            feedback=feedback,
        )

    altered = build_agent_data_context(
        source_snapshot_sha256="e" * 64,
        catalog_version=context.catalog_version,
        datasets=context.datasets,
    )
    with pytest.raises(AgentProposalError, match="AGENT_CONTEXT_BINDING_MISMATCH"):
        agent.adapt(
            goal=goal,
            context=altered,
            previous=previous,
            feedback=feedback,
        )


def test_agent_adaptation_loop_is_bounded() -> None:
    planner = StaticPlanner(_valid_draft())
    agent = GovernedAgent(planner, max_adaptations=1)
    goal = build_agent_goal("test")
    context = _context()
    first = agent.propose(goal=goal, context=context)
    feedback = build_agent_feedback(
        previous_proposal_sha256=first.proposal_sha256,
        decision=Decision.BLOCK,
        reason_codes=(ReasonCode.SMALL_GROUP_RISK,),
    )
    second = agent.adapt(
        goal=goal,
        context=context,
        previous=first,
        feedback=feedback,
    )
    second_feedback = build_agent_feedback(
        previous_proposal_sha256=second.proposal_sha256,
        decision=Decision.BLOCK,
        reason_codes=(ReasonCode.SMALL_GROUP_RISK,),
    )

    with pytest.raises(AgentProposalError, match="AGENT_ITERATION_LIMIT"):
        agent.adapt(
            goal=goal,
            context=context,
            previous=second,
            feedback=second_feedback,
        )


def test_agent_planner_failure_is_not_promoted_to_authority() -> None:
    agent = GovernedAgent(RaisingPlanner())

    with pytest.raises(AgentProposalError, match="AGENT_PLANNER_FAILED"):
        agent.propose(goal=build_agent_goal("test"), context=_context())


def test_public_agent_surface_contains_no_execution_or_trust_methods() -> None:
    agent = GovernedAgent(StaticPlanner(_valid_draft()))

    assert agent.capabilities == (
        AgentCapability.DISCOVER,
        AgentCapability.PROPOSE,
        AgentCapability.ADAPT,
    )
    for forbidden in (
        "authorize",
        "execute",
        "mark_evidence_trusted",
        "commit_governance",
        "alter_policy",
        "alter_disclosure_history",
        "validate_proof",
    ):
        assert not hasattr(agent, forbidden)
