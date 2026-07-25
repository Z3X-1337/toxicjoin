"""Security-owned wrapper around an untrusted SQL-planning agent."""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from typing import Any, Protocol

from pydantic import ValidationError

from toxicjoin.agent.models import (
    AgentCapability,
    AgentDataContext,
    AgentDraft,
    AgentFeedback,
    AgentGoal,
    AgentProposal,
    compute_agent_proposal_sha256,
)
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.sql import SqlAnalysisError, analyze_sql

_MAX_AGENT_ADAPTATIONS = 8


class AgentProposalError(RuntimeError):
    """Stable fail-closed rejection at the untrusted planner boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class AgentPlanner(Protocol):
    """Untrusted planner contract. It can return only draft content, never authority."""

    def propose(
        self,
        *,
        goal: AgentGoal,
        context: AgentDataContext,
    ) -> AgentDraft | Mapping[str, Any]: ...

    def adapt(
        self,
        *,
        goal: AgentGoal,
        context: AgentDataContext,
        previous: AgentProposal,
        feedback: AgentFeedback,
    ) -> AgentDraft | Mapping[str, Any]: ...


class GovernedAgent:
    """Convert untrusted planner drafts into canonical planning-only proposals.

    This object deliberately has no PolicyEngine, execution authorizer, executor, EvidencePolicy,
    disclosure ledger, DataHub mutation client, or proof-verification dependency. Its authority is
    restricted to PROPOSE and ADAPT over a sanitized DISCOVER context supplied by a separate
    security-owned component.
    """

    def __init__(
        self,
        planner: AgentPlanner,
        *,
        max_adaptations: int = _MAX_AGENT_ADAPTATIONS,
    ) -> None:
        if not 1 <= max_adaptations <= _MAX_AGENT_ADAPTATIONS:
            raise ValueError(
                f"max_adaptations must be in [1, {_MAX_AGENT_ADAPTATIONS}]"
            )
        self._planner = planner
        self._max_adaptations = max_adaptations

    @property
    def capabilities(self) -> tuple[AgentCapability, ...]:
        return (
            AgentCapability.DISCOVER,
            AgentCapability.PROPOSE,
            AgentCapability.ADAPT,
        )

    def propose(
        self,
        *,
        goal: AgentGoal,
        context: AgentDataContext,
    ) -> AgentProposal:
        trusted_goal = _revalidate_goal(goal)
        trusted_context = _revalidate_context(context)
        try:
            raw = self._planner.propose(goal=trusted_goal, context=trusted_context)
        except Exception as exc:
            raise AgentProposalError("AGENT_PLANNER_FAILED") from exc
        draft = _validate_draft(raw)
        return _build_proposal(
            capability=AgentCapability.PROPOSE,
            iteration=0,
            goal=trusted_goal,
            context=trusted_context,
            draft=draft,
            prior_proposal_sha256=None,
            feedback_sha256=None,
        )

    def adapt(
        self,
        *,
        goal: AgentGoal,
        context: AgentDataContext,
        previous: AgentProposal,
        feedback: AgentFeedback,
    ) -> AgentProposal:
        trusted_goal = _revalidate_goal(goal)
        trusted_context = _revalidate_context(context)
        trusted_previous = _revalidate_proposal(previous)
        trusted_feedback = _revalidate_feedback(feedback)

        if trusted_previous.goal_sha256 != trusted_goal.goal_sha256:
            raise AgentProposalError("AGENT_GOAL_BINDING_MISMATCH")
        if trusted_previous.data_context_sha256 != trusted_context.context_sha256:
            raise AgentProposalError("AGENT_CONTEXT_BINDING_MISMATCH")
        if (
            trusted_feedback.previous_proposal_sha256
            != trusted_previous.proposal_sha256
        ):
            raise AgentProposalError("AGENT_FEEDBACK_BINDING_MISMATCH")
        if trusted_previous.iteration >= self._max_adaptations:
            raise AgentProposalError("AGENT_ITERATION_LIMIT")

        try:
            raw = self._planner.adapt(
                goal=trusted_goal,
                context=trusted_context,
                previous=trusted_previous,
                feedback=trusted_feedback,
            )
        except Exception as exc:
            raise AgentProposalError("AGENT_PLANNER_FAILED") from exc
        draft = _validate_draft(raw)
        return _build_proposal(
            capability=AgentCapability.ADAPT,
            iteration=trusted_previous.iteration + 1,
            goal=trusted_goal,
            context=trusted_context,
            draft=draft,
            prior_proposal_sha256=trusted_previous.proposal_sha256,
            feedback_sha256=trusted_feedback.feedback_sha256,
        )


def _build_proposal(
    *,
    capability: AgentCapability,
    iteration: int,
    goal: AgentGoal,
    context: AgentDataContext,
    draft: AgentDraft,
    prior_proposal_sha256: str | None,
    feedback_sha256: str | None,
) -> AgentProposal:
    try:
        plan = analyze_sql(draft.sql, dialect="duckdb")
    except SqlAnalysisError as exc:
        raise AgentProposalError("AGENT_SQL_ANALYSIS_FAILED") from exc
    except Exception as exc:
        raise AgentProposalError("AGENT_SQL_ANALYSIS_FAILED") from exc

    if plan.contains_wildcard:
        raise AgentProposalError("AGENT_WILDCARD_NOT_ALLOWED")
    _require_discovered_surface(plan, context)

    payload = {
        "capability": capability,
        "iteration": iteration,
        "goal_sha256": goal.goal_sha256,
        "data_context_sha256": context.context_sha256,
        "prior_proposal_sha256": prior_proposal_sha256,
        "feedback_sha256": feedback_sha256,
        "task_purpose": draft.task_purpose,
        "sql": draft.sql,
        "sql_sha256": hashlib.sha256(draft.sql.encode("utf-8")).hexdigest(),
        "query_plan_sha256": canonical_json_sha256(plan.model_dump(mode="json")),
        "security_authoritative": False,
    }
    provisional = AgentProposal.model_construct(
        **payload,
        proposal_sha256="0" * 64,
    )
    return AgentProposal(
        **payload,
        proposal_sha256=compute_agent_proposal_sha256(provisional),
    )


def _require_discovered_surface(plan, context: AgentDataContext) -> None:
    datasets = {dataset.logical_name: dataset for dataset in context.datasets}
    outside_datasets = tuple(
        sorted(dataset for dataset in plan.source_datasets if dataset not in datasets)
    )
    if outside_datasets:
        raise AgentProposalError("AGENT_DATASET_OUTSIDE_DISCOVERED_CONTEXT")

    allowed_fields = {
        (dataset.logical_name, field.field_path)
        for dataset in context.datasets
        for field in dataset.fields
    }
    outside_fields = tuple(
        sorted(
            {
                (ref.dataset, ref.field_path)
                for ref in plan.referenced_columns
                if (ref.dataset, ref.field_path) not in allowed_fields
            }
        )
    )
    if outside_fields:
        raise AgentProposalError("AGENT_COLUMN_OUTSIDE_DISCOVERED_CONTEXT")


def _validate_draft(raw: AgentDraft | Mapping[str, Any]) -> AgentDraft:
    try:
        if isinstance(raw, AgentDraft):
            return AgentDraft.model_validate(raw.model_dump(mode="json"))
        if isinstance(raw, Mapping):
            return AgentDraft.model_validate(dict(raw))
    except ValidationError as exc:
        raise AgentProposalError("AGENT_DRAFT_INVALID") from exc
    raise AgentProposalError("AGENT_DRAFT_INVALID")


def _revalidate_goal(goal: AgentGoal) -> AgentGoal:
    try:
        return AgentGoal.model_validate(goal.model_dump(mode="json"))
    except (AttributeError, ValidationError) as exc:
        raise AgentProposalError("AGENT_GOAL_INVALID") from exc


def _revalidate_context(context: AgentDataContext) -> AgentDataContext:
    try:
        return AgentDataContext.model_validate(context.model_dump(mode="json"))
    except (AttributeError, ValidationError) as exc:
        raise AgentProposalError("AGENT_CONTEXT_INVALID") from exc


def _revalidate_proposal(proposal: AgentProposal) -> AgentProposal:
    try:
        return AgentProposal.model_validate(proposal.model_dump(mode="json"))
    except (AttributeError, ValidationError) as exc:
        raise AgentProposalError("AGENT_PREVIOUS_PROPOSAL_INVALID") from exc


def _revalidate_feedback(feedback: AgentFeedback) -> AgentFeedback:
    try:
        return AgentFeedback.model_validate(feedback.model_dump(mode="json"))
    except (AttributeError, ValidationError) as exc:
        raise AgentProposalError("AGENT_FEEDBACK_INVALID") from exc
