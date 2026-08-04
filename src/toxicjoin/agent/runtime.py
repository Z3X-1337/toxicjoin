"""Wiring that puts the Governed Agent boundary on the executable product path.

`GovernedAgent` was previously reachable only from tests: it had no way to obtain a planning
context from the resolver the runtime actually uses, and nothing drove the propose/adapt loop
against real decisions. This module supplies both, so an agent can attempt work, be refused,
read the deterministic reason, and try again — while authorization stays entirely outside it.

The loop deliberately terminates on the pipeline's decision, never on the planner's opinion.
An agent that keeps proposing unsafe SQL simply exhausts its adaptation budget.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

from pydantic import Field

from toxicjoin.agent.governed import GovernedAgent, TrustedPlannerAdapter
from toxicjoin.agent.models import (
    AgentDataContext,
    AgentDatasetView,
    AgentDraft,
    AgentFeedback,
    AgentFieldView,
    AgentGoal,
    AgentLineageView,
    AgentProposal,
    build_agent_data_context,
    build_agent_feedback,
    build_agent_goal,
)
from toxicjoin.context.fixture import FixtureCatalog
from toxicjoin.models import ColumnRef, Decision, ReasonCode, StrictModel
from toxicjoin.pipeline import PipelineRequest, PipelineResult, ToxicJoinPipeline


MAX_AGENT_ATTEMPTS = 4


def build_agent_context_from_catalog(catalog: FixtureCatalog) -> AgentDataContext:
    """Project governed catalog metadata into the sanitized planning schema.

    Only what a planner legitimately needs to write SQL crosses this boundary: logical names,
    field paths, governed categories, labels and upstream lineage. No values, no credentials,
    and nothing marked security-authoritative.
    """

    datasets: list[AgentDatasetView] = []
    for logical_name, dataset in catalog.datasets.items():
        fields = tuple(
            AgentFieldView(
                field_path=field_path,
                category=field.category,
                tags=tuple(sorted(set(field.tags))),
                glossary_terms=tuple(sorted(set(field.glossary_terms))),
                lineage=tuple(
                    sorted(
                        (
                            AgentLineageView(
                                source_dataset_urn=source.datahub_urn or dataset.urn,
                                source_field_path=source.ref.field_path,
                                category=source.category,
                            )
                            for source in field.lineage_sources
                        ),
                        key=lambda view: view.key,
                    )
                ),
            )
            for field_path, field in sorted(dataset.fields.items())
        )
        datasets.append(
            AgentDatasetView(
                logical_name=logical_name,
                dataset_urn=dataset.urn,
                owner=dataset.owner,
                domain=dataset.domain,
                fields=fields,
            )
        )

    return build_agent_data_context(
        source_snapshot_sha256=_catalog_sha256(catalog),
        catalog_version=catalog.version,
        datasets=tuple(datasets),
    )


def _catalog_sha256(catalog: FixtureCatalog) -> str:
    canonical = json.dumps(
        catalog.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class RemediatingTemplatePlanner:
    """A deterministic planner used to exercise the boundary without an LLM.

    A model would make the demonstration non-reproducible and would prove nothing extra: the
    security property under test is that *no* planner can widen its own authority. This one
    behaves like a naive analyst — it reaches for row-level detail first and only narrows when
    ToxicJoin refuses — which is exactly the behaviour the firewall exists to contain.

    Swap this for a real model by implementing ``TrustedPlannerAdapter``; nothing downstream
    changes, because the wrapper revalidates every field the planner returns.
    """

    def propose(
        self,
        *,
        goal: AgentGoal,
        context: AgentDataContext,
    ) -> AgentDraft:
        del context
        return AgentDraft(
            task_purpose=goal.goal,
            sql=_initial_sql(goal.goal),
        )

    def adapt(
        self,
        *,
        goal: AgentGoal,
        context: AgentDataContext,
        previous: AgentProposal,
        feedback: AgentFeedback,
    ) -> AgentDraft:
        del context
        return AgentDraft(
            task_purpose=goal.goal,
            sql=_remediated_sql(previous.sql, feedback),
        )


def _goal_topic(goal: str) -> str:
    lowered = goal.casefold()
    if "churn" in lowered or "retention" in lowered:
        return "churn"
    if "support" in lowered or "case" in lowered:
        return "support"
    if "spend" in lowered or "purchase" in lowered or "revenue" in lowered:
        return "spend"
    return "orders"


_INITIAL_SQL: Mapping[str, str] = {
    # Each of these is deliberately unsafe or under-constrained: a naive planner asks for
    # individual rows, and the firewall is what turns that into something releasable.
    "churn": (
        "SELECT c.customer_id, c.coarse_region, r.churn_score\n"
        "FROM customers c\n"
        "JOIN retention_scores r ON c.customer_id = r.customer_id"
    ),
    "support": (
        "SELECT c.customer_id, c.age_band, c.precise_area, s.case_category\n"
        "FROM customers c\n"
        "JOIN support_cases s ON c.customer_id = s.customer_id"
    ),
    "spend": (
        "SELECT c.customer_id, c.coarse_region, o.purchase_amount\n"
        "FROM customers c\n"
        "JOIN orders o ON c.customer_id = o.customer_id"
    ),
    "orders": (
        "SELECT o.category, COUNT(*) AS order_count\nFROM orders o\nGROUP BY o.category"
    ),
}

_AGGREGATED_SQL: Mapping[str, str] = {
    "churn": (
        "SELECT c.coarse_region,\n"
        "       AVG(r.churn_score) AS average_churn,\n"
        "       COUNT(DISTINCT c.customer_id) AS subject_count\n"
        "FROM customers c\n"
        "JOIN retention_scores r ON c.customer_id = r.customer_id\n"
        "GROUP BY c.coarse_region"
    ),
    "support": (
        "SELECT c.coarse_region,\n"
        "       COUNT(DISTINCT c.customer_id) AS subject_count\n"
        "FROM customers c\n"
        "JOIN support_cases s ON c.customer_id = s.customer_id\n"
        "GROUP BY c.coarse_region"
    ),
    "spend": (
        "SELECT c.coarse_region,\n"
        "       AVG(o.purchase_amount) AS average_spend,\n"
        "       COUNT(DISTINCT c.customer_id) AS subject_count\n"
        "FROM customers c\n"
        "JOIN orders o ON c.customer_id = o.customer_id\n"
        "GROUP BY c.coarse_region"
    ),
    "orders": _INITIAL_SQL["orders"],
}

_REMEDIABLE_BY_AGGREGATION = {
    ReasonCode.COMPOSITIONAL_REIDENTIFICATION_RISK,
    ReasonCode.DIRECT_SENSITIVE_LINKAGE,
    ReasonCode.SMALL_GROUP_RISK,
}


def _initial_sql(goal: str) -> str:
    return _INITIAL_SQL[_goal_topic(goal)]


def _remediated_sql(previous_sql: str, feedback: AgentFeedback) -> str:
    topic = _topic_of_sql(previous_sql)
    if any(reason in _REMEDIABLE_BY_AGGREGATION for reason in feedback.reason_codes):
        aggregated = _AGGREGATED_SQL[topic]
        if aggregated != previous_sql:
            return aggregated
        # Already aggregated and still refused for group size: add the subject threshold the
        # policy asks for rather than inventing a new shape.
        if "HAVING" not in previous_sql.upper():
            return f"{previous_sql}\nHAVING COUNT(DISTINCT c.customer_id) >= 20"
    return _AGGREGATED_SQL[topic]


def _topic_of_sql(sql: str) -> str:
    for topic, template in _INITIAL_SQL.items():
        if template.split("\n")[0] in sql or _AGGREGATED_SQL[topic].split("\n")[0] in sql:
            return topic
    lowered = sql.casefold()
    if "churn_score" in lowered:
        return "churn"
    if "case_category" in lowered:
        return "support"
    if "purchase_amount" in lowered:
        return "spend"
    return "orders"


class AgentAttempt(StrictModel):
    """One proposal and the deterministic verdict it received."""

    iteration: int = Field(ge=0)
    capability: str
    task_purpose: str
    sql: str
    proposal_sha256: str
    decision: Decision
    reason_codes: tuple[ReasonCode, ...]
    safe_sql: str | None = None
    receipt_id: str
    released_row_count: int | None = None


class AgentSessionResult(StrictModel):
    """The full attempt chain plus the outcome the caller may act on."""

    goal: str
    goal_sha256: str
    data_context_sha256: str
    attempts: tuple[AgentAttempt, ...]
    final_decision: Decision
    succeeded: bool
    exhausted_attempts: bool


class GovernedAgentSession:
    """Drive propose/adapt against real decisions until one is releasable or budget runs out."""

    def __init__(
        self,
        *,
        pipeline: ToxicJoinPipeline,
        catalog: FixtureCatalog,
        planner: TrustedPlannerAdapter | None = None,
        max_attempts: int = MAX_AGENT_ATTEMPTS,
    ) -> None:
        if not 1 <= max_attempts <= MAX_AGENT_ATTEMPTS:
            raise ValueError(f"max_attempts must be in [1, {MAX_AGENT_ATTEMPTS}]")
        self._pipeline = pipeline
        self._context = build_agent_context_from_catalog(catalog)
        self._agent = GovernedAgent(planner or RemediatingTemplatePlanner())
        self._max_attempts = max_attempts

    @property
    def data_context(self) -> AgentDataContext:
        return self._context

    def run(
        self,
        *,
        goal: str,
        subject_key: ColumnRef,
        execute: bool = True,
    ) -> AgentSessionResult:
        agent_goal = build_agent_goal(goal)
        attempts: list[AgentAttempt] = []
        proposal = self._agent.propose(goal=agent_goal, context=self._context)

        for iteration in range(self._max_attempts):
            result = self._evaluate(proposal, subject_key=subject_key, execute=execute)
            attempts.append(_attempt(proposal, result))
            if result.effective_decision == Decision.ALLOW:
                return AgentSessionResult(
                    goal=agent_goal.goal,
                    goal_sha256=agent_goal.goal_sha256,
                    data_context_sha256=self._context.context_sha256,
                    attempts=tuple(attempts),
                    final_decision=Decision.ALLOW,
                    succeeded=True,
                    exhausted_attempts=False,
                )
            if iteration == self._max_attempts - 1:
                break

            feedback = build_agent_feedback(
                previous_proposal_sha256=proposal.proposal_sha256,
                decision=result.effective_decision,
                reason_codes=_effective_reasons(result),
            )
            proposal = self._agent.adapt(
                goal=agent_goal,
                context=self._context,
                previous=proposal,
                feedback=feedback,
            )

        return AgentSessionResult(
            goal=agent_goal.goal,
            goal_sha256=agent_goal.goal_sha256,
            data_context_sha256=self._context.context_sha256,
            attempts=tuple(attempts),
            final_decision=attempts[-1].decision,
            succeeded=False,
            exhausted_attempts=True,
        )

    def _evaluate(
        self,
        proposal: AgentProposal,
        *,
        subject_key: ColumnRef,
        execute: bool,
    ) -> PipelineResult:
        request = PipelineRequest(
            task_purpose=proposal.task_purpose,
            sql=proposal.sql,
            subject_key=subject_key,
        )
        return (
            self._pipeline.execute_safe(request)
            if execute
            else self._pipeline.analyze(request)
        )


def _effective_reasons(result: PipelineResult) -> tuple[ReasonCode, ...]:
    if result.final_decision is not None and result.final_decision.reason_codes:
        return tuple(result.final_decision.reason_codes)
    return tuple(result.initial_decision.reason_codes)


def _attempt(proposal: AgentProposal, result: PipelineResult) -> AgentAttempt:
    execution = result.verification.execution if result.verification else None
    return AgentAttempt(
        iteration=proposal.iteration,
        capability=proposal.capability.value,
        task_purpose=proposal.task_purpose,
        sql=proposal.sql,
        proposal_sha256=proposal.proposal_sha256,
        decision=result.effective_decision,
        reason_codes=_effective_reasons(result),
        safe_sql=result.safe_sql,
        receipt_id=result.receipt.receipt_id,
        released_row_count=len(execution.rows) if execution is not None else None,
    )
