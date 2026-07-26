from __future__ import annotations

from datetime import datetime, timedelta, timezone
import inspect

import pytest

from toxicjoin.agent import (
    DataHubAgentProposalAuthority,
    DataHubGovernanceTrustAuthority,
    GovernedAgent,
    build_agent_data_context_from_snapshot,
    build_agent_goal,
)
from toxicjoin.agent.prospective_privacy import (
    AgentProspectivePrivacyEvaluation,
    DataHubAgentProspectivePrivacyAuthority,
    compute_agent_prospective_privacy_evaluation_sha256,
)
from toxicjoin.context.datahub import DataHubSnapshot
from toxicjoin.context.fixture import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.disclosure.composition import is_protected_release
from toxicjoin.disclosure.models import DisclosureComposition, DisclosureScope, compute_scope_sha256
from toxicjoin.disclosure.semantic import (
    build_semantic_release_from_resolution,
    resolve_governed_subject_domain,
)
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.integrations.datahub_authority import read_only_settings_from_env
from toxicjoin.models import ColumnRef, SensitivityCategory
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.prospective.forbidden import build_forbidden_predicate_policy
from toxicjoin.prospective.grammar import (
    build_future_action_grammar_context,
    instantiate_future_action_grammar,
)
from toxicjoin.prospective.ppmc import (
    PpmcStatus,
    build_local_oracle_decision,
    build_ppmc_search_config,
)
from toxicjoin.prospective.twin import build_disclosure_state


NOW = datetime(2026, 7, 27, 5, 0, tzinfo=timezone.utc)
DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.day13_agent_ppmc,PROD)"
PURPOSE = "Count diagnoses with the approved subject threshold"
SQL = (
    "SELECT COUNT(diagnosis) AS diagnosis_count "
    "FROM patients "
    "HAVING COUNT(DISTINCT customer_id) >= 20"
)
SUBJECT_KEY = ColumnRef(dataset="patients", field_path="customer_id")


class _Planner:
    def propose(self, *, goal, context):
        return {"task_purpose": PURPOSE, "sql": SQL}

    def adapt(self, *, goal, context, previous, feedback):
        return self.propose(goal=goal, context=context)


def _snapshot() -> DataHubSnapshot:
    return DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:day13-agent-ppmc-v1",
            datasets={
                "patients": FixtureDataset(
                    urn=DATASET_URN,
                    fields={
                        "customer_id": FixtureField(
                            category=SensitivityCategory.STABLE_PSEUDONYM,
                            tags=("stable-customer-identifier",),
                        ),
                        "diagnosis": FixtureField(
                            category=SensitivityCategory.SENSITIVE_ATTRIBUTE,
                            tags=("toxicjoin-sensitive-attribute",),
                        ),
                    },
                )
            },
        ),
        verified_entities=(DATASET_URN,),
        field_counts={"patients": 2},
        lineage_sample={"relationships": []},
        discovered_tools=("get_entities", "get_lineage", "list_schema_fields"),
        observed_at=NOW,
    )


def _artifacts(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("DATAHUB_GMS_URL", "https://day13-agent-ppmc.example")
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", "day13-agent-ppmc-token")
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv("DATAHUB_MCP_ARGS", "mcp-server-datahub")
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")

    snapshot = _snapshot()
    planning_context = build_agent_data_context_from_snapshot(snapshot)
    goal = build_agent_goal("Count diagnoses without releasing individual records")
    proposal = GovernedAgent(_Planner()).propose(goal=goal, context=planning_context)
    evaluation = DataHubAgentProposalAuthority(
        snapshot=snapshot,
        read_settings=read_only_settings_from_env(),
        policy_engine=PolicyEngine(load_policy()),
        clock=lambda: NOW + timedelta(seconds=1),
        datahub_max_age_seconds=300,
    ).evaluate(
        proposal=proposal,
        goal=goal,
        planning_context=planning_context,
        authorized_task_purpose=PURPOSE,
        subject_key=SUBJECT_KEY,
    )
    governance_trust = DataHubGovernanceTrustAuthority(
        clock=lambda: NOW + timedelta(seconds=2)
    ).bind(evaluation)

    semantic = build_semantic_release_from_resolution(
        evaluation.query_plan,
        evaluation.resolution,
    )
    subject = resolve_governed_subject_domain(
        snapshot.catalog,
        subject_key=SUBJECT_KEY,
        source_datasets=evaluation.query_plan.source_datasets,
    )
    scope = DisclosureScope(
        principal_id="principal-day13-agent-ppmc",
        agent_id="agent-day13-agent-ppmc",
        subject=subject,
        scope_sha256=compute_scope_sha256(
            principal_id="principal-day13-agent-ppmc",
            agent_id="agent-day13-agent-ppmc",
            subject_namespace_sha256=subject.namespace_sha256,
        ),
    )
    composition = DisclosureComposition(
        protected_release=is_protected_release(semantic),
        release_family_sha256=semantic.semantic_sha256,
        cohort_hmac_sha256=canonical_json_sha256({"cohort": "day13-agent-ppmc"}),
    )
    state = build_disclosure_state(
        scope=scope,
        audit_history=(),
        candidate_semantic=semantic,
        candidate_composition=composition,
        purpose_commitment_sha256=evaluation.authorized_task_purpose_sha256,
        governance_commitment_sha256=canonical_json_sha256(
            evaluation.governance_binding.model_dump(mode="json")
        ),
        evidence_root_sha256=evaluation.evidence_bundle.evidence_root_sha256,
        warehouse_snapshot_sha256=canonical_json_sha256(
            {"warehouse": "day13-agent-ppmc"}
        ),
    )
    grammar_context = build_future_action_grammar_context(
        base_state=state,
        base_semantic=semantic,
        base_composition=composition,
    )
    grammar = instantiate_future_action_grammar(grammar_context)
    forbidden_policy = build_forbidden_predicate_policy(minimum_group_size=20)
    config = build_ppmc_search_config(bound=0, max_states=32)

    def local_oracle(current_state, action):
        return build_local_oracle_decision(
            oracle_version="day13-agent-ppmc-test-v1",
            state_sha256=current_state.state_sha256,
            action_sha256=action.action_sha256,
            admissible=True,
        )

    return evaluation, governance_trust, state, grammar, forbidden_policy, local_oracle, config


def test_agent_prospective_authority_issues_f6_clearance_internally_and_runs_ppmc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        evaluation,
        governance_trust,
        state,
        grammar,
        forbidden_policy,
        local_oracle,
        config,
    ) = _artifacts(monkeypatch)

    result = DataHubAgentProspectivePrivacyAuthority(
        clock=lambda: NOW + timedelta(seconds=3)
    ).check(
        evaluation=evaluation,
        governance_trust=governance_trust,
        initial_state=state,
        grammar=grammar,
        forbidden_policy=forbidden_policy,
        local_oracle=local_oracle,
        config=config,
    )

    assert result.prospective_privacy_checked is True
    assert result.execution_authorized is False
    assert result.evaluation_sha256 == evaluation.evaluation_sha256
    assert result.disclosure_state_sha256 == state.state_sha256
    assert result.f6_clearance.evaluation_sha256 == evaluation.evaluation_sha256
    assert result.f6_clearance.disclosure_state_sha256 == state.state_sha256
    assert result.ppmc_result.initial_state_sha256 == state.state_sha256
    assert result.ppmc_result.grammar_sha256 == grammar.grammar_sha256
    assert result.ppmc_result.forbidden_policy_sha256 == forbidden_policy.policy_sha256
    assert result.ppmc_result.governance_binding_sha256 == (
        result.f6_clearance.f6_binding.binding_sha256
    )
    assert result.ppmc_result.status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND


def test_agent_prospective_authority_surface_has_no_legacy_trust_input() -> None:
    parameters = inspect.signature(DataHubAgentProspectivePrivacyAuthority.check).parameters

    assert "governance_binding" not in parameters
    assert "f6_binding" not in parameters
    assert "f6_clearance" not in parameters
    assert "trusted" not in parameters
    assert "governance_trust" in parameters


def test_agent_prospective_result_rejects_self_consistent_state_rebinding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        evaluation,
        governance_trust,
        state,
        grammar,
        forbidden_policy,
        local_oracle,
        config,
    ) = _artifacts(monkeypatch)
    result = DataHubAgentProspectivePrivacyAuthority(
        clock=lambda: NOW + timedelta(seconds=3)
    ).check(
        evaluation=evaluation,
        governance_trust=governance_trust,
        initial_state=state,
        grammar=grammar,
        forbidden_policy=forbidden_policy,
        local_oracle=local_oracle,
        config=config,
    )

    different_state_sha256 = canonical_json_sha256({"state": "different"})
    provisional = result.model_copy(
        update={
            "disclosure_state_sha256": different_state_sha256,
            "prospective_evaluation_sha256": "0" * 64,
        }
    )
    forged = provisional.model_copy(
        update={
            "prospective_evaluation_sha256": (
                compute_agent_prospective_privacy_evaluation_sha256(provisional)
            )
        }
    )

    with pytest.raises(ValueError, match="state commitment mismatch"):
        AgentProspectivePrivacyEvaluation.model_validate(forged.model_dump(mode="json"))
