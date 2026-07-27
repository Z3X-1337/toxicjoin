from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from toxicjoin.agent import (
    DataHubAgentProposalAuthority,
    DataHubGovernanceTrustAuthority,
    GovernedAgent,
    build_agent_data_context_from_snapshot,
    build_agent_goal,
)
from toxicjoin.agent.ppmc_authority import (
    AgentPpmcAuthorityError,
    DataHubAgentPpmcAuthority,
)
from toxicjoin.context.datahub import DataHubSnapshot
from toxicjoin.context.fixture import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.disclosure.composition import is_protected_release
from toxicjoin.disclosure.models import (
    DisclosureComposition,
    DisclosureScope,
    DisclosureSemanticRelease,
    compute_scope_sha256,
    compute_semantic_sha256,
)
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
from toxicjoin.prospective.ppmc import build_ppmc_search_config
from toxicjoin.prospective.twin import (
    DisclosureState,
    compute_disclosure_state_sha256,
    compute_inference_rules_sha256,
    direct_atoms_for_release,
    instantiate_disclosure_inference_rules,
    least_fixed_point,
)


NOW = datetime(2026, 7, 27, 5, 30, tzinfo=timezone.utc)
DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.day13_ppmc_semantic,PROD)"
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
            version="datahub-mcp:day13-ppmc-semantic-v1",
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


def _rebuild_state_with_historical_release(
    state: DisclosureState,
    semantic: DisclosureSemanticRelease,
    composition: DisclosureComposition,
) -> DisclosureState:
    merged = {atom.atom_sha256: atom for atom in state.released_atoms}
    for atom in direct_atoms_for_release(semantic, composition):
        merged[atom.atom_sha256] = atom
    released_atoms = tuple(merged[key] for key in sorted(merged))
    rules = instantiate_disclosure_inference_rules(released_atoms)
    derived_atoms = least_fixed_point(released_atoms, rules)
    rules_root = compute_inference_rules_sha256(rules)
    provisional = state.model_copy(
        update={
            "released_atoms": released_atoms,
            "derived_atoms": derived_atoms,
            "inference_rules_sha256": rules_root,
            "state_sha256": "0" * 64,
        }
    )
    return DisclosureState.model_validate(
        provisional.model_copy(
            update={"state_sha256": compute_disclosure_state_sha256(provisional)}
        ).model_dump(mode="json")
    )


def test_historical_base_semantic_cannot_replace_current_agent_evaluation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATAHUB_GMS_URL", "https://day13-ppmc-semantic.example")
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", "day13-ppmc-semantic-token")
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

    current_semantic = build_semantic_release_from_resolution(
        evaluation.query_plan,
        evaluation.resolution,
    )
    subject = resolve_governed_subject_domain(
        snapshot.catalog,
        subject_key=SUBJECT_KEY,
        source_datasets=evaluation.query_plan.source_datasets,
    )
    scope = DisclosureScope(
        principal_id="principal-day13-ppmc-semantic",
        agent_id="agent-day13-ppmc-semantic",
        subject=subject,
        scope_sha256=compute_scope_sha256(
            principal_id="principal-day13-ppmc-semantic",
            agent_id="agent-day13-ppmc-semantic",
            subject_namespace_sha256=subject.namespace_sha256,
        ),
    )
    current_composition = DisclosureComposition(
        protected_release=is_protected_release(current_semantic),
        release_family_sha256=current_semantic.semantic_sha256,
        cohort_hmac_sha256=canonical_json_sha256({"cohort": "current"}),
    )
    current_state = DisclosureState.model_validate(
        __import__("toxicjoin.prospective.twin", fromlist=["build_disclosure_state"])
        .build_disclosure_state(
            scope=scope,
            audit_history=(),
            candidate_semantic=current_semantic,
            candidate_composition=current_composition,
            purpose_commitment_sha256=evaluation.authorized_task_purpose_sha256,
            governance_commitment_sha256=canonical_json_sha256(
                evaluation.governance_binding.model_dump(mode="json")
            ),
            evidence_root_sha256=evaluation.evidence_bundle.evidence_root_sha256,
            warehouse_snapshot_sha256=canonical_json_sha256(
                {"warehouse": "day13-ppmc-semantic"}
            ),
        )
        .model_dump(mode="json")
    )

    historical_provisional = current_semantic.model_copy(
        update={
            "minimum_group_size_present": (current_semantic.minimum_group_size_present or 1) + 1,
            "semantic_sha256": "0" * 64,
        }
    )
    historical_semantic = DisclosureSemanticRelease.model_validate(
        historical_provisional.model_copy(
            update={"semantic_sha256": compute_semantic_sha256(historical_provisional)}
        ).model_dump(mode="json")
    )
    assert historical_semantic.semantic_sha256 != current_semantic.semantic_sha256
    historical_composition = DisclosureComposition(
        protected_release=is_protected_release(historical_semantic),
        release_family_sha256=historical_semantic.semantic_sha256,
        cohort_hmac_sha256=canonical_json_sha256({"cohort": "historical"}),
    )
    state_with_history = _rebuild_state_with_historical_release(
        current_state,
        historical_semantic,
        historical_composition,
    )
    historical_grammar = instantiate_future_action_grammar(
        build_future_action_grammar_context(
            base_state=state_with_history,
            base_semantic=historical_semantic,
            base_composition=historical_composition,
        )
    )
    policy = load_policy()

    with pytest.raises(
        AgentPpmcAuthorityError,
        match="AGENT_PPMC_GRAMMAR_SEMANTIC_MISMATCH",
    ):
        DataHubAgentPpmcAuthority(clock=lambda: NOW + timedelta(seconds=4)).check(
            evaluation=evaluation,
            governance_trust=governance_trust,
            initial_state=state_with_history,
            grammar=historical_grammar,
            forbidden_policy=build_forbidden_predicate_policy(
                minimum_group_size=policy.minimum_group_size
            ),
            local_oracle=lambda state, action: False,
            config=build_ppmc_search_config(bound=0, max_states=32),
        )
