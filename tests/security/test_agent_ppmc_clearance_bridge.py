from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from toxicjoin.agent import (
    DataHubAgentProposalAuthority,
    DataHubGovernanceTrustAuthority,
    GovernedAgent,
    build_agent_data_context_from_snapshot,
    build_agent_goal,
)
from toxicjoin.agent.f6_governance import DataHubF6GovernanceAuthority
from toxicjoin.agent.ppmc_authority import (
    AgentPpmcAuthorityError,
    DataHubAgentPpmcAuthority,
    TrustedAgentPpmcEvaluation,
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
from toxicjoin.prospective.ppmc import PpmcStatus, build_ppmc_search_config
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


class _SequenceClock:
    def __init__(self, *samples: datetime) -> None:
        self._samples = iter(samples)

    def __call__(self) -> datetime:
        return next(self._samples)


class _MutableClock:
    def __init__(self, current: datetime) -> None:
        self.current = current

    def __call__(self) -> datetime:
        return self.current


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
    trust_binding = DataHubGovernanceTrustAuthority(
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
        warehouse_snapshot_sha256=canonical_json_sha256({"warehouse": "day13-agent-ppmc-a"}),
    )
    clearance = DataHubF6GovernanceAuthority(
        clock=lambda: NOW + timedelta(seconds=3)
    ).clear(
        evaluation=evaluation,
        governance_trust=trust_binding,
        state=state,
    )
    grammar = instantiate_future_action_grammar(
        build_future_action_grammar_context(
            base_state=state,
            base_semantic=semantic,
            base_composition=composition,
        )
    )
    policy = load_policy()
    forbidden_policy = build_forbidden_predicate_policy(
        minimum_group_size=policy.minimum_group_size
    )
    config = build_ppmc_search_config(bound=0, max_states=32)
    return evaluation, state, clearance, grammar, forbidden_policy, config, semantic, composition


def _unexpected_oracle(state, action):
    raise AssertionError("bound-zero Agent PPMC must not invoke the local oracle")


def test_exact_f6_clearance_drives_agent_ppmc(monkeypatch: pytest.MonkeyPatch) -> None:
    _, state, clearance, grammar, forbidden_policy, config, _, _ = _artifacts(monkeypatch)

    result = DataHubAgentPpmcAuthority(
        clock=lambda: NOW + timedelta(seconds=4)
    ).check(
        initial_state=state,
        f6_clearance=clearance,
        grammar=grammar,
        forbidden_policy=forbidden_policy,
        local_oracle=_unexpected_oracle,
        config=config,
    )

    assert result.f6_clearance_sha256 == clearance.clearance_sha256
    assert result.disclosure_state_sha256 == state.state_sha256
    assert result.governance_binding_sha256 == clearance.f6_binding.binding_sha256
    assert result.ppmc_result.status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND
    assert result.ppmc_result.initial_state_sha256 == state.state_sha256
    assert result.ppmc_result.governance_binding_sha256 == clearance.f6_binding.binding_sha256
    assert result.ppmc_result_sha256 == result.ppmc_result.result_sha256
    assert result.prospective_privacy_checked is True
    assert result.execution_authorized is False


def test_clearance_for_different_state_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    evaluation, state, clearance, _, forbidden_policy, config, semantic, composition = _artifacts(
        monkeypatch
    )
    replacement_state = build_disclosure_state(
        scope=state.scope,
        audit_history=(),
        candidate_semantic=semantic,
        candidate_composition=composition,
        purpose_commitment_sha256=evaluation.authorized_task_purpose_sha256,
        governance_commitment_sha256=state.governance_commitment_sha256,
        evidence_root_sha256=state.evidence_root_sha256,
        warehouse_snapshot_sha256=canonical_json_sha256(
            {"warehouse": "day13-agent-ppmc-b"}
        ),
    )
    replacement_grammar = instantiate_future_action_grammar(
        build_future_action_grammar_context(
            base_state=replacement_state,
            base_semantic=semantic,
            base_composition=composition,
        )
    )
    assert replacement_state.state_sha256 != state.state_sha256

    with pytest.raises(AgentPpmcAuthorityError, match="AGENT_PPMC_STATE_MISMATCH"):
        DataHubAgentPpmcAuthority(clock=lambda: NOW + timedelta(seconds=4)).check(
            initial_state=replacement_state,
            f6_clearance=clearance,
            grammar=replacement_grammar,
            forbidden_policy=forbidden_policy,
            local_oracle=_unexpected_oracle,
            config=config,
        )


def test_legacy_f6_binding_cannot_substitute_for_clearance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, state, clearance, grammar, forbidden_policy, config, _, _ = _artifacts(monkeypatch)

    with pytest.raises(AgentPpmcAuthorityError, match="AGENT_PPMC_INPUT_INVALID"):
        DataHubAgentPpmcAuthority(clock=lambda: NOW + timedelta(seconds=4)).check(
            initial_state=state,
            f6_clearance=clearance.f6_binding,
            grammar=grammar,
            forbidden_policy=forbidden_policy,
            local_oracle=_unexpected_oracle,
            config=config,
        )


def test_clearance_from_future_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    _, state, clearance, grammar, forbidden_policy, config, _, _ = _artifacts(monkeypatch)

    with pytest.raises(AgentPpmcAuthorityError, match="AGENT_PPMC_CLEARANCE_FROM_FUTURE"):
        DataHubAgentPpmcAuthority(clock=lambda: NOW + timedelta(seconds=2)).check(
            initial_state=state,
            f6_clearance=clearance,
            grammar=grammar,
            forbidden_policy=forbidden_policy,
            local_oracle=_unexpected_oracle,
            config=config,
        )


def test_stale_clearance_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    _, state, clearance, grammar, forbidden_policy, config, _, _ = _artifacts(monkeypatch)

    with pytest.raises(AgentPpmcAuthorityError, match="AGENT_PPMC_CLEARANCE_STALE"):
        DataHubAgentPpmcAuthority(clock=lambda: NOW + timedelta(seconds=301)).check(
            initial_state=state,
            f6_clearance=clearance,
            grammar=grammar,
            forbidden_policy=forbidden_policy,
            local_oracle=_unexpected_oracle,
            config=config,
        )


def test_expiry_after_ppmc_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _, state, clearance, grammar, forbidden_policy, config, _, _ = _artifacts(monkeypatch)
    clock = _SequenceClock(
        NOW + timedelta(seconds=299),
        NOW + timedelta(seconds=301),
    )

    with pytest.raises(
        AgentPpmcAuthorityError,
        match="AGENT_PPMC_CLEARANCE_STALE_AT_ISSUE",
    ):
        DataHubAgentPpmcAuthority(clock=clock).check(
            initial_state=state,
            f6_clearance=clearance,
            grammar=grammar,
            forbidden_policy=forbidden_policy,
            local_oracle=_unexpected_oracle,
            config=config,
        )


def test_cross_call_clock_rollback_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    _, state, clearance, grammar, forbidden_policy, config, _, _ = _artifacts(monkeypatch)
    clock = _MutableClock(NOW + timedelta(seconds=10))
    authority = DataHubAgentPpmcAuthority(clock=clock)

    first = authority.check(
        initial_state=state,
        f6_clearance=clearance,
        grammar=grammar,
        forbidden_policy=forbidden_policy,
        local_oracle=_unexpected_oracle,
        config=config,
    )
    assert first.ppmc_result.status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND

    clock.current = NOW + timedelta(seconds=5)
    with pytest.raises(AgentPpmcAuthorityError, match="AGENT_PPMC_TIME_ROLLBACK"):
        authority.check(
            initial_state=state,
            f6_clearance=clearance,
            grammar=grammar,
            forbidden_policy=forbidden_policy,
            local_oracle=_unexpected_oracle,
            config=config,
        )


def test_trusted_agent_ppmc_evaluation_hash_tampering_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, state, clearance, grammar, forbidden_policy, config, _, _ = _artifacts(monkeypatch)
    result = DataHubAgentPpmcAuthority(
        clock=lambda: NOW + timedelta(seconds=4)
    ).check(
        initial_state=state,
        f6_clearance=clearance,
        grammar=grammar,
        forbidden_policy=forbidden_policy,
        local_oracle=_unexpected_oracle,
        config=config,
    )
    payload = result.model_dump(mode="json")
    payload["evaluation_sha256"] = "0" * 64

    with pytest.raises(ValidationError, match="Agent PPMC evaluation hash mismatch"):
        TrustedAgentPpmcEvaluation.model_validate(payload)
