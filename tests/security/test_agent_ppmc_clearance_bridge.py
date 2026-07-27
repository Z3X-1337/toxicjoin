from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from toxicjoin.agent import (
    DataHubAgentProposalAuthority,
    DataHubGovernanceTrustAuthority,
    GovernedAgent,
    TrustedAgentProposalEvaluation,
    build_agent_data_context_from_snapshot,
    build_agent_goal,
)
from toxicjoin.agent.ppmc_authority import (
    AgentPpmcAuthorityError,
    DataHubAgentPpmcAuthority,
    TrustedAgentPpmcEvaluation,
    compute_trusted_agent_ppmc_evaluation_sha256,
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
    FutureActionGrammarContext,
    build_future_action_grammar_context,
    compute_future_action_context_sha256,
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
        warehouse_snapshot_sha256=canonical_json_sha256({"warehouse": "day13-agent-ppmc-a"}),
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
    return (
        evaluation,
        governance_trust,
        state,
        grammar,
        forbidden_policy,
        config,
        semantic,
        composition,
    )


def _check(authority, artifacts):
    evaluation, governance_trust, state, grammar, forbidden_policy, config, _, _ = artifacts
    return authority.check(
        evaluation=evaluation,
        governance_trust=governance_trust,
        initial_state=state,
        grammar=grammar,
        forbidden_policy=forbidden_policy,
        config=config,
    )


def _rebind_context(grammar, *, field: str, value: str):
    provisional = grammar.context.model_copy(
        update={field: value, "context_sha256": "0" * 64}
    )
    rebound = provisional.model_copy(
        update={"context_sha256": compute_future_action_context_sha256(provisional)}
    )
    canonical_context = FutureActionGrammarContext.model_validate(
        rebound.model_dump(mode="json")
    )
    return instantiate_future_action_grammar(canonical_context)


def test_internal_f6_clearance_drives_agent_ppmc(monkeypatch: pytest.MonkeyPatch) -> None:
    artifacts = _artifacts(monkeypatch)
    evaluation, _, state, grammar, forbidden_policy, _, _, _ = artifacts

    result = _check(
        DataHubAgentPpmcAuthority(clock=lambda: NOW + timedelta(seconds=4)),
        artifacts,
    )

    assert result.agent_evaluation_sha256 == evaluation.evaluation_sha256
    assert result.f6_clearance.evaluation_sha256 == evaluation.evaluation_sha256
    assert result.f6_clearance_sha256 == result.f6_clearance.clearance_sha256
    assert result.f6_clearance.disclosure_state_sha256 == state.state_sha256
    assert result.disclosure_state_sha256 == state.state_sha256
    assert result.governance_binding_sha256 == result.f6_clearance.f6_binding.binding_sha256
    assert result.ppmc_result.status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND
    assert result.ppmc_result.initial_state_sha256 == state.state_sha256
    assert result.ppmc_result.grammar_sha256 == grammar.grammar_sha256
    assert result.ppmc_result.forbidden_policy_sha256 == forbidden_policy.policy_sha256
    assert result.ppmc_result.governance_binding_sha256 == (
        result.f6_clearance.f6_binding.binding_sha256
    )
    assert result.ppmc_result_sha256 == result.ppmc_result.result_sha256
    assert result.prospective_privacy_checked is True
    assert result.execution_authorized is False


@pytest.mark.parametrize(
    ("field", "error_code"),
    (
        ("scope_sha256", "AGENT_PPMC_GRAMMAR_SCOPE_MISMATCH"),
        ("purpose_commitment_sha256", "AGENT_PPMC_GRAMMAR_PURPOSE_MISMATCH"),
        ("governance_commitment_sha256", "AGENT_PPMC_GRAMMAR_GOVERNANCE_MISMATCH"),
        ("evidence_root_sha256", "AGENT_PPMC_GRAMMAR_EVIDENCE_MISMATCH"),
        ("base_warehouse_snapshot_sha256", "AGENT_PPMC_GRAMMAR_SNAPSHOT_MISMATCH"),
    ),
)
def test_self_consistent_grammar_context_rebinding_fails_closed_at_bound_zero(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    error_code: str,
) -> None:
    (
        evaluation,
        governance_trust,
        state,
        grammar,
        forbidden_policy,
        config,
        _,
        _,
    ) = _artifacts(monkeypatch)
    forged_grammar = _rebind_context(grammar, field=field, value="a" * 64)

    with pytest.raises(AgentPpmcAuthorityError, match=error_code):
        DataHubAgentPpmcAuthority(clock=lambda: NOW + timedelta(seconds=4)).check(
            evaluation=evaluation,
            governance_trust=governance_trust,
            initial_state=state,
            grammar=forged_grammar,
            forbidden_policy=forbidden_policy,
            config=config,
        )


def test_evaluation_subclass_is_rejected_before_virtual_serialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = _artifacts(monkeypatch)
    evaluation, governance_trust, state, grammar, forbidden_policy, config, _, _ = artifacts
    calls: list[str] = []

    class _MaliciousEvaluation(TrustedAgentProposalEvaluation):
        def model_dump(self, *args, **kwargs):
            calls.append("model_dump")
            return super().model_dump(*args, **kwargs)

    attacker = _MaliciousEvaluation.model_validate(evaluation.model_dump(mode="json"))
    calls.clear()

    with pytest.raises(AgentPpmcAuthorityError, match="AGENT_PPMC_INPUT_INVALID"):
        DataHubAgentPpmcAuthority(clock=lambda: NOW + timedelta(seconds=4)).check(
            evaluation=attacker,
            governance_trust=governance_trust,
            initial_state=state,
            grammar=grammar,
            forbidden_policy=forbidden_policy,
            config=config,
        )

    assert calls == []


def test_stale_evidence_cannot_issue_internal_f6_clearance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = _artifacts(monkeypatch)

    with pytest.raises(
        AgentPpmcAuthorityError,
        match="AGENT_PPMC_F6_CLEARANCE_FAILED",
    ):
        _check(
            DataHubAgentPpmcAuthority(clock=lambda: NOW + timedelta(seconds=301)),
            artifacts,
        )


def test_expiry_after_ppmc_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    artifacts = _artifacts(monkeypatch)
    clock = _SequenceClock(
        NOW + timedelta(seconds=299),
        NOW + timedelta(seconds=299),
        NOW + timedelta(seconds=299),
        NOW + timedelta(seconds=301),
    )

    with pytest.raises(
        AgentPpmcAuthorityError,
        match="AGENT_PPMC_CLEARANCE_STALE_AT_ISSUE",
    ):
        _check(DataHubAgentPpmcAuthority(clock=clock), artifacts)


def test_cross_call_clock_rollback_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    artifacts = _artifacts(monkeypatch)
    clock = _MutableClock(NOW + timedelta(seconds=10))
    authority = DataHubAgentPpmcAuthority(clock=clock)

    first = _check(authority, artifacts)
    assert first.ppmc_result.status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND

    clock.current = NOW + timedelta(seconds=5)
    with pytest.raises(
        AgentPpmcAuthorityError,
        match="AGENT_PPMC_F6_CLEARANCE_FAILED",
    ):
        _check(authority, artifacts)


def test_trusted_agent_ppmc_evaluation_hash_tampering_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _check(
        DataHubAgentPpmcAuthority(clock=lambda: NOW + timedelta(seconds=4)),
        _artifacts(monkeypatch),
    )
    payload = result.model_dump(mode="json")
    payload["evaluation_sha256"] = "0" * 64

    with pytest.raises(ValidationError, match="Agent PPMC evaluation hash mismatch"):
        TrustedAgentPpmcEvaluation.model_validate(payload)


def test_self_consistent_result_state_rebinding_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _check(
        DataHubAgentPpmcAuthority(clock=lambda: NOW + timedelta(seconds=4)),
        _artifacts(monkeypatch),
    )
    different_state_sha256 = canonical_json_sha256({"state": "different"})
    provisional = result.model_copy(
        update={
            "disclosure_state_sha256": different_state_sha256,
            "evaluation_sha256": "0" * 64,
        }
    )
    forged = provisional.model_copy(
        update={
            "evaluation_sha256": compute_trusted_agent_ppmc_evaluation_sha256(provisional)
        }
    )

    with pytest.raises(ValidationError, match="F6/state commitment mismatch"):
        TrustedAgentPpmcEvaluation.model_validate(forged.model_dump(mode="json"))
