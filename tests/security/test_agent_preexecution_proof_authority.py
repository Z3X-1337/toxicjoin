from __future__ import annotations

from datetime import datetime, timedelta, timezone
import inspect

import pytest

from toxicjoin.agent import (
    DataHubAgentPpmcAuthority,
    DataHubAgentPreExecutionProofAuthority,
    DataHubAgentProposalAuthority,
    DataHubGovernanceTrustAuthority,
    GovernedAgent,
    build_agent_data_context_from_snapshot,
    build_agent_goal,
)
from toxicjoin.agent.proof_authority import AgentPreExecutionProofAuthorityError
from toxicjoin.auth import RequestIdentity, bind_request_identity
from toxicjoin.context.datahub import DataHubSnapshot, DataHubSnapshotContextResolver
from toxicjoin.context.fixture import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.disclosure.composition import is_protected_release
from toxicjoin.disclosure.models import DisclosureComposition, DisclosureScope, compute_scope_sha256
from toxicjoin.disclosure.semantic import (
    build_semantic_release_from_resolution,
    resolve_governed_subject_domain,
)
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.execute import ProofBoundExecutionAuthorizer
from toxicjoin.integrations.datahub_authority import read_only_settings_from_env
from toxicjoin.models import ColumnRef, SensitivityCategory
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.proofs import compute_agent_ppmc_provenance_hmac
from toxicjoin.prospective.forbidden import build_forbidden_predicate_policy
from toxicjoin.prospective.grammar import (
    build_future_action_grammar_context,
    instantiate_future_action_grammar,
)
from toxicjoin.prospective.ppmc import PpmcStatus, build_ppmc_search_config
from toxicjoin.prospective.twin import build_disclosure_state

NOW = datetime(2026, 7, 27, 7, 0, tzinfo=timezone.utc)
DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.agent_proof_v1,PROD)"
PURPOSE = "List approved country values for the governed customer population"
SQL = "SELECT country FROM patients WHERE customer_id IS NOT NULL"
SUBJECT_KEY = ColumnRef(dataset="patients", field_path="customer_id")
PROOF_KEY = b"agent-preexec-proof-integrity-key-32-bytes!!"
PROVENANCE_KEY = b"agent-preexec-provenance-key-32-bytes-distinct!!"
AUTH_KEY = b"agent-preexec-execution-auth-key-32-bytes!!"
IDENTITY = RequestIdentity(
    principal_id="principal-agent-preexec",
    credential_id="credential-agent-preexec",
    agent_id="agent-agent-preexec",
    session_id="session-agent-preexec",
)


class _Planner:
    def propose(self, *, goal, context):
        return {"task_purpose": PURPOSE, "sql": SQL}

    def adapt(self, *, goal, context, previous, feedback):
        return self.propose(goal=goal, context=context)


def _snapshot() -> DataHubSnapshot:
    return DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:agent-preexec-proof-v1",
            datasets={
                "patients": FixtureDataset(
                    urn=DATASET_URN,
                    owner="urn:li:corpuser:agent-preexec-owner",
                    domain="urn:li:domain:privacy",
                    fields={
                        "customer_id": FixtureField(
                            category=SensitivityCategory.STABLE_PSEUDONYM,
                            tags=("toxicjoin:stable-pseudonym",),
                        ),
                        "country": FixtureField(
                            category=SensitivityCategory.PUBLIC_OR_LOW_RISK,
                            tags=("toxicjoin:public-or-low-risk",),
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


def _upstream(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("DATAHUB_GMS_URL", "https://agent-preexec-proof.example")
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", "agent-preexec-proof-token")
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv("DATAHUB_MCP_ARGS", "mcp-server-datahub")
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")

    snapshot = _snapshot()
    planning_context = build_agent_data_context_from_snapshot(snapshot)
    goal = build_agent_goal("List non-sensitive country values for the approved population")
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
        principal_id=IDENTITY.principal_id,
        agent_id=IDENTITY.agent_id,
        subject=subject,
        scope_sha256=compute_scope_sha256(
            principal_id=IDENTITY.principal_id,
            agent_id=IDENTITY.agent_id,
            subject_namespace_sha256=subject.namespace_sha256,
        ),
    )
    composition = DisclosureComposition(
        protected_release=is_protected_release(semantic),
        release_family_sha256=semantic.semantic_sha256,
        cohort_hmac_sha256=canonical_json_sha256({"cohort": "agent-preexec-proof"}),
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
            {"warehouse": "agent-preexec-proof-a"}
        ),
    )
    grammar = instantiate_future_action_grammar(
        build_future_action_grammar_context(
            base_state=state,
            base_semantic=semantic,
            base_composition=composition,
        )
    )
    package_policy = load_policy()
    ppmc_evaluation = DataHubAgentPpmcAuthority(
        clock=lambda: NOW + timedelta(seconds=4)
    ).check(
        evaluation=evaluation,
        governance_trust=governance_trust,
        initial_state=state,
        grammar=grammar,
        forbidden_policy=build_forbidden_predicate_policy(
            minimum_group_size=package_policy.minimum_group_size
        ),
        config=build_ppmc_search_config(bound=3, max_states=128),
    )
    return snapshot, proposal, evaluation, ppmc_evaluation, state, grammar


def _proof_authority() -> DataHubAgentPreExecutionProofAuthority:
    return DataHubAgentPreExecutionProofAuthority(
        integrity_key=PROOF_KEY,
        provenance_integrity_key=PROVENANCE_KEY,
        clock=lambda: NOW + timedelta(seconds=5),
    )


def test_agent_proof_authority_surface_does_not_accept_legacy_ppmc_authority_inputs() -> None:
    parameters = inspect.signature(DataHubAgentPreExecutionProofAuthority.build).parameters

    assert "proposal" in parameters
    assert "evaluation" in parameters
    assert "ppmc_evaluation" in parameters
    assert "identity" in parameters
    assert "sql" in parameters
    assert "state" in parameters
    assert "grammar" in parameters
    assert "ppmc_result" not in parameters
    assert "governance_trust_binding" not in parameters
    assert "f6_clearance" not in parameters
    assert "policy_engine" not in parameters
    assert "integrity_key" not in parameters
    assert "provenance_integrity_key" not in parameters


def test_agent_ppmc_provenance_mints_proof_accepted_by_strict_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot, proposal, evaluation, ppmc_evaluation, state, grammar = _upstream(monkeypatch)
    assert ppmc_evaluation.ppmc_result.status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND
    assert ppmc_evaluation.ppmc_result.bound == 3

    proof = _proof_authority().build(
        proposal=proposal,
        evaluation=evaluation,
        ppmc_evaluation=ppmc_evaluation,
        identity=IDENTITY,
        sql=SQL,
        state=state,
        grammar=grammar,
    )

    provenance = proof.agent_ppmc_provenance
    assert provenance is not None
    assert provenance.agent_proposal_sha256 == evaluation.proposal_sha256
    assert provenance.agent_evaluation_sha256 == evaluation.evaluation_sha256
    assert provenance.agent_ppmc_evaluation_sha256 == ppmc_evaluation.evaluation_sha256
    assert provenance.f6_clearance_sha256 == ppmc_evaluation.f6_clearance_sha256
    assert provenance.ppmc_result_sha256 == ppmc_evaluation.ppmc_result_sha256
    assert provenance.disclosure_state_sha256 == state.state_sha256
    assert provenance.grammar_sha256 == grammar.grammar_sha256
    assert provenance.authority_hmac_sha256 == compute_agent_ppmc_provenance_hmac(
        provenance,
        integrity_key=PROVENANCE_KEY,
    )

    resolver = DataHubSnapshotContextResolver(
        snapshot,
        max_age_seconds=300,
        clock=lambda: NOW + timedelta(seconds=6),
    )
    authorizer = ProofBoundExecutionAuthorizer(
        context_resolver=resolver,
        policy_engine=PolicyEngine(load_policy()),
        privacy_proof_integrity_key=PROOF_KEY,
        agent_provenance_integrity_key=PROVENANCE_KEY,
        secret_key=AUTH_KEY,
        ttl_seconds=5,
        clock=lambda: (NOW + timedelta(seconds=6)).timestamp(),
    )

    with bind_request_identity(IDENTITY):
        authorization = authorizer.issue(
            SQL,
            task_purpose=PURPOSE,
            subject_key=SUBJECT_KEY,
            privacy_proof=proof,
            expected_governance_binding=evaluation.governance_binding,
        )

    assert authorization.privacy_proof_sha256 == proof.privacy_proof_sha256


def test_agent_proof_authority_rejects_sql_plan_rebinding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, proposal, evaluation, ppmc_evaluation, state, grammar = _upstream(monkeypatch)

    with pytest.raises(
        AgentPreExecutionProofAuthorityError,
        match="AGENT_PROOF_SQL_BINDING_MISMATCH",
    ):
        _proof_authority().build(
            proposal=proposal,
            evaluation=evaluation,
            ppmc_evaluation=ppmc_evaluation,
            identity=IDENTITY,
            sql="SELECT customer_id FROM patients",
            state=state,
            grammar=grammar,
        )


def test_agent_proof_authority_rejects_same_plan_different_proposal_sql(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, proposal, evaluation, ppmc_evaluation, state, grammar = _upstream(monkeypatch)
    same_plan_different_sql = SQL + " "

    with pytest.raises(
        AgentPreExecutionProofAuthorityError,
        match="AGENT_PROOF_SQL_BINDING_MISMATCH",
    ):
        _proof_authority().build(
            proposal=proposal,
            evaluation=evaluation,
            ppmc_evaluation=ppmc_evaluation,
            identity=IDENTITY,
            sql=same_plan_different_sql,
            state=state,
            grammar=grammar,
        )


def test_agent_proof_authority_rejects_reused_provenance_key() -> None:
    with pytest.raises(
        AgentPreExecutionProofAuthorityError,
        match="AGENT_PROOF_INTEGRITY_KEY_INVALID",
    ):
        DataHubAgentPreExecutionProofAuthority(
            integrity_key=PROOF_KEY,
            provenance_integrity_key=PROOF_KEY,
        )
