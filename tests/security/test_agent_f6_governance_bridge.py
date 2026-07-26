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
from toxicjoin.agent.f6_governance import (
    DataHubF6GovernanceAuthority,
    F6GovernanceClearance,
    F6GovernanceClearanceError,
)
from toxicjoin.agent.governance_trust import (
    GovernanceTrustBinding,
    compute_governance_trust_binding_sha256,
)
from toxicjoin.context.datahub import DataHubSnapshot
from toxicjoin.context.fixture import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.disclosure.composition import is_protected_release
from toxicjoin.disclosure.models import DisclosureComposition, DisclosureScope, compute_scope_sha256
from toxicjoin.disclosure.semantic import (
    build_semantic_release_from_resolution,
    resolve_governed_subject_domain,
)
from toxicjoin.evidence import EvidenceTrustState, build_evidence_resolution
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.integrations.datahub_authority import read_only_settings_from_env
from toxicjoin.models import ColumnRef, LineageSource, SensitivityCategory
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.prospective.forbidden import (
    ForbiddenPredicateId,
    ForbiddenPredicateStatus,
    build_forbidden_predicate_policy,
    build_temporal_path_context,
    evaluate_forbidden_state,
)
from toxicjoin.prospective.twin import DisclosureState, build_disclosure_state


NOW = datetime(2026, 7, 27, 3, 0, tzinfo=timezone.utc)
PATIENTS_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.day13_f6_patients,PROD)"
CUSTOMERS_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.day13_f6_customers,PROD)"
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


class _MutableClock:
    def __init__(self, current: datetime) -> None:
        self.current = current

    def __call__(self) -> datetime:
        return self.current


def _snapshot() -> DataHubSnapshot:
    return DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:day13-f6-governance-v1",
            datasets={
                "customers": FixtureDataset(
                    urn=CUSTOMERS_URN,
                    fields={
                        "customer_id": FixtureField(
                            category=SensitivityCategory.STABLE_PSEUDONYM,
                            tags=("stable-customer-identifier",),
                        )
                    },
                ),
                "patients": FixtureDataset(
                    urn=PATIENTS_URN,
                    fields={
                        "customer_id": FixtureField(
                            category=SensitivityCategory.STABLE_PSEUDONYM,
                            tags=("stable-customer-identifier",),
                        ),
                        "diagnosis": FixtureField(
                            category=SensitivityCategory.SENSITIVE_ATTRIBUTE,
                            tags=("toxicjoin-sensitive-attribute",),
                            lineage_sources=(
                                LineageSource(
                                    ref=ColumnRef(dataset="customers", field_path="customer_id"),
                                    category=SensitivityCategory.STABLE_PSEUDONYM,
                                    datahub_urn=CUSTOMERS_URN,
                                ),
                            ),
                        ),
                    },
                ),
            },
        ),
        verified_entities=(CUSTOMERS_URN, PATIENTS_URN),
        field_counts={"customers": 1, "patients": 2},
        lineage_sample={"relationships": [{"source": CUSTOMERS_URN}]},
        discovered_tools=("get_entities", "get_lineage", "list_schema_fields"),
        observed_at=NOW,
    )


def _evaluation_and_binding(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("DATAHUB_GMS_URL", "https://day13-f6.example")
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", "day13-f6-read-token")
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
    binding = DataHubGovernanceTrustAuthority(
        clock=lambda: NOW + timedelta(seconds=2)
    ).bind(evaluation)
    return snapshot, evaluation, binding


def _state(snapshot: DataHubSnapshot, evaluation, **overrides) -> DisclosureState:
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
        principal_id="principal-day13-f6",
        agent_id="agent-day13-f6",
        subject=subject,
        scope_sha256=compute_scope_sha256(
            principal_id="principal-day13-f6",
            agent_id="agent-day13-f6",
            subject_namespace_sha256=subject.namespace_sha256,
        ),
    )
    composition = DisclosureComposition(
        protected_release=is_protected_release(semantic),
        release_family_sha256=semantic.semantic_sha256,
        cohort_hmac_sha256=canonical_json_sha256({"cohort": "day13-f6"}),
    )
    values = {
        "purpose_commitment_sha256": evaluation.authorized_task_purpose_sha256,
        "governance_commitment_sha256": canonical_json_sha256(
            evaluation.governance_binding.model_dump(mode="json")
        ),
        "evidence_root_sha256": evaluation.evidence_bundle.evidence_root_sha256,
        "warehouse_snapshot_sha256": canonical_json_sha256({"warehouse": "day13-f6-a"}),
    }
    values.update(overrides)
    return build_disclosure_state(
        scope=scope,
        audit_history=(),
        candidate_semantic=semantic,
        candidate_composition=composition,
        **values,
    )


def _f6_status(state: DisclosureState, clearance: F6GovernanceClearance):
    policy = load_policy()
    evaluation = evaluate_forbidden_state(
        state,
        policy=build_forbidden_predicate_policy(
            minimum_group_size=policy.minimum_group_size
        ),
        governance_binding=clearance.f6_binding,
        temporal_path=build_temporal_path_context(()),
    )
    return next(
        item
        for item in evaluation.predicates
        if item.predicate_id == ForbiddenPredicateId.F6_UNTRUSTED_GOVERNANCE_AUTHORIZATION
    )


def test_positive_security_owned_bridge_clears_f6(monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot, evaluation, binding = _evaluation_and_binding(monkeypatch)
    state = _state(snapshot, evaluation)

    clearance = DataHubF6GovernanceAuthority(
        clock=lambda: NOW + timedelta(seconds=3)
    ).clear(evaluation=evaluation, governance_trust=binding, state=state)

    assert clearance.evaluation_sha256 == evaluation.evaluation_sha256
    assert clearance.governance_trust_binding_sha256 == binding.binding_sha256
    assert clearance.disclosure_state_sha256 == state.state_sha256
    assert clearance.f6_binding.trusted is True
    assert clearance.f6_binding.trust_evidence_sha256 == binding.binding_sha256
    assert clearance.prospective_privacy_checked is False
    assert clearance.execution_authorized is False
    assert _f6_status(state, clearance).status == ForbiddenPredicateStatus.CLEAR


def test_self_consistent_subset_binding_cannot_clear_f6(monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot, evaluation, binding = _evaluation_and_binding(monkeypatch)
    state = _state(snapshot, evaluation)
    provisional = binding.model_copy(
        update={
            "requirements": binding.requirements[:-1],
            "resolutions": binding.resolutions[:-1],
            "binding_sha256": "0" * 64,
        }
    )
    forged = GovernanceTrustBinding.model_validate(
        provisional.model_copy(
            update={
                "binding_sha256": compute_governance_trust_binding_sha256(provisional)
            }
        ).model_dump(mode="json")
    )

    with pytest.raises(
        F6GovernanceClearanceError,
        match="F6_GOVERNANCE_REQUIREMENTS_MISMATCH",
    ):
        DataHubF6GovernanceAuthority(clock=lambda: NOW + timedelta(seconds=3)).clear(
            evaluation=evaluation,
            governance_trust=forged,
            state=state,
        )


def test_forged_trusted_resolution_cannot_clear_f6(monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot, evaluation, binding = _evaluation_and_binding(monkeypatch)
    state = _state(snapshot, evaluation)
    original = binding.resolutions[0]
    forged_resolution = build_evidence_resolution(
        subject=original.subject,
        predicate=original.predicate,
        state=EvidenceTrustState.TRUSTED,
        value=original.value,
        claim_ids=("evc_" + "f" * 32,),
        policy_version=original.policy_version,
    )
    provisional = binding.model_copy(
        update={
            "resolutions": (forged_resolution, *binding.resolutions[1:]),
            "binding_sha256": "0" * 64,
        }
    )
    forged = GovernanceTrustBinding.model_validate(
        provisional.model_copy(
            update={
                "binding_sha256": compute_governance_trust_binding_sha256(provisional)
            }
        ).model_dump(mode="json")
    )

    with pytest.raises(
        F6GovernanceClearanceError,
        match="F6_GOVERNANCE_RESOLUTIONS_MISMATCH",
    ):
        DataHubF6GovernanceAuthority(clock=lambda: NOW + timedelta(seconds=3)).clear(
            evaluation=evaluation,
            governance_trust=forged,
            state=state,
        )


@pytest.mark.parametrize(
    ("override", "code"),
    [
        ({"purpose_commitment_sha256": "a" * 64}, "F6_STATE_PURPOSE_MISMATCH"),
        ({"governance_commitment_sha256": "b" * 64}, "F6_STATE_GOVERNANCE_MISMATCH"),
        ({"evidence_root_sha256": "c" * 64}, "F6_STATE_EVIDENCE_MISMATCH"),
    ],
)
def test_state_commitments_must_match_exact_evaluation(
    monkeypatch: pytest.MonkeyPatch,
    override: dict[str, str],
    code: str,
) -> None:
    snapshot, evaluation, binding = _evaluation_and_binding(monkeypatch)
    state = _state(snapshot, evaluation, **override)

    with pytest.raises(F6GovernanceClearanceError, match=code):
        DataHubF6GovernanceAuthority(clock=lambda: NOW + timedelta(seconds=3)).clear(
            evaluation=evaluation,
            governance_trust=binding,
            state=state,
        )


def test_binding_from_future_cannot_clear_f6(monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot, evaluation, binding = _evaluation_and_binding(monkeypatch)
    state = _state(snapshot, evaluation)

    with pytest.raises(
        F6GovernanceClearanceError,
        match="F6_GOVERNANCE_BINDING_FROM_FUTURE",
    ):
        DataHubF6GovernanceAuthority(clock=lambda: NOW + timedelta(seconds=1)).clear(
            evaluation=evaluation,
            governance_trust=binding,
            state=state,
        )


def test_stale_governance_cannot_clear_f6(monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot, evaluation, binding = _evaluation_and_binding(monkeypatch)
    state = _state(snapshot, evaluation)

    with pytest.raises(
        F6GovernanceClearanceError,
        match="F6_GOVERNANCE_STALE",
    ):
        DataHubF6GovernanceAuthority(clock=lambda: NOW + timedelta(seconds=301)).clear(
            evaluation=evaluation,
            governance_trust=binding,
            state=state,
        )


def test_clock_rollback_across_clearances_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot, evaluation, binding = _evaluation_and_binding(monkeypatch)
    state = _state(snapshot, evaluation)
    clock = _MutableClock(NOW + timedelta(seconds=10))
    authority = DataHubF6GovernanceAuthority(clock=clock)

    first = authority.clear(evaluation=evaluation, governance_trust=binding, state=state)
    assert first.f6_binding.trusted is True

    clock.current = NOW + timedelta(seconds=5)
    with pytest.raises(F6GovernanceClearanceError, match="F6_GOVERNANCE_TIME_ROLLBACK"):
        authority.clear(evaluation=evaluation, governance_trust=binding, state=state)


def test_clearance_hash_tampering_is_rejected(monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot, evaluation, binding = _evaluation_and_binding(monkeypatch)
    state = _state(snapshot, evaluation)
    clearance = DataHubF6GovernanceAuthority(
        clock=lambda: NOW + timedelta(seconds=3)
    ).clear(evaluation=evaluation, governance_trust=binding, state=state)
    payload = clearance.model_dump(mode="json")
    payload["clearance_sha256"] = "0" * 64

    with pytest.raises(ValidationError, match="F6 governance clearance hash mismatch"):
        F6GovernanceClearance.model_validate(payload)
