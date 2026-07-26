from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from toxicjoin.agent import (
    DataHubAgentProposalAuthority,
    DataHubGovernanceTrustAuthority,
    GovernedAgent,
    TrustedAgentProposalEvaluation,
    build_agent_data_context_from_snapshot,
    build_agent_goal,
    compute_trusted_agent_proposal_evaluation_sha256,
)
from toxicjoin.agent.f6_governance import (
    DataHubF6GovernanceAuthority,
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
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.integrations.datahub_authority import read_only_settings_from_env
from toxicjoin.models import ColumnRef, ReasonCode, SensitivityCategory
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.prospective.twin import (
    DisclosureState,
    build_disclosure_state,
    compute_disclosure_state_sha256,
)


NOW = datetime(2026, 7, 27, 4, 0, tzinfo=timezone.utc)
DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.day13_f6_parity,PROD)"
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


def _artifacts(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("DATAHUB_GMS_URL", "https://day13-f6-parity.example")
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", "day13-f6-parity-token")
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv("DATAHUB_MCP_ARGS", "mcp-server-datahub")
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")

    snapshot = DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:day13-f6-parity-v1",
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
        principal_id="principal-day13-f6-parity",
        agent_id="agent-day13-f6-parity",
        subject=subject,
        scope_sha256=compute_scope_sha256(
            principal_id="principal-day13-f6-parity",
            agent_id="agent-day13-f6-parity",
            subject_namespace_sha256=subject.namespace_sha256,
        ),
    )
    composition = DisclosureComposition(
        protected_release=is_protected_release(semantic),
        release_family_sha256=semantic.semantic_sha256,
        cohort_hmac_sha256=canonical_json_sha256({"cohort": "day13-f6-parity"}),
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
        warehouse_snapshot_sha256=canonical_json_sha256({"warehouse": "day13-f6-parity"}),
    )
    return evaluation, binding, state


def _forge_evaluation(
    evaluation: TrustedAgentProposalEvaluation,
    *,
    governance_binding=None,
    resolution=None,
) -> TrustedAgentProposalEvaluation:
    forged_governance_binding = governance_binding or evaluation.governance_binding
    forged_resolution = resolution or evaluation.resolution
    forged_policy_input = forged_resolution.to_policy_input(
        task_purpose=evaluation.authorized_task_purpose,
        query_plan=evaluation.query_plan,
        subject_key=evaluation.subject_key,
    )
    governance_sha256 = canonical_json_sha256(
        {
            "resolution": forged_resolution.model_dump(mode="json"),
            "binding": forged_governance_binding.model_dump(mode="json"),
        }
    )
    provisional = evaluation.model_copy(
        update={
            "resolution": forged_resolution,
            "governance_binding": forged_governance_binding,
            "governance_sha256": governance_sha256,
            "policy_input": forged_policy_input,
            "policy_input_sha256": canonical_json_sha256(
                forged_policy_input.model_dump(mode="json")
            ),
            "evaluation_sha256": "0" * 64,
        }
    )
    return TrustedAgentProposalEvaluation.model_validate(
        provisional.model_copy(
            update={
                "evaluation_sha256": compute_trusted_agent_proposal_evaluation_sha256(
                    provisional
                )
            }
        ).model_dump(mode="json")
    )


def _forge_binding(
    binding: GovernanceTrustBinding,
    evaluation: TrustedAgentProposalEvaluation,
) -> GovernanceTrustBinding:
    provisional = binding.model_copy(
        update={
            "evaluation_sha256": evaluation.evaluation_sha256,
            "governance_sha256": evaluation.governance_sha256,
            "binding_sha256": "0" * 64,
        }
    )
    return GovernanceTrustBinding.model_validate(
        provisional.model_copy(
            update={
                "binding_sha256": compute_governance_trust_binding_sha256(provisional)
            }
        ).model_dump(mode="json")
    )


def _forge_state(
    state: DisclosureState,
    evaluation: TrustedAgentProposalEvaluation,
) -> DisclosureState:
    provisional = state.model_copy(
        update={
            "governance_commitment_sha256": canonical_json_sha256(
                evaluation.governance_binding.model_dump(mode="json")
            ),
            "state_sha256": "0" * 64,
        }
    )
    return DisclosureState.model_validate(
        provisional.model_copy(
            update={"state_sha256": compute_disclosure_state_sha256(provisional)}
        ).model_dump(mode="json")
    )


def test_self_consistent_provider_source_rebinding_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluation, binding, state = _artifacts(monkeypatch)
    forged_evaluation = _forge_evaluation(
        evaluation,
        governance_binding=evaluation.governance_binding.model_copy(
            update={"source": "forged-provider"}
        ),
    )
    forged_binding = _forge_binding(binding, forged_evaluation)
    forged_state = _forge_state(state, forged_evaluation)

    with pytest.raises(
        F6GovernanceClearanceError,
        match="F6_GOVERNANCE_SOURCE_MISMATCH",
    ):
        DataHubF6GovernanceAuthority(clock=lambda: NOW + timedelta(seconds=3)).clear(
            evaluation=forged_evaluation,
            governance_trust=forged_binding,
            state=forged_state,
        )


def test_self_consistent_grounding_failure_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluation, binding, state = _artifacts(monkeypatch)
    forged_evaluation = _forge_evaluation(
        evaluation,
        resolution=evaluation.resolution.model_copy(
            update={"failures": (ReasonCode.UNRESOLVED_COLUMN,)}
        ),
    )
    forged_binding = _forge_binding(binding, forged_evaluation)
    forged_state = _forge_state(state, forged_evaluation)

    with pytest.raises(
        F6GovernanceClearanceError,
        match="F6_GOVERNANCE_GROUNDING_INCOMPLETE",
    ):
        DataHubF6GovernanceAuthority(clock=lambda: NOW + timedelta(seconds=3)).clear(
            evaluation=forged_evaluation,
            governance_trust=forged_binding,
            state=forged_state,
        )
