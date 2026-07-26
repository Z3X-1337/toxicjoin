from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import SecretStr, ValidationError

from toxicjoin.agent import (
    AgentProposalAuthorityError,
    DataHubAgentProposalAuthority,
    GovernedAgent,
    TrustedAgentProposalEvaluation,
    build_agent_data_context,
    build_agent_data_context_from_snapshot,
    build_agent_goal,
)
from toxicjoin.context.datahub import DataHubSnapshot
from toxicjoin.context.fixture import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.evidence.derivation import (
    DataHubDerivationValidation,
    compute_datahub_derivation_validation_sha256,
)
from toxicjoin.integrations.datahub_authority import (
    ReadOnlyDataHubMcpSettings,
    read_only_settings_from_env,
)
from toxicjoin.models import ColumnRef, Decision, SensitivityCategory
from toxicjoin.policy import PolicyEngine, load_policy


NOW = datetime(2026, 7, 26, 1, 45, tzinfo=timezone.utc)
DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.day13_patients,PROD)"
SQL = (
    "SELECT COUNT(diagnosis) AS diagnosis_count "
    "FROM patients "
    "HAVING COUNT(DISTINCT customer_id) >= 20"
)
PURPOSE = "Count diagnoses with the approved subject threshold"
GOAL_TEXT = "Count diagnoses without releasing individual records"
LIVE_READ_TOKEN = "day13-distinctive-live-read-token"


class StaticPlannerAdapter:
    def __init__(self, *, purpose: str = PURPOSE) -> None:
        self.purpose = purpose

    def propose(self, *, goal, context):
        return {
            "task_purpose": self.purpose,
            "sql": SQL,
        }

    def adapt(self, *, goal, context, previous, feedback):
        return self.propose(goal=goal, context=context)


def _snapshot() -> DataHubSnapshot:
    return DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:day13-proposal-authority-v1",
            datasets={
                "patients": FixtureDataset(
                    urn=DATASET_URN,
                    owner="urn:li:corpuser:data-owner",
                    domain="urn:li:domain:clinical-security",
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
        lineage_sample={"relationships": [{"source": DATASET_URN}]},
        discovered_tools=("get_entities", "get_lineage", "list_schema_fields"),
        observed_at=NOW,
    )


def _read_settings(monkeypatch) -> ReadOnlyDataHubMcpSettings:
    monkeypatch.setenv("DATAHUB_GMS_URL", "http://127.0.0.1:8080")
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", LIVE_READ_TOKEN)
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv("DATAHUB_MCP_ARGS", "mcp-server-datahub")
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")
    return read_only_settings_from_env()


def _authority(
    monkeypatch,
    snapshot: DataHubSnapshot,
    *,
    clock=lambda: NOW + timedelta(seconds=1),
) -> DataHubAgentProposalAuthority:
    return DataHubAgentProposalAuthority(
        snapshot=snapshot,
        read_settings=_read_settings(monkeypatch),
        policy_engine=PolicyEngine(load_policy()),
        clock=clock,
        datahub_max_age_seconds=300,
    )


def _proposal(
    snapshot: DataHubSnapshot,
    *,
    source_sha256: str | None = None,
    proposed_purpose: str = PURPOSE,
):
    context = build_agent_data_context_from_snapshot(snapshot)
    if source_sha256 is not None:
        context = build_agent_data_context(
            source_snapshot_sha256=source_sha256,
            catalog_version=context.catalog_version,
            datasets=context.datasets,
        )
    goal = build_agent_goal(GOAL_TEXT)
    agent = GovernedAgent(StaticPlannerAdapter(purpose=proposed_purpose))
    proposal = agent.propose(goal=goal, context=context)
    return goal, context, proposal


def _evaluate(authority, *, goal, context, proposal):
    return authority.evaluate(
        proposal=proposal,
        goal=goal,
        planning_context=context,
        authorized_task_purpose=PURPOSE,
        subject_key=ColumnRef(dataset="patients", field_path="customer_id"),
    )


def test_security_side_intake_regrounds_and_allows_day8_local_candidate(monkeypatch) -> None:
    snapshot = _snapshot()
    goal, context, proposal = _proposal(snapshot)
    authority = _authority(monkeypatch, snapshot)

    evaluation = _evaluate(
        authority,
        goal=goal,
        context=context,
        proposal=proposal,
    )

    assert evaluation.security_authoritative is True
    assert evaluation.evidence_trust_resolved is False
    assert evaluation.prospective_privacy_checked is False
    assert evaluation.execution_authorized is False
    assert evaluation.proposal_sha256 == proposal.proposal_sha256
    assert evaluation.goal_sha256 == goal.goal_sha256
    assert evaluation.planning_context_sha256 == context.context_sha256
    assert evaluation.source_snapshot_sha256 == snapshot.snapshot_sha256
    assert evaluation.authorized_task_purpose == PURPOSE
    assert evaluation.subject_key == ColumnRef(
        dataset="patients",
        field_path="customer_id",
    )
    assert evaluation.governance_binding.snapshot_sha256 == snapshot.snapshot_sha256
    assert evaluation.evidence_bundle.snapshot_sha256 == snapshot.snapshot_sha256
    assert evaluation.evidence_validation.snapshot_sha256 == snapshot.snapshot_sha256
    assert evaluation.policy_input.task_purpose == PURPOSE
    assert evaluation.policy_input.query_plan == evaluation.query_plan
    assert evaluation.policy_input.subject_key == evaluation.subject_key
    assert evaluation.policy_decision.decision == Decision.ALLOW
    assert evaluation.policy_decision.policy_version == evaluation.policy_version
    assert len(evaluation.policy_input_sha256) == 64
    assert len(evaluation.policy_config_sha256) == 64
    assert len(evaluation.evaluation_sha256) == 64


def test_agent_cannot_escalate_policy_purpose(monkeypatch) -> None:
    snapshot = _snapshot()
    goal, context, proposal = _proposal(
        snapshot,
        proposed_purpose="Emergency unrestricted research access",
    )
    authority = _authority(monkeypatch, snapshot)

    with pytest.raises(
        AgentProposalAuthorityError,
        match="AGENT_AUTHORITY_PURPOSE_BINDING_MISMATCH",
    ):
        _evaluate(
            authority,
            goal=goal,
            context=context,
            proposal=proposal,
        )


def test_planning_context_cannot_rebind_proposal_to_another_snapshot(monkeypatch) -> None:
    snapshot = _snapshot()
    goal, context, proposal = _proposal(snapshot, source_sha256="f" * 64)
    authority = _authority(monkeypatch, snapshot)

    with pytest.raises(
        AgentProposalAuthorityError,
        match="AGENT_AUTHORITY_SNAPSHOT_BINDING_MISMATCH",
    ):
        _evaluate(
            authority,
            goal=goal,
            context=context,
            proposal=proposal,
        )


def test_goal_commitment_cannot_be_substituted(monkeypatch) -> None:
    snapshot = _snapshot()
    _, context, proposal = _proposal(snapshot)
    substituted_goal = build_agent_goal("A different request")
    authority = _authority(monkeypatch, snapshot)

    with pytest.raises(
        AgentProposalAuthorityError,
        match="AGENT_AUTHORITY_GOAL_BINDING_MISMATCH",
    ):
        _evaluate(
            authority,
            goal=substituted_goal,
            context=context,
            proposal=proposal,
        )


def test_authority_resamples_time_and_rejects_snapshot_after_expiry(monkeypatch) -> None:
    snapshot = _snapshot()
    goal, context, proposal = _proposal(snapshot)
    times = iter(
        (
            NOW + timedelta(seconds=1),
            NOW + timedelta(seconds=1),
            NOW + timedelta(seconds=1),
            NOW + timedelta(seconds=301),
        )
    )
    authority = _authority(monkeypatch, snapshot, clock=lambda: next(times))

    first = _evaluate(
        authority,
        goal=goal,
        context=context,
        proposal=proposal,
    )
    assert first.policy_decision.decision == Decision.ALLOW

    with pytest.raises(
        AgentProposalAuthorityError,
        match="AGENT_AUTHORITY_EVIDENCE_STALE",
    ):
        _evaluate(
            authority,
            goal=goal,
            context=context,
            proposal=proposal,
        )


def test_authority_rechecks_freshness_immediately_before_issuance(monkeypatch) -> None:
    snapshot = _snapshot()
    goal, context, proposal = _proposal(snapshot)
    times = iter(
        (
            NOW + timedelta(seconds=299),
            NOW + timedelta(seconds=301),
        )
    )
    authority = _authority(monkeypatch, snapshot, clock=lambda: next(times))

    with pytest.raises(
        AgentProposalAuthorityError,
        match="AGENT_AUTHORITY_STALE_AT_ISSUE",
    ):
        _evaluate(
            authority,
            goal=goal,
            context=context,
            proposal=proposal,
        )


def test_authority_rejects_policy_config_drift_after_binding(monkeypatch) -> None:
    snapshot = _snapshot()
    goal, context, proposal = _proposal(snapshot)
    authority = _authority(monkeypatch, snapshot)
    authority._policy_engine_source.config = authority._policy_engine_source.config.model_copy(
        update={
            "minimum_group_size": authority._policy_engine_source.config.minimum_group_size + 1
        }
    )

    with pytest.raises(
        AgentProposalAuthorityError,
        match="AGENT_AUTHORITY_POLICY_CHANGED",
    ):
        _evaluate(
            authority,
            goal=goal,
            context=context,
            proposal=proposal,
        )


def test_authority_rejects_directly_constructed_unregistered_read_credential() -> None:
    snapshot = _snapshot()
    unregistered = ReadOnlyDataHubMcpSettings(
        gms_url="http://127.0.0.1:8080",
        gms_token=SecretStr("unregistered-read-token"),
        command="uvx",
        args=("mcp-server-datahub",),
        timeout_seconds=30.0,
    )

    with pytest.raises(AgentProposalAuthorityError, match="AGENT_AUTHORITY_SOURCE_INVALID") as exc:
        DataHubAgentProposalAuthority(
            snapshot=snapshot,
            read_settings=unregistered,
            policy_engine=PolicyEngine(load_policy()),
            clock=lambda: NOW + timedelta(seconds=1),
        )

    assert exc.value.__cause__ is None


def test_authority_retains_only_redacted_datahub_source_identity(monkeypatch) -> None:
    snapshot = _snapshot()
    raw_endpoint_secret = "raw-endpoint-credential"
    raw_launcher_secret = "raw-launcher-credential"
    monkeypatch.setenv(
        "DATAHUB_GMS_URL",
        f"https://datahub.internal:8443/graphql/{raw_endpoint_secret}",
    )
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", LIVE_READ_TOKEN)
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv(
        "DATAHUB_MCP_ARGS",
        f"mcp-server-datahub --opaque-ref={raw_launcher_secret}",
    )
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")
    settings = read_only_settings_from_env()

    authority = DataHubAgentProposalAuthority(
        snapshot=snapshot,
        read_settings=settings,
        policy_engine=PolicyEngine(load_policy()),
        clock=lambda: NOW + timedelta(seconds=1),
    )
    retained = repr(vars(authority))

    assert "_source_settings" not in vars(authority)
    assert authority._source_identity.startswith("datahub-mcp:gms_sha256=")
    assert LIVE_READ_TOKEN not in retained
    assert raw_endpoint_secret not in retained
    assert raw_launcher_secret not in retained


def test_trusted_evaluation_rejects_validation_source_rebinding(monkeypatch) -> None:
    snapshot = _snapshot()
    goal, context, proposal = _proposal(snapshot)
    evaluation = _evaluate(
        _authority(monkeypatch, snapshot),
        goal=goal,
        context=context,
        proposal=proposal,
    )
    payload = evaluation.model_dump(mode="json")

    forged_payload = evaluation.evidence_validation.model_dump(mode="python")
    forged_payload["source_identity"] = "datahub-mcp:forged"
    forged_payload["validation_sha256"] = "0" * 64
    forged = DataHubDerivationValidation.model_construct(**forged_payload)
    forged_payload["validation_sha256"] = compute_datahub_derivation_validation_sha256(forged)
    payload["evidence_validation"] = DataHubDerivationValidation.model_construct(
        **forged_payload
    ).model_dump(mode="json")

    with pytest.raises(ValidationError, match="evidence validation source mismatch"):
        TrustedAgentProposalEvaluation.model_validate(payload)


def test_trusted_evaluation_rejects_policy_input_tampering(monkeypatch) -> None:
    snapshot = _snapshot()
    goal, context, proposal = _proposal(snapshot)
    evaluation = _evaluate(
        _authority(monkeypatch, snapshot),
        goal=goal,
        context=context,
        proposal=proposal,
    )
    payload = evaluation.model_dump(mode="json")
    payload["policy_input"]["task_purpose"] = "tampered-purpose"

    with pytest.raises(
        ValidationError,
        match="trusted Agent policy input does not match grounded request",
    ):
        TrustedAgentProposalEvaluation.model_validate(payload)


def test_trusted_evaluation_cannot_claim_later_stage_authority(monkeypatch) -> None:
    snapshot = _snapshot()
    goal, context, proposal = _proposal(snapshot)
    evaluation = _evaluate(
        _authority(monkeypatch, snapshot),
        goal=goal,
        context=context,
        proposal=proposal,
    )
    payload = evaluation.model_dump(mode="json")
    payload["evidence_trust_resolved"] = True

    with pytest.raises(ValidationError):
        TrustedAgentProposalEvaluation.model_validate(payload)


def test_trusted_evaluation_hash_tampering_is_rejected(monkeypatch) -> None:
    snapshot = _snapshot()
    goal, context, proposal = _proposal(snapshot)
    evaluation = _evaluate(
        _authority(monkeypatch, snapshot),
        goal=goal,
        context=context,
        proposal=proposal,
    )
    payload = evaluation.model_dump(mode="json")
    payload["evaluation_sha256"] = "0" * 64

    with pytest.raises(ValidationError, match="trusted Agent evaluation hash mismatch"):
        TrustedAgentProposalEvaluation.model_validate(payload)
