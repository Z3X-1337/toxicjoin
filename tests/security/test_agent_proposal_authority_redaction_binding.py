from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import SecretStr, ValidationError

from toxicjoin.agent import (
    AgentProposalAuthorityError,
    DataHubAgentProposalAuthority,
    GovernedAgent,
    TrustedAgentProposalEvaluation,
    build_agent_data_context_from_snapshot,
    build_agent_goal,
    compute_trusted_agent_proposal_evaluation_sha256,
)
from toxicjoin.context.datahub import DataHubSnapshot
from toxicjoin.context.fixture import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.integrations.datahub_authority import (
    ReadOnlyDataHubMcpSettings,
    read_only_settings_from_env,
)
from toxicjoin.models import ColumnRef, SensitivityCategory
from toxicjoin.policy import PolicyEngine, load_policy

NOW = datetime(2026, 7, 26, 8, 55, tzinfo=timezone.utc)
DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.day13_binding,PROD)"
SQL = (
    "SELECT COUNT(diagnosis) AS diagnosis_count "
    "FROM patients "
    "HAVING COUNT(DISTINCT customer_id) >= 20"
)
PURPOSE = "Count diagnoses with the approved subject threshold"
READ_TOKEN = "day13-constructor-traceback-read-token"


class _Planner:
    def propose(self, *, goal, context):
        return {"task_purpose": PURPOSE, "sql": SQL}

    def adapt(self, *, goal, context, previous, feedback):
        return self.propose(goal=goal, context=context)


def _snapshot(*, reflected_tag: str | None = None) -> DataHubSnapshot:
    tags = (reflected_tag,) if reflected_tag is not None else ()
    return DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:day13-binding-v1",
            datasets={
                "patients": FixtureDataset(
                    urn=DATASET_URN,
                    fields={
                        "customer_id": FixtureField(
                            category=SensitivityCategory.STABLE_PSEUDONYM,
                            tags=tags,
                        ),
                        "diagnosis": FixtureField(
                            category=SensitivityCategory.SENSITIVE_ATTRIBUTE,
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


def _registered_settings(monkeypatch: pytest.MonkeyPatch) -> ReadOnlyDataHubMcpSettings:
    monkeypatch.setenv("DATAHUB_GMS_URL", "https://day13-binding.example")
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", READ_TOKEN)
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv("DATAHUB_MCP_ARGS", "mcp-server-datahub")
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")
    return read_only_settings_from_env()


def _evaluation(monkeypatch: pytest.MonkeyPatch):
    snapshot = _snapshot()
    context = build_agent_data_context_from_snapshot(snapshot)
    goal = build_agent_goal("Count diagnoses without releasing individual records")
    proposal = GovernedAgent(_Planner()).propose(goal=goal, context=context)
    authority = DataHubAgentProposalAuthority(
        snapshot=snapshot,
        read_settings=_registered_settings(monkeypatch),
        policy_engine=PolicyEngine(load_policy()),
        clock=lambda: NOW + timedelta(seconds=1),
        datahub_max_age_seconds=300,
    )
    return authority.evaluate(
        proposal=proposal,
        goal=goal,
        planning_context=context,
        authorized_task_purpose=PURPOSE,
        subject_key=ColumnRef(dataset="patients", field_path="customer_id"),
    )


def test_source_validation_error_does_not_retain_read_credential_in_traceback() -> None:
    unregistered = ReadOnlyDataHubMcpSettings(
        gms_url="https://traceback.example",
        gms_token=SecretStr(READ_TOKEN),
        command="uvx",
        args=("mcp-server-datahub",),
        timeout_seconds=30.0,
    )

    try:
        DataHubAgentProposalAuthority(
            snapshot=_snapshot(),
            read_settings=unregistered,
            policy_engine=PolicyEngine(load_policy()),
            clock=lambda: NOW + timedelta(seconds=1),
        )
    except AgentProposalAuthorityError as error:
        assert error.__context__ is None
        assert error.__cause__ is None
        cursor = error.__traceback__
        observed_authority_frame = False
        while cursor is not None:
            frame = cursor.tb_frame
            if frame.f_globals.get("__name__") == "toxicjoin.agent.proposal_authority":
                observed_authority_frame = True
                for name, value in frame.f_locals.items():
                    assert not isinstance(value, ReadOnlyDataHubMcpSettings), (
                        f"traceback local {name!r} retained DataHub read settings"
                    )
                    assert not isinstance(value, SecretStr), (
                        f"traceback local {name!r} retained bearer wrapper"
                    )
            cursor = cursor.tb_next
        assert observed_authority_frame is True
    else:
        raise AssertionError("unregistered read credential was accepted")


def test_authority_rejects_runtime_bearer_reflected_through_datahub_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _registered_settings(monkeypatch)
    snapshot = _snapshot(reflected_tag=f"classification:prefix-{READ_TOKEN}-suffix")

    with pytest.raises(AgentProposalAuthorityError, match="AGENT_AUTHORITY_SOURCE_INVALID"):
        DataHubAgentProposalAuthority(
            snapshot=snapshot,
            read_settings=settings,
            policy_engine=PolicyEngine(load_policy()),
            clock=lambda: NOW + timedelta(seconds=1),
        )


def test_trusted_evaluation_cross_binds_evidence_snapshot_to_source_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluation = _evaluation(monkeypatch)
    forged_snapshot = "f" * 64
    forged_binding = evaluation.governance_binding.model_copy(
        update={"snapshot_sha256": forged_snapshot}
    )
    forged_governance_sha256 = canonical_json_sha256(
        {
            "resolution": evaluation.resolution.model_dump(mode="json"),
            "binding": forged_binding.model_dump(mode="json"),
        }
    )
    provisional = evaluation.model_copy(
        update={
            "source_snapshot_sha256": forged_snapshot,
            "governance_binding": forged_binding,
            "governance_sha256": forged_governance_sha256,
            "evaluation_sha256": "0" * 64,
        }
    )
    forged = provisional.model_copy(
        update={
            "evaluation_sha256": compute_trusted_agent_proposal_evaluation_sha256(
                provisional
            )
        }
    )

    with pytest.raises(ValidationError, match="evidence snapshot mismatch"):
        TrustedAgentProposalEvaluation.model_validate(forged.model_dump(mode="json"))
