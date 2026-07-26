from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from toxicjoin.agent import (
    AgentProposalAuthorityError,
    DataHubAgentProposalAuthority,
    GovernedAgent,
    build_agent_data_context_from_snapshot,
    build_agent_goal,
)
from toxicjoin.agent.models import (
    AgentDataContext,
    AgentGoal,
    AgentProposal,
    compute_agent_proposal_sha256,
)
from toxicjoin.context.datahub import DataHubSnapshot
from toxicjoin.context.fixture import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.integrations.datahub_authority import (
    ReadOnlyDataHubMcpSettings,
    read_only_settings_from_env,
)
from toxicjoin.models import ColumnRef, SensitivityCategory
from toxicjoin.policy import PolicyEngine, load_policy


NOW = datetime(2026, 7, 26, 13, 0, tzinfo=timezone.utc)
DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.day13_final_review,PROD)"
SQL = (
    "SELECT COUNT(diagnosis) AS diagnosis_count "
    "FROM patients "
    "HAVING COUNT(DISTINCT customer_id) >= 20"
)
PURPOSE = "Count diagnoses with the approved subject threshold"
GOAL_TEXT = "Count diagnoses without releasing individual records"
READ_TOKEN = "day13-final-review-read-token"
RAW_SQL_MARKER = "day13-parser-secret-marker"


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
            version="datahub-mcp:day13-final-review-v1",
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


def _read_settings(monkeypatch: pytest.MonkeyPatch) -> ReadOnlyDataHubMcpSettings:
    monkeypatch.setenv("DATAHUB_GMS_URL", "https://day13-final-review.example")
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", READ_TOKEN)
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv("DATAHUB_MCP_ARGS", "mcp-server-datahub")
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")
    return read_only_settings_from_env()


def _request(snapshot: DataHubSnapshot) -> tuple[AgentGoal, AgentDataContext, AgentProposal]:
    context = build_agent_data_context_from_snapshot(snapshot)
    goal = build_agent_goal(GOAL_TEXT)
    proposal = GovernedAgent(_Planner()).propose(goal=goal, context=context)
    return goal, context, proposal


def _authority(
    monkeypatch: pytest.MonkeyPatch,
    snapshot: DataHubSnapshot,
    *,
    clock,
) -> DataHubAgentProposalAuthority:
    return DataHubAgentProposalAuthority(
        snapshot=snapshot,
        read_settings=_read_settings(monkeypatch),
        policy_engine=PolicyEngine(load_policy()),
        clock=clock,
        datahub_max_age_seconds=300,
    )


def _evaluate(
    authority: DataHubAgentProposalAuthority,
    *,
    goal: AgentGoal,
    context: AgentDataContext,
    proposal: AgentProposal,
):
    return authority.evaluate(
        proposal=proposal,
        goal=goal,
        planning_context=context,
        authorized_task_purpose=PURPOSE,
        subject_key=ColumnRef(dataset="patients", field_path="customer_id"),
    )


def test_authority_rechecks_freshness_after_artifact_construction(monkeypatch) -> None:
    snapshot = _snapshot()
    goal, context, proposal = _request(snapshot)
    samples = iter(
        (
            NOW + timedelta(seconds=299),
            NOW + timedelta(seconds=299, milliseconds=500),
            NOW + timedelta(seconds=301),
        )
    )
    authority = _authority(monkeypatch, snapshot, clock=lambda: next(samples))

    with pytest.raises(
        AgentProposalAuthorityError,
        match="AGENT_AUTHORITY_STALE_AT_ISSUE",
    ):
        _evaluate(authority, goal=goal, context=context, proposal=proposal)


def test_authority_rejects_clock_rollback_between_evaluations(monkeypatch) -> None:
    snapshot = _snapshot()
    goal, context, proposal = _request(snapshot)
    clock = _MutableClock(NOW + timedelta(seconds=100))
    authority = _authority(monkeypatch, snapshot, clock=clock)

    first = _evaluate(authority, goal=goal, context=context, proposal=proposal)
    assert first.security_authoritative is True

    clock.current = NOW + timedelta(seconds=50)
    with pytest.raises(
        AgentProposalAuthorityError,
        match="AGENT_AUTHORITY_TIME_ROLLBACK",
    ):
        _evaluate(authority, goal=goal, context=context, proposal=proposal)


def test_sql_parse_failure_crosses_only_sanitized_error_boundary(monkeypatch) -> None:
    snapshot = _snapshot()
    goal, context, proposal = _request(snapshot)
    malicious_sql = f"SELECT '{RAW_SQL_MARKER}' FROM ("
    provisional = proposal.model_copy(
        update={
            "sql": malicious_sql,
            "sql_sha256": hashlib.sha256(malicious_sql.encode("utf-8")).hexdigest(),
            "proposal_sha256": "0" * 64,
        }
    )
    malformed = AgentProposal.model_validate(
        provisional.model_copy(
            update={"proposal_sha256": compute_agent_proposal_sha256(provisional)}
        ).model_dump(mode="json")
    )
    authority = _authority(
        monkeypatch,
        snapshot,
        clock=_MutableClock(NOW + timedelta(seconds=1)),
    )

    try:
        _evaluate(authority, goal=goal, context=context, proposal=malformed)
    except AgentProposalAuthorityError as error:
        assert error.code == "AGENT_AUTHORITY_SQL_REPARSE_FAILED"
        assert error.__context__ is None
        assert error.__cause__ is None

        cursor = error.__traceback__
        while cursor is not None:
            if cursor.tb_frame.f_code.co_filename.endswith("proposal_authority.py"):
                for name, value in cursor.tb_frame.f_locals.items():
                    assert RAW_SQL_MARKER not in repr(value), (
                        f"authority traceback local {name!r} retained raw SQL"
                    )
                    assert not isinstance(
                        value,
                        (AgentProposal, AgentGoal, AgentDataContext),
                    ), f"authority traceback local {name!r} retained request artifact"
            cursor = cursor.tb_next
    else:
        raise AssertionError("malformed SQL was accepted")
