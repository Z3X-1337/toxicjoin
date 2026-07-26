from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from toxicjoin.agent import (
    DataHubAgentProposalAuthority,
    GovernedAgent,
    build_agent_data_context_from_snapshot,
    build_agent_goal,
)
from toxicjoin.agent.governance_trust import DataHubGovernanceTrustAuthority
from toxicjoin.context.datahub import DataHubSnapshot
from toxicjoin.context.fixture import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.integrations.datahub_authority import read_only_settings_from_env
from toxicjoin.models import ColumnRef, Decision, SensitivityCategory
from toxicjoin.policy import PolicyEngine, load_policy


NOW = datetime(2026, 7, 27, 2, 30, tzinfo=timezone.utc)
PATIENTS_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.day13_trust_dataset,PROD)"
PURPOSE = "Count rows without releasing individual records"
SQL = "SELECT COUNT(*) AS row_count FROM patients"


class _Planner:
    def propose(self, *, goal, context):
        return {"task_purpose": PURPOSE, "sql": SQL}

    def adapt(self, *, goal, context, previous, feedback):
        return self.propose(goal=goal, context=context)


def _snapshot() -> DataHubSnapshot:
    return DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:day13-governance-trust-dataset-v1",
            datasets={
                "patients": FixtureDataset(
                    urn=PATIENTS_URN,
                    fields={
                        "customer_id": FixtureField(
                            category=SensitivityCategory.STABLE_PSEUDONYM,
                            tags=("stable-customer-identifier",),
                        )
                    },
                )
            },
        ),
        verified_entities=(PATIENTS_URN,),
        field_counts={"patients": 1},
        lineage_sample={"relationships": []},
        discovered_tools=("get_entities", "get_lineage", "list_schema_fields"),
        observed_at=NOW,
    )


def test_source_dataset_mapping_is_trusted_even_without_column_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATAHUB_GMS_URL", "https://day13-trust-dataset.example")
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", "day13-trust-dataset-read-token")
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv("DATAHUB_MCP_ARGS", "mcp-server-datahub")
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")

    snapshot = _snapshot()
    planning_context = build_agent_data_context_from_snapshot(snapshot)
    goal = build_agent_goal("Count rows in the governed dataset")
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
        subject_key=ColumnRef(dataset="patients", field_path="customer_id"),
    )

    assert evaluation.policy_decision.decision == Decision.ALLOW
    assert evaluation.query_plan.source_datasets == ("patients",)
    assert evaluation.resolution.projected_context == ()
    assert evaluation.resolution.all_referenced_context == ()

    binding = DataHubGovernanceTrustAuthority(
        clock=lambda: NOW + timedelta(seconds=2)
    ).bind(evaluation)
    requirements = {
        (requirement.subject, requirement.predicate): requirement.expected_value
        for requirement in binding.requirements
    }

    assert requirements[(PATIENTS_URN, "datahub.logical_name")] == "patients"
