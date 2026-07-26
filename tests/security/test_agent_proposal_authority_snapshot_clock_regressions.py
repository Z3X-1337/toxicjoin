from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from toxicjoin.agent import AgentProposalAuthorityError, DataHubAgentProposalAuthority
from toxicjoin.context.datahub import DataHubSnapshot
from toxicjoin.context.fixture import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.integrations.datahub_authority import (
    ReadOnlyDataHubMcpSettings,
    read_only_settings_from_env,
)
from toxicjoin.models import SensitivityCategory
from toxicjoin.policy import PolicyEngine, load_policy


NOW = datetime(2026, 7, 26, 14, 15, tzinfo=timezone.utc)
DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.day13_snapshot_clock,PROD)"
READ_TOKEN = "day13-snapshot-clock-read-token"


def _snapshot() -> DataHubSnapshot:
    return DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:day13-snapshot-clock-v1",
            datasets={
                "patients": FixtureDataset(
                    urn=DATASET_URN,
                    fields={
                        "customer_id": FixtureField(
                            category=SensitivityCategory.STABLE_PSEUDONYM,
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


def _read_settings(monkeypatch: pytest.MonkeyPatch) -> ReadOnlyDataHubMcpSettings:
    monkeypatch.setenv("DATAHUB_GMS_URL", "https://day13-snapshot-clock.example")
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", READ_TOKEN)
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv("DATAHUB_MCP_ARGS", "mcp-server-datahub")
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")
    return read_only_settings_from_env()


def test_constructor_rejects_snapshot_subclass_before_virtual_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    class _MaliciousSnapshot(DataHubSnapshot):
        def model_dump(self, *args, **kwargs):
            calls.append("model_dump")
            return super().model_dump(*args, **kwargs)

    base = _snapshot()
    attacker_snapshot = _MaliciousSnapshot.model_validate(base.model_dump(mode="json"))

    with pytest.raises(
        AgentProposalAuthorityError,
        match="AGENT_AUTHORITY_SOURCE_INVALID",
    ) as exc:
        DataHubAgentProposalAuthority(
            snapshot=attacker_snapshot,
            read_settings=_read_settings(monkeypatch),
            policy_engine=PolicyEngine(load_policy()),
            clock=lambda: NOW + timedelta(seconds=1),
            datahub_max_age_seconds=300,
        )

    assert calls == []
    assert exc.value.__context__ is None
    assert exc.value.__cause__ is None


class _FalseyClock:
    def __init__(self, current: datetime) -> None:
        self.current = current

    def __bool__(self) -> bool:
        return False

    def __call__(self) -> datetime:
        return self.current


def test_constructor_preserves_falsey_explicit_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    clock = _FalseyClock(NOW + timedelta(seconds=1))
    authority = DataHubAgentProposalAuthority(
        snapshot=_snapshot(),
        read_settings=_read_settings(monkeypatch),
        policy_engine=PolicyEngine(load_policy()),
        clock=clock,
        datahub_max_age_seconds=300,
    )

    assert authority._clock is clock
    assert authority._sample_clock() == NOW + timedelta(seconds=1)
