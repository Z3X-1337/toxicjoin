from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest
from pydantic import SecretStr

import toxicjoin.agent.datahub_discovery as discovery_module
from toxicjoin.agent import AgentDataHubDiscoveryError, DataHubAgentDiscoverer
from toxicjoin.context.datahub import DataHubAssetMap, DataHubSnapshot
from toxicjoin.context.fixture import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.integrations.datahub_authority import (
    ReadOnlyDataHubMcpSettings,
    read_only_settings_from_env,
)
from toxicjoin.models import SensitivityCategory

PATIENTS_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,patients,PROD)"
_READ_TOKEN = "traceback-object-secret-token"
_ENDPOINT = "https://traceback-object-isolation.example"


class _NoopTransport:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        return None


class _StaticSnapshotLoader:
    def __init__(self, _client, _asset_map) -> None:
        pass

    async def load(self, *, require_mutations: bool) -> DataHubSnapshot:
        assert require_mutations is False
        return DataHubSnapshot(
            catalog=FixtureCatalog(
                version="datahub-mcp:traceback-object-isolation-v1",
                datasets={
                    "patients": FixtureDataset(
                        urn=PATIENTS_URN,
                        fields={
                            "customer_id": FixtureField(
                                category=SensitivityCategory.STABLE_PSEUDONYM,
                            )
                        },
                    )
                },
            ),
            verified_entities=(PATIENTS_URN,),
            field_counts={"patients": 1},
            lineage_sample={"relationships": []},
            discovered_tools=("get_entities", "get_lineage", "list_schema_fields"),
            observed_at=datetime(2026, 7, 26, 4, 5, tzinfo=timezone.utc),
        )


def _settings(monkeypatch: pytest.MonkeyPatch) -> ReadOnlyDataHubMcpSettings:
    monkeypatch.setenv("DATAHUB_GMS_URL", _ENDPOINT)
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", _READ_TOKEN)
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv("DATAHUB_MCP_ARGS", "mcp-server-datahub")
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")
    return read_only_settings_from_env()


def _asset_map() -> DataHubAssetMap:
    return DataHubAssetMap(
        version="traceback-object-isolation-v1",
        datasets={"patients": PATIENTS_URN},
        flagship_dataset="patients",
        flagship_column=None,
    )


def _assert_no_credential_bearing_objects_in_discovery_frames(
    error: BaseException,
) -> None:
    cursor = error.__traceback__
    observed_discovery_frame = False
    while cursor is not None:
        frame = cursor.tb_frame
        if frame.f_globals.get("__name__") == "toxicjoin.agent.datahub_discovery":
            observed_discovery_frame = True
            for name, value in frame.f_locals.items():
                assert not isinstance(value, DataHubAgentDiscoverer), (
                    f"traceback local {name!r} retained credential-bearing discoverer"
                )
                assert not isinstance(value, ReadOnlyDataHubMcpSettings), (
                    f"traceback local {name!r} retained runtime DataHub settings"
                )
                assert not isinstance(value, SecretStr), (
                    f"traceback local {name!r} retained bearer wrapper"
                )
        cursor = cursor.tb_next
    assert observed_discovery_frame is True


def test_secret_reflection_error_drops_credential_bearing_objects_from_traceback_locals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(discovery_module, "DataHubSnapshotLoader", _StaticSnapshotLoader)
    monkeypatch.setattr(
        discovery_module._AgentMetadataSecretGuard,
        "context_is_safe",
        lambda _guard, _context: False,
    )

    try:
        asyncio.run(
            DataHubAgentDiscoverer(
                settings=_settings(monkeypatch),
                asset_map=_asset_map(),
                transport_factory=lambda _settings: _NoopTransport(),
            ).discover()
        )
    except AgentDataHubDiscoveryError as error:
        assert error.code == "AGENT_DATAHUB_SECRET_REFLECTION"
        assert error.__cause__ is None
        assert error.__context__ is None
        _assert_no_credential_bearing_objects_in_discovery_frames(error)
    else:
        raise AssertionError("forced secret-reflection rejection did not fail closed")
