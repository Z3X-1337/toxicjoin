from __future__ import annotations

import asyncio

import pytest
from pydantic import SecretStr

import toxicjoin.agent.datahub_discovery as discovery_module
from toxicjoin.agent import DataHubAgentDiscoverer
from toxicjoin.context.datahub import DataHubAssetMap
from toxicjoin.integrations.datahub_authority import (
    ReadOnlyDataHubMcpSettings,
    read_only_settings_from_env,
)

PATIENTS_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,patients,PROD)"
_READ_TOKEN = "cancellation-traceback-secret-token"
_ENDPOINT = "https://cancellation-traceback.example"


class _CancellingTransport:
    def __init__(self, settings: ReadOnlyDataHubMcpSettings) -> None:
        self.settings = settings

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        return None


class _CancellingSnapshotLoader:
    def __init__(self, _client, _asset_map) -> None:
        pass

    async def load(self, *, require_mutations: bool):
        assert require_mutations is False
        raise asyncio.CancelledError()


def _settings(monkeypatch: pytest.MonkeyPatch) -> ReadOnlyDataHubMcpSettings:
    monkeypatch.setenv("DATAHUB_GMS_URL", _ENDPOINT)
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", _READ_TOKEN)
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv("DATAHUB_MCP_ARGS", "mcp-server-datahub")
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")
    return read_only_settings_from_env()


def _asset_map() -> DataHubAssetMap:
    return DataHubAssetMap(
        version="cancellation-traceback-v1",
        datasets={"patients": PATIENTS_URN},
        flagship_dataset="patients",
        flagship_column=None,
    )


def _assert_discovery_frames_are_credential_free(error: BaseException) -> None:
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
                assert not isinstance(value, _CancellingTransport), (
                    f"traceback local {name!r} retained credential-bearing transport"
                )
        cursor = cursor.tb_next
    assert observed_discovery_frame is True


def test_discovery_cancellation_preserves_cancelled_error_and_cleans_traceback_locals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        discovery_module,
        "DataHubSnapshotLoader",
        _CancellingSnapshotLoader,
    )

    try:
        asyncio.run(
            DataHubAgentDiscoverer(
                settings=_settings(monkeypatch),
                asset_map=_asset_map(),
                transport_factory=lambda settings: _CancellingTransport(settings),
            ).discover()
        )
    except asyncio.CancelledError as error:
        _assert_discovery_frames_are_credential_free(error)
    else:
        raise AssertionError("discovery cancellation was swallowed or converted")
