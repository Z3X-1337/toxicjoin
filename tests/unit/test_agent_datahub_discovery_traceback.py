from __future__ import annotations

import asyncio
import traceback

import pytest
from pydantic import SecretStr

from toxicjoin.agent import AgentDataHubDiscoveryError, DataHubAgentDiscoverer
from toxicjoin.context.datahub import DataHubAssetMap
from toxicjoin.integrations.datahub_mcp import DataHubMcpSettings

PATIENTS_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,patients,PROD)"
_SECRET = "agent-discovery-secret-token"
_ENDPOINT = "https://datahub.example"


class LeakingTransport:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def list_tools(self):
        raise RuntimeError(f"transport leaked {_SECRET} {_ENDPOINT}")

    async def call_tool(self, name: str, arguments: dict):
        raise AssertionError("call_tool must not be reached after list_tools failure")


def test_discovery_suppresses_sensitive_exception_chain() -> None:
    settings = DataHubMcpSettings(
        gms_url=_ENDPOINT,
        gms_token=SecretStr(_SECRET),
        command="uvx",
        args=("mcp-server-datahub",),
        timeout_seconds=30,
        mutation_enabled=True,
    )
    asset_map = DataHubAssetMap(
        version="traceback-redaction-v1",
        datasets={"patients": PATIENTS_URN},
        flagship_dataset="patients",
        flagship_column="customer_id",
    )

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        asyncio.run(
            DataHubAgentDiscoverer(
                settings=settings,
                asset_map=asset_map,
                transport_factory=lambda _: LeakingTransport(),
            ).discover()
        )

    assert exc_info.value.code == "AGENT_DATAHUB_DISCOVERY_FAILED"
    rendered = "".join(
        traceback.format_exception(
            type(exc_info.value),
            exc_info.value,
            exc_info.value.__traceback__,
        )
    )
    assert _SECRET not in rendered
    assert _ENDPOINT not in rendered
    assert "transport leaked" not in rendered
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__suppress_context__ is True
