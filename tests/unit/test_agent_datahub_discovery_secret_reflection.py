from __future__ import annotations

import asyncio
import base64
from collections.abc import Callable

import pytest

from toxicjoin.agent import AgentDataHubDiscoveryError, DataHubAgentDiscoverer
from toxicjoin.context.datahub import DataHubAssetMap
from toxicjoin.integrations.datahub_authority import (
    ReadOnlyDataHubMcpSettings,
    read_only_settings_from_env,
)
from toxicjoin.integrations.datahub_mcp import McpToolDefinition

PATIENTS_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,patients,PROD)"
UPSTREAM_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,raw_patients,PROD)"
_READ_TOKEN = "agent-discovery-reflection-secret"
_ENDPOINT = "https://datahub-reflection.example"


def _configure(
    monkeypatch: pytest.MonkeyPatch,
    *,
    token: str = _READ_TOKEN,
    endpoint: str = _ENDPOINT,
    args: str = "mcp-server-datahub",
) -> ReadOnlyDataHubMcpSettings:
    monkeypatch.setenv("DATAHUB_GMS_URL", endpoint)
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", token)
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv("DATAHUB_MCP_ARGS", args)
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")
    return read_only_settings_from_env()


def _asset_map() -> DataHubAssetMap:
    return DataHubAssetMap(
        version="agent-secret-reflection-v1",
        datasets={"patients": PATIENTS_URN},
        flagship_dataset="patients",
        flagship_column=None,
    )


class ReflectingTransport:
    def __init__(
        self,
        settings: ReadOnlyDataHubMcpSettings,
        *,
        channel: str | None = None,
        reflected_value: str | None = None,
    ) -> None:
        self.settings = settings
        self.channel = channel
        self.reflected_value = reflected_value

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        return None

    async def list_tools(self) -> tuple[McpToolDefinition, ...]:
        return (
            McpToolDefinition(
                name="get_entities",
                input_schema={"properties": {"urns": {}}},
            ),
            McpToolDefinition(
                name="list_schema_fields",
                input_schema={
                    "properties": {
                        "urn": {},
                        "keywords": {},
                        "limit": {},
                        "offset": {},
                    }
                },
            ),
            McpToolDefinition(
                name="get_lineage",
                input_schema={
                    "properties": {
                        "urn": {},
                        "column": {},
                        "upstream": {},
                        "max_hops": {},
                        "max_results": {},
                        "offset": {},
                    }
                },
            ),
        )

    async def call_tool(self, name: str, arguments: dict):
        reflected = self.reflected_value
        if name == "get_entities":
            owner = "urn:li:corpuser:privacy-owner"
            domain = "urn:li:domain:privacy"
            if self.channel == "owner":
                owner = f"urn:li:corpuser:{reflected}"
            elif self.channel == "domain":
                domain = f"urn:li:domain:{reflected}"
            return [
                {
                    "urn": PATIENTS_URN,
                    "ownership": {"owner": owner},
                    "domains": {"domain": domain},
                }
            ]

        if name == "list_schema_fields":
            field_path = "customer_id"
            tags = ["toxicjoin:stable-pseudonym"]
            glossary_terms = ["CustomerIdentifier"]
            if self.channel == "field_path":
                field_path = f"field_{reflected}"
            elif self.channel == "tag":
                tags = [f"classification:{reflected}:marker"]
            elif self.channel == "glossary":
                glossary_terms = [f"term:{reflected}:marker"]
            return {
                "fields": [
                    {
                        "fieldPath": field_path,
                        "tags": tags,
                        "glossaryTerms": glossary_terms,
                    }
                ],
                "remainingCount": 0,
            }

        if name == "get_lineage":
            upstream_urn = UPSTREAM_URN
            upstream_field = "external_customer_id"
            if self.channel == "lineage_urn":
                upstream_urn = (
                    "urn:li:dataset:(urn:li:dataPlatform:duckdb,"
                    f"upstream-{reflected},PROD)"
                )
            elif self.channel == "lineage_field":
                upstream_field = f"upstream_{reflected}"
            return {
                "relationships": [
                    {
                        "entity": {"urn": upstream_urn},
                        "lineageColumns": [upstream_field],
                    }
                ]
            }

        raise AssertionError(f"unexpected tool call: {name}")


def _factory(
    *,
    channel: str | None,
    reflected_value: str | None,
) -> Callable[[ReadOnlyDataHubMcpSettings], ReflectingTransport]:
    def build(settings: ReadOnlyDataHubMcpSettings) -> ReflectingTransport:
        return ReflectingTransport(
            settings,
            channel=channel,
            reflected_value=reflected_value,
        )

    return build


def _discover(
    settings: ReadOnlyDataHubMcpSettings,
    *,
    channel: str | None = None,
    reflected_value: str | None = None,
):
    return asyncio.run(
        DataHubAgentDiscoverer(
            settings=settings,
            asset_map=_asset_map(),
            transport_factory=_factory(
                channel=channel,
                reflected_value=reflected_value,
            ),
        ).discover()
    )


@pytest.mark.parametrize(
    "channel",
    (
        "owner",
        "domain",
        "field_path",
        "tag",
        "glossary",
        "lineage_urn",
        "lineage_field",
    ),
)
def test_live_discovery_rejects_bearer_reflected_through_every_agent_metadata_channel(
    monkeypatch: pytest.MonkeyPatch,
    channel: str,
) -> None:
    settings = _configure(monkeypatch)

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        _discover(
            settings,
            channel=channel,
            reflected_value=_READ_TOKEN,
        )

    assert exc_info.value.code == "AGENT_DATAHUB_SECRET_REFLECTION"
    assert _READ_TOKEN not in str(exc_info.value)
    assert _ENDPOINT not in str(exc_info.value)


def test_live_discovery_rejects_endpoint_reflection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _configure(monkeypatch)

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        _discover(settings, channel="tag", reflected_value=_ENDPOINT)

    assert exc_info.value.code == "AGENT_DATAHUB_SECRET_REFLECTION"


def test_live_discovery_rejects_secret_bearing_launcher_argument_reflection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launcher_secret = "launcher-secret-value-42"
    settings = _configure(
        monkeypatch,
        args=f"mcp-server-datahub --api-key {launcher_secret}",
    )

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        _discover(settings, channel="tag", reflected_value=launcher_secret)

    assert exc_info.value.code == "AGENT_DATAHUB_SECRET_REFLECTION"


def test_live_discovery_rejects_proxy_credential_reflection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    proxy_password = "proxy-password-value-42"
    monkeypatch.setenv(
        "HTTPS_PROXY",
        f"https://proxy-user:{proxy_password}@proxy-reflection.example",
    )
    settings = _configure(monkeypatch)

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        _discover(settings, channel="tag", reflected_value=proxy_password)

    assert exc_info.value.code == "AGENT_DATAHUB_SECRET_REFLECTION"


def test_live_discovery_rejects_base64_bearer_reflection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _configure(monkeypatch)
    reflected = base64.b64encode(_READ_TOKEN.encode("utf-8")).decode("ascii")

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        _discover(settings, channel="tag", reflected_value=reflected)

    assert exc_info.value.code == "AGENT_DATAHUB_SECRET_REFLECTION"


def test_live_discovery_rejects_lowercase_full_percent_encoded_bearer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "reflection:/+%secret-42"
    settings = _configure(monkeypatch, token=token)
    reflected = "".join(f"%{byte:02x}" for byte in token.encode("utf-8"))

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        _discover(settings, channel="tag", reflected_value=reflected)

    assert exc_info.value.code == "AGENT_DATAHUB_SECRET_REFLECTION"


def test_live_discovery_rejects_zero_width_obfuscated_bearer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _configure(monkeypatch)
    reflected = "\u200b".join(_READ_TOKEN)

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        _discover(settings, channel="tag", reflected_value=reflected)

    assert exc_info.value.code == "AGENT_DATAHUB_SECRET_REFLECTION"


def test_live_discovery_rejects_endpoint_path_secret_reflection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path_secret = "endpoint-path-secret-42"
    endpoint = f"https://datahub-reflection.example/internal/{path_secret}"
    settings = _configure(monkeypatch, endpoint=endpoint)

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        _discover(settings, channel="tag", reflected_value=path_secret)

    assert exc_info.value.code == "AGENT_DATAHUB_SECRET_REFLECTION"


def test_live_discovery_rejects_standalone_launcher_env_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    launcher_secret = "launcher-env-secret-42"
    settings = _configure(
        monkeypatch,
        args=f"mcp-server-datahub --env DATAHUB_TOKEN {launcher_secret}",
    )

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        _discover(settings, channel="tag", reflected_value=launcher_secret)

    assert exc_info.value.code == "AGENT_DATAHUB_SECRET_REFLECTION"


def test_live_discovery_allows_nonsecret_metadata(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _configure(monkeypatch)
    context = _discover(settings)

    serialized = context.model_dump_json()
    assert context.security_authoritative is False
    assert context.datasets[0].owner == "urn:li:corpuser:privacy-owner"
    assert context.datasets[0].domain == "urn:li:domain:privacy"
    assert _READ_TOKEN not in serialized
    assert _ENDPOINT not in serialized
