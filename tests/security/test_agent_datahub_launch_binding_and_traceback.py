from __future__ import annotations

import asyncio
import os
from urllib.parse import urlsplit

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
_READ_TOKEN = "traceback-reflection-secret-token"
_ENDPOINT = "https://datahub-reflection.example"
_OLD_PROXY_PASSWORD = "old-proxy-secret-42"
_NEW_PROXY_PASSWORD = "new-proxy-secret-42"


def _configure(
    monkeypatch: pytest.MonkeyPatch,
    *,
    token: str = _READ_TOKEN,
    endpoint: str = _ENDPOINT,
) -> ReadOnlyDataHubMcpSettings:
    monkeypatch.setenv("DATAHUB_GMS_URL", endpoint)
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", token)
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv("DATAHUB_MCP_ARGS", "mcp-server-datahub")
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")
    return read_only_settings_from_env()


def _asset_map() -> DataHubAssetMap:
    return DataHubAssetMap(
        version="agent-launch-binding-v1",
        datasets={"patients": PATIENTS_URN},
        flagship_dataset="patients",
        flagship_column=None,
    )


class ReflectionTransport:
    def __init__(
        self,
        settings: ReadOnlyDataHubMcpSettings,
        *,
        reflected_value: str,
    ) -> None:
        self.settings = settings
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
        if name == "get_entities":
            return [{"urn": PATIENTS_URN}]
        if name == "list_schema_fields":
            return {
                "fields": [
                    {
                        "fieldPath": "customer_id",
                        "tags": [f"classification:{self.reflected_value}:marker"],
                    }
                ],
                "remainingCount": 0,
            }
        if name == "get_lineage":
            return {
                "relationships": [
                    {
                        "entity": {"urn": UPSTREAM_URN},
                        "lineageColumns": ["external_customer_id"],
                    }
                ]
            }
        raise AssertionError(f"unexpected tool call: {name}")


class RotatingProxyTransport(ReflectionTransport):
    def __init__(
        self,
        settings: ReadOnlyDataHubMcpSettings,
        *,
        replacement_proxy: str,
    ) -> None:
        super().__init__(settings, reflected_value="not-yet-launched")
        self.replacement_proxy = replacement_proxy
        self.launched_proxy: str | None = None
        self.launched_proxy_password: str | None = None

    async def __aenter__(self):
        os.environ["HTTPS_PROXY"] = self.replacement_proxy
        launched_environment = self.settings.child_environment()
        self.launched_proxy = launched_environment.get("HTTPS_PROXY")
        if self.launched_proxy is None:
            raise AssertionError("HTTPS_PROXY was not forwarded to the simulated child")
        self.launched_proxy_password = urlsplit(self.launched_proxy).password
        if self.launched_proxy_password is None:
            raise AssertionError("simulated child proxy had no password")
        self.reflected_value = self.launched_proxy_password
        return self


def _discover_reflection(
    settings: ReadOnlyDataHubMcpSettings,
    reflected_value: str,
) -> None:
    def factory(runtime_settings: ReadOnlyDataHubMcpSettings) -> ReflectionTransport:
        return ReflectionTransport(runtime_settings, reflected_value=reflected_value)

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        asyncio.run(
            DataHubAgentDiscoverer(
                settings=settings,
                asset_map=_asset_map(),
                transport_factory=factory,
            ).discover()
        )
    assert exc_info.value.code == "AGENT_DATAHUB_SECRET_REFLECTION"


def test_role_bound_child_environment_is_frozen_after_first_materialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_proxy = f"https://proxy-user:{_OLD_PROXY_PASSWORD}@proxy-old.example"
    new_proxy = f"https://proxy-user:{_NEW_PROXY_PASSWORD}@proxy-new.example"
    monkeypatch.setenv("HTTPS_PROXY", old_proxy)
    settings = _configure(monkeypatch)

    first = settings.child_environment()
    monkeypatch.setenv("HTTPS_PROXY", new_proxy)
    second = settings.child_environment()

    assert first == second
    assert first["HTTPS_PROXY"] == old_proxy
    assert _NEW_PROXY_PASSWORD not in repr(second)


def test_guard_and_transport_use_same_proxy_environment_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old_proxy = f"https://proxy-user:{_OLD_PROXY_PASSWORD}@proxy-old.example"
    new_proxy = f"https://proxy-user:{_NEW_PROXY_PASSWORD}@proxy-new.example"
    monkeypatch.setenv("HTTPS_PROXY", old_proxy)
    settings = _configure(monkeypatch)
    captured: list[RotatingProxyTransport] = []

    def factory(runtime_settings: ReadOnlyDataHubMcpSettings) -> RotatingProxyTransport:
        transport = RotatingProxyTransport(
            runtime_settings,
            replacement_proxy=new_proxy,
        )
        captured.append(transport)
        return transport

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        asyncio.run(
            DataHubAgentDiscoverer(
                settings=settings,
                asset_map=_asset_map(),
                transport_factory=factory,
            ).discover()
        )

    assert exc_info.value.code == "AGENT_DATAHUB_SECRET_REFLECTION"
    assert len(captured) == 1
    assert captured[0].launched_proxy == old_proxy
    assert captured[0].launched_proxy_password == _OLD_PROXY_PASSWORD
    assert _NEW_PROXY_PASSWORD not in str(exc_info.value)


def test_secret_reflection_error_clears_sensitive_discovery_traceback_locals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _configure(monkeypatch)

    def factory(runtime_settings: ReadOnlyDataHubMcpSettings) -> ReflectionTransport:
        return ReflectionTransport(runtime_settings, reflected_value=_READ_TOKEN)

    try:
        asyncio.run(
            DataHubAgentDiscoverer(
                settings=settings,
                asset_map=_asset_map(),
                transport_factory=factory,
            ).discover()
        )
    except AgentDataHubDiscoveryError as error:
        assert error.code == "AGENT_DATAHUB_SECRET_REFLECTION"
        traceback_cursor = error.__traceback__
        toxicjoin_locals: list[str] = []
        while traceback_cursor is not None:
            frame = traceback_cursor.tb_frame
            if frame.f_globals.get("__name__") == "toxicjoin.agent.datahub_discovery":
                toxicjoin_locals.append(repr(frame.f_locals))
            traceback_cursor = traceback_cursor.tb_next
    else:
        raise AssertionError("secret reflection unexpectedly reached the Agent context")

    rendered_locals = "\n".join(toxicjoin_locals)
    assert _READ_TOKEN not in rendered_locals
    assert _ENDPOINT not in rendered_locals
    assert "classification:traceback-reflection-secret-token:marker" not in rendered_locals


def test_unicode_control_removal_is_renormalized_before_matching(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "é7"
    settings = _configure(monkeypatch, token=token)
    reflected = "prefix-e\u200b\u03017-suffix"

    _discover_reflection(settings, reflected)


def test_partial_percent_encoding_is_decoded_before_matching(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "q7"
    settings = _configure(monkeypatch, token=token)

    _discover_reflection(settings, "prefix-%717-suffix")


def test_mixed_case_hex_reflection_is_matched_case_insensitively(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "z?"
    settings = _configure(monkeypatch, token=token)

    _discover_reflection(settings, "prefix-7A3f-suffix")


def test_secret_shaped_fragment_value_is_treated_as_strong(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fragment_secret = "q7"
    endpoint = f"https://datahub-reflection.example/#access_token={fragment_secret}"
    settings = _configure(monkeypatch, endpoint=endpoint)

    _discover_reflection(settings, f"prefix-{fragment_secret}-suffix")
