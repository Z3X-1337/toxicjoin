from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from pydantic import SecretStr

from toxicjoin.integrations.datahub_mcp import (
    DataHubMcpError,
    DataHubMcpSettings,
    StdioDataHubMcpTransport,
)


class SlowSession:
    async def list_tools(self):
        await asyncio.sleep(0.05)
        return SimpleNamespace(tools=[])

    async def call_tool(self, name: str, *, arguments: dict):
        await asyncio.sleep(0.05)
        return SimpleNamespace(content=[], isError=False)


def _settings(*, timeout_seconds: float = 30.0) -> DataHubMcpSettings:
    return DataHubMcpSettings(
        gms_url="https://datahub.example.test",
        gms_token=SecretStr("DATAHUB_SECRET"),
        command="uvx",
        args=("mcp-server-datahub",),
        timeout_seconds=timeout_seconds,
    )


def test_child_environment_forwards_only_required_secrets(monkeypatch) -> None:
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("OPENAI_API_KEY", "SHOULD_NOT_LEAK")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "SHOULD_NOT_LEAK")
    monkeypatch.setenv("DATABASE_URL", "SHOULD_NOT_LEAK")

    environment = _settings().child_environment()

    assert environment["PATH"] == "/usr/bin"
    assert environment["DATAHUB_GMS_URL"] == "https://datahub.example.test"
    assert environment["DATAHUB_GMS_TOKEN"] == "DATAHUB_SECRET"
    assert environment["TOOLS_IS_MUTATION_ENABLED"] == "true"
    assert environment["DATAHUB_MCP_DOCUMENT_TOOLS_DISABLED"] == "false"
    assert "OPENAI_API_KEY" not in environment
    assert "AWS_SECRET_ACCESS_KEY" not in environment
    assert "DATABASE_URL" not in environment


def test_redacted_summary_excludes_url_and_token() -> None:
    settings = _settings()

    summary = settings.redacted_summary()
    rendered = repr(summary)

    assert summary["gms_scheme"] == "https"
    assert summary["token_present"] is True
    assert "datahub.example.test" not in rendered
    assert "DATAHUB_SECRET" not in rendered


def test_list_tools_timeout_fails_closed() -> None:
    transport = StdioDataHubMcpTransport(_settings(timeout_seconds=0.001))
    transport._session = SlowSession()

    with pytest.raises(DataHubMcpError, match="list_tools timed out"):
        asyncio.run(transport.list_tools())


def test_tool_call_timeout_fails_closed_without_arguments() -> None:
    transport = StdioDataHubMcpTransport(_settings(timeout_seconds=0.001))
    transport._session = SlowSession()

    with pytest.raises(DataHubMcpError, match="tool timed out: get_entities") as captured:
        asyncio.run(
            transport.call_tool(
                "get_entities",
                {"urns": ["urn:li:dataset:sensitive"]},
            )
        )

    assert "urn:li:dataset:sensitive" not in str(captured.value)
