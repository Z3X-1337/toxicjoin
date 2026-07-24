from __future__ import annotations

import asyncio
from collections import deque
from pathlib import Path
from typing import Any, Self

import pytest

from toxicjoin.integrations.datahub_authority import (
    DataHubMcpRole,
    RoleBoundDataHubMcpClient,
    mutation_settings_from_env,
    read_only_settings_from_env,
)
from toxicjoin.integrations.datahub_mcp import (
    DataHubMcpContractError,
    DataHubMcpError,
    McpToolDefinition,
)


class FakeTransport:
    def __init__(
        self,
        *,
        tools: tuple[McpToolDefinition, ...],
        responses: dict[str, list[Any]] | None = None,
    ) -> None:
        self.tools = tools
        self.responses = {
            name: deque(items) for name, items in (responses or {}).items()
        }
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        return None

    async def list_tools(self) -> tuple[McpToolDefinition, ...]:
        return self.tools

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        self.calls.append((name, arguments))
        queue = self.responses.get(name)
        if not queue:
            raise AssertionError(f"no fake response configured for {name}")
        return queue.popleft()


def _read_tools(*, include_mutation: bool = False) -> tuple[McpToolDefinition, ...]:
    tools = [
        McpToolDefinition(
            name="get_entities",
            input_schema={"properties": {"urns": {"type": "array"}}},
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
                }
            },
        ),
        McpToolDefinition(
            name="grep_documents",
            input_schema={
                "properties": {
                    "urns": {},
                    "pattern": {},
                    "context_chars": {},
                    "max_matches_per_doc": {},
                    "start_offset": {},
                }
            },
        ),
    ]
    if include_mutation:
        tools.extend((_save_document_tool(), McpToolDefinition(name="add_tags", input_schema={})))
    return tuple(tools)


def _save_document_tool() -> McpToolDefinition:
    return McpToolDefinition(
        name="save_document",
        input_schema={
            "properties": {
                "title": {},
                "content": {},
                "document_type": {"enum": ["Decision", "Note"]},
                "related_assets": {},
                "external_url": {},
            }
        },
    )


def _configure_common_env(monkeypatch) -> None:
    monkeypatch.setenv("DATAHUB_GMS_URL", "https://datahub.example.test")
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv("DATAHUB_MCP_ARGS", "mcp-server-datahub")
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")


def test_read_and_write_roles_use_distinct_credentials_and_child_capabilities(monkeypatch) -> None:
    _configure_common_env(monkeypatch)
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", "READ_ONLY_TOKEN")
    monkeypatch.setenv("DATAHUB_GMS_WRITE_TOKEN", "WRITE_ONLY_TOKEN")
    monkeypatch.setenv("TOOLS_IS_MUTATION_ENABLED", "true")
    monkeypatch.setenv("SAVE_DOCUMENT_TOOL_ENABLED", "true")

    read_settings = read_only_settings_from_env()
    write_settings = mutation_settings_from_env()
    read_env = read_settings.child_environment()
    write_env = write_settings.child_environment()

    assert read_settings.mutation_enabled is False
    assert write_settings.mutation_enabled is True
    assert read_env["DATAHUB_GMS_TOKEN"] == "READ_ONLY_TOKEN"
    assert write_env["DATAHUB_GMS_TOKEN"] == "WRITE_ONLY_TOKEN"
    assert read_env["TOOLS_IS_MUTATION_ENABLED"] == "false"
    assert write_env["TOOLS_IS_MUTATION_ENABLED"] == "true"
    assert read_env["SAVE_DOCUMENT_TOOL_ENABLED"] == "false"
    assert write_env["SAVE_DOCUMENT_TOOL_ENABLED"] == "true"
    assert read_env["DATAHUB_MCP_DOCUMENT_TOOLS_DISABLED"] == "false"
    assert write_env["DATAHUB_MCP_DOCUMENT_TOOLS_DISABLED"] == "false"
    assert read_settings.redacted_summary()["role"] == "read_only"
    assert write_settings.redacted_summary()["role"] == "mutation"
    assert "WRITE_ONLY_TOKEN" not in repr(read_settings.redacted_summary())
    assert "READ_ONLY_TOKEN" not in repr(write_settings.redacted_summary())


def test_each_role_requires_its_own_token(monkeypatch) -> None:
    _configure_common_env(monkeypatch)
    monkeypatch.delenv("DATAHUB_GMS_READ_TOKEN", raising=False)
    monkeypatch.delenv("DATAHUB_GMS_WRITE_TOKEN", raising=False)
    monkeypatch.setenv("DATAHUB_GMS_TOKEN", "LEGACY_AMBIGUOUS_TOKEN")

    with pytest.raises(DataHubMcpError, match="DATAHUB_GMS_READ_TOKEN"):
        read_only_settings_from_env()
    with pytest.raises(DataHubMcpError, match="DATAHUB_GMS_WRITE_TOKEN"):
        mutation_settings_from_env()


def test_read_only_client_rejects_mutation_contract_exposure() -> None:
    client = RoleBoundDataHubMcpClient(
        FakeTransport(tools=_read_tools(include_mutation=True)),
        role=DataHubMcpRole.READ_ONLY,
    )

    with pytest.raises(DataHubMcpContractError, match="exposed mutation tools"):
        asyncio.run(client.discover_and_validate(require_mutations=False))


def test_read_only_client_cannot_request_or_call_mutation_authority() -> None:
    transport = FakeTransport(tools=_read_tools())
    client = RoleBoundDataHubMcpClient(transport, role=DataHubMcpRole.READ_ONLY)

    with pytest.raises(DataHubMcpContractError, match="cannot validate"):
        asyncio.run(client.discover_and_validate(require_mutations=True))
    with pytest.raises(DataHubMcpContractError, match="cannot perform mutations"):
        asyncio.run(
            client.save_decision(
                title="blocked",
                content="blocked",
                related_assets=("urn:li:dataset:test",),
            )
        )
    assert transport.calls == []


def test_mutation_client_validates_only_write_contract_and_cannot_acquire_context() -> None:
    transport = FakeTransport(
        tools=(_save_document_tool(),),
        responses={
            "save_document": [
                {"document": {"urn": "urn:li:document:isolated-writer"}}
            ]
        },
    )
    client = RoleBoundDataHubMcpClient(transport, role=DataHubMcpRole.MUTATION)

    definitions = asyncio.run(client.discover_and_validate(require_mutations=True))
    urn = asyncio.run(
        client.save_decision(
            title="decision",
            content="sanitized",
            related_assets=("urn:li:dataset:test",),
        )
    )

    assert [definition.name for definition in definitions] == ["save_document"]
    assert urn == "urn:li:document:isolated-writer"
    with pytest.raises(DataHubMcpContractError, match="cannot acquire governed read context"):
        asyncio.run(client.get_entities(("urn:li:dataset:test",)))
    assert [name for name, _ in transport.calls] == ["save_document"]


def test_production_source_does_not_use_ambiguous_mcp_settings_factory() -> None:
    ambiguous = "DataHubMcpSettings.from_env("
    violations: list[str] = []
    for path in Path("src/toxicjoin").rglob("*.py"):
        if path.name == "datahub_mcp.py":
            continue
        if ambiguous in path.read_text(encoding="utf-8"):
            violations.append(path.as_posix())

    assert violations == []
