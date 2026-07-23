from __future__ import annotations

import asyncio
from collections import deque
from typing import Any, Self

import pytest

from toxicjoin.integrations.datahub_mcp import (
    DataHubMcpClient,
    DataHubMcpContractError,
    DataHubMcpError,
    McpToolDefinition,
)


class FakeTransport:
    def __init__(
        self,
        *,
        tools: tuple[McpToolDefinition, ...] | None = None,
        responses: dict[str, list[Any]] | None = None,
    ) -> None:
        self.tools = tools or _official_contracts()
        self.responses = {
            name: deque(items)
            for name, items in (responses or {}).items()
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
        if queue is None or not queue:
            raise AssertionError(f"no fake response configured for {name}")
        return queue.popleft()


def _official_contracts() -> tuple[McpToolDefinition, ...]:
    return (
        McpToolDefinition(
            name="get_entities",
            input_schema={"type": "object", "properties": {"urns": {"type": "array"}}},
        ),
        McpToolDefinition(
            name="list_schema_fields",
            input_schema={
                "type": "object",
                "properties": {
                    "urn": {"type": "string"},
                    "keywords": {"type": "array"},
                    "limit": {"type": "integer"},
                    "offset": {"type": "integer"},
                },
            },
        ),
        McpToolDefinition(
            name="get_lineage",
            input_schema={
                "type": "object",
                "properties": {
                    "urn": {"type": "string"},
                    "column": {"type": ["string", "null"]},
                    "upstream": {"type": "boolean"},
                    "max_hops": {"type": "integer"},
                    "max_results": {"type": "integer"},
                    "offset": {"type": "integer"},
                },
            },
        ),
        McpToolDefinition(
            name="save_document",
            input_schema={
                "type": "object",
                "properties": {
                    "title": {"type": "string"},
                    "content": {"type": "string"},
                    "document_type": {
                        "type": "string",
                        "enum": [
                            "Insight",
                            "Decision",
                            "FAQ",
                            "Analysis",
                            "Summary",
                            "Recommendation",
                            "Note",
                            "Context",
                        ],
                    },
                    "related_assets": {"type": "array"},
                    "external_url": {"type": ["string", "null"]},
                },
            },
        ),
    )


def test_validates_official_read_and_write_contracts() -> None:
    client = DataHubMcpClient(FakeTransport())

    definitions = asyncio.run(
        client.discover_and_validate(require_mutations=True)
    )

    assert {definition.name for definition in definitions} == {
        "get_entities",
        "list_schema_fields",
        "get_lineage",
        "save_document",
    }


def test_missing_mutation_tool_fails_closed() -> None:
    tools = tuple(
        tool for tool in _official_contracts() if tool.name != "save_document"
    )
    client = DataHubMcpClient(FakeTransport(tools=tools))

    with pytest.raises(DataHubMcpContractError, match="missing tool save_document"):
        asyncio.run(client.discover_and_validate(require_mutations=True))


def test_missing_required_input_property_fails_closed() -> None:
    tools = list(_official_contracts())
    tools[1] = McpToolDefinition(
        name="list_schema_fields",
        input_schema={
            "type": "object",
            "properties": {"urn": {"type": "string"}},
        },
    )
    client = DataHubMcpClient(FakeTransport(tools=tuple(tools)))

    with pytest.raises(DataHubMcpContractError, match="keywords, limit, offset"):
        asyncio.run(client.discover_and_validate(require_mutations=False))


def test_save_document_requires_decision_enum_when_enum_is_declared() -> None:
    tools = list(_official_contracts())
    save = tools[-1]
    schema = dict(save.input_schema)
    properties = dict(save.properties)
    properties["document_type"] = {"type": "string", "enum": ["Note"]}
    schema["properties"] = properties
    tools[-1] = McpToolDefinition(name="save_document", input_schema=schema)

    with pytest.raises(DataHubMcpContractError, match="document_type=Decision"):
        asyncio.run(
            DataHubMcpClient(FakeTransport(tools=tuple(tools))).discover_and_validate(
                require_mutations=True
            )
        )


def test_schema_fields_pagination_makes_progress() -> None:
    transport = FakeTransport(
        responses={
            "list_schema_fields": [
                {
                    "urn": "urn:li:dataset:test",
                    "fields": [{"fieldPath": "customer_id"}],
                    "total": 2,
                    "returned": 1,
                    "remainingCount": 1,
                },
                {
                    "urn": "urn:li:dataset:test",
                    "fields": [{"fieldPath": "coarse_region"}],
                    "total": 2,
                    "returned": 1,
                    "remainingCount": 0,
                },
            ]
        }
    )
    client = DataHubMcpClient(transport)

    fields = asyncio.run(
        client.list_schema_fields("urn:li:dataset:test", page_size=1)
    )

    assert [field["fieldPath"] for field in fields] == [
        "customer_id",
        "coarse_region",
    ]
    assert [call[1]["offset"] for call in transport.calls] == [0, 1]


def test_schema_pagination_rejects_remaining_without_progress() -> None:
    transport = FakeTransport(
        responses={
            "list_schema_fields": [
                {
                    "urn": "urn:li:dataset:test",
                    "fields": [],
                    "remainingCount": 1,
                }
            ]
        }
    )

    with pytest.raises(DataHubMcpError, match="without progress"):
        asyncio.run(
            DataHubMcpClient(transport).list_schema_fields(
                "urn:li:dataset:test"
            )
        )


def test_save_decision_extracts_nested_document_urn() -> None:
    transport = FakeTransport(
        responses={
            "save_document": [
                {
                    "status": "ok",
                    "document": {
                        "urn": "urn:li:document:toxicjoin-decision-123"
                    },
                }
            ]
        }
    )
    client = DataHubMcpClient(transport)

    urn = asyncio.run(
        client.save_decision(
            title="ToxicJoin decision",
            content="verified marker",
            related_assets=("urn:li:dataset:test",),
        )
    )

    assert urn == "urn:li:document:toxicjoin-decision-123"
    name, arguments = transport.calls[0]
    assert name == "save_document"
    assert arguments["document_type"] == "Decision"
    assert arguments["related_assets"] == ["urn:li:dataset:test"]


def test_independent_marker_readback_rejects_missing_marker() -> None:
    urn = "urn:li:document:toxicjoin-decision-123"
    transport = FakeTransport(
        responses={"get_entities": [[{"urn": urn, "content": "other"}]]}
    )

    with pytest.raises(DataHubMcpError, match="verification marker"):
        asyncio.run(
            DataHubMcpClient(transport).verify_document_marker(
                urn,
                "TOXICJOIN_MARKER_ABC",
            )
        )


def test_independent_marker_readback_accepts_nested_content() -> None:
    urn = "urn:li:document:toxicjoin-decision-123"
    marker = "TOXICJOIN_MARKER_ABC"
    transport = FakeTransport(
        responses={
            "get_entities": [
                [
                    {
                        "urn": urn,
                        "document": {"properties": {"contents": marker}},
                    }
                ]
            ]
        }
    )

    entity = asyncio.run(
        DataHubMcpClient(transport).verify_document_marker(urn, marker)
    )

    assert entity["urn"] == urn

def test_get_entities_accepts_fastmcp_collection_result_envelope() -> None:
    urn = "urn:li:dataset:test"
    transport = FakeTransport(
        responses={"get_entities": [{"result": [{"urn": urn}]}]}
    )

    entities = asyncio.run(DataHubMcpClient(transport).get_entities((urn,)))

    assert entities == ({"urn": urn},)


def test_get_entities_still_accepts_bare_list() -> None:
    urn = "urn:li:dataset:test"
    transport = FakeTransport(responses={"get_entities": [[{"urn": urn}]]})

    entities = asyncio.run(DataHubMcpClient(transport).get_entities((urn,)))

    assert entities == ({"urn": urn},)


def test_get_entities_rejects_nonstandard_result_envelope() -> None:
    urn = "urn:li:dataset:test"
    transport = FakeTransport(
        responses={
            "get_entities": [
                {"result": [{"urn": urn}], "metadata": {"unsafe": True}}
            ]
        }
    )

    with pytest.raises(DataHubMcpError, match="unexpected payload"):
        asyncio.run(DataHubMcpClient(transport).get_entities((urn,)))

