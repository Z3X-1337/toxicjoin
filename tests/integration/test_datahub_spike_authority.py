from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Self

from pydantic import SecretStr

from toxicjoin.context.datahub import DataHubAssetMap
from toxicjoin.integrations.datahub_mcp import DataHubMcpSettings, McpToolDefinition
from toxicjoin.integrations.datahub_spike import run_datahub_spike


_DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.customers,PROD)"


class FakeRoleTransport:
    def __init__(self, *, mutation_enabled: bool, phase: int) -> None:
        self.mutation_enabled = mutation_enabled
        self.phase = phase
        self.calls: list[str] = []

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        return None

    async def list_tools(self) -> tuple[McpToolDefinition, ...]:
        if self.mutation_enabled:
            return (
                McpToolDefinition(
                    name="save_document",
                    input_schema={
                        "properties": {
                            "title": {},
                            "content": {},
                            "document_type": {"enum": ["Decision"]},
                            "related_assets": {},
                            "external_url": {},
                        }
                    },
                ),
            )
        tools = [
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
                    }
                },
            ),
        ]
        if self.phase == 3:
            tools.append(
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
                )
            )
        return tuple(tools)

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        self.calls.append(name)
        if name == "get_entities":
            return [{"urn": _DATASET_URN}]
        if name == "list_schema_fields":
            return {
                "fields": [
                    {
                        "fieldPath": "customer_id",
                        "tags": {"tags": [{"tag": "urn:li:tag:ToxicJoinDirectIdentifier"}]},
                    }
                ],
                "remainingCount": 0,
            }
        if name == "get_lineage":
            return {
                "relationships": [
                    {"source": "upstream", "target": _DATASET_URN, "degree": 1}
                ]
            }
        if name == "save_document":
            return {"document": {"urn": "urn:li:document:isolated-write"}}
        if name == "grep_documents":
            marker = str(arguments["pattern"])
            return {
                "results": [
                    {
                        "urn": "urn:li:document:isolated-write",
                        "matches": [{"excerpt": f"marker: {marker}"}],
                    }
                ],
                "total_matches": 1,
            }
        raise AssertionError(name)


class RecordingFactory:
    def __init__(self) -> None:
        self.transports: list[FakeRoleTransport] = []

    def __call__(self, settings: DataHubMcpSettings) -> FakeRoleTransport:
        phase = len(self.transports) + 1
        transport = FakeRoleTransport(
            mutation_enabled=settings.mutation_enabled,
            phase=phase,
        )
        self.transports.append(transport)
        return transport


def _settings(*, mutation_enabled: bool, token: str) -> DataHubMcpSettings:
    return DataHubMcpSettings(
        gms_url="https://datahub.example.test",
        gms_token=SecretStr(token),
        mutation_enabled=mutation_enabled,
    )


def test_spike_uses_read_then_write_then_fresh_readback_processes(tmp_path: Path) -> None:
    factory = RecordingFactory()
    report = asyncio.run(
        run_datahub_spike(
            read_settings=_settings(mutation_enabled=False, token="READ_TOKEN"),
            write_settings=_settings(mutation_enabled=True, token="WRITE_TOKEN"),
            asset_map=DataHubAssetMap(
                version="test",
                datasets={"customers": _DATASET_URN},
                flagship_dataset="customers",
                flagship_column="customer_id",
            ),
            output=tmp_path / "spike.json",
            transport_factory=factory,
        )
    )

    assert [transport.mutation_enabled for transport in factory.transports] == [
        False,
        True,
        False,
    ]
    assert factory.transports[0].calls == [
        "get_entities",
        "list_schema_fields",
        "get_lineage",
    ]
    assert factory.transports[1].calls == ["save_document"]
    assert factory.transports[2].calls == ["grep_documents"]
    assert report.schema_version == "1.1"
    assert report.read_settings["mutation_enabled"] is False
    assert report.write_settings["mutation_enabled"] is True
    assert "save_document" not in report.read_discovered_tools
    assert "save_document" in report.write_discovered_tools
    assert "save_document" not in report.readback_discovered_tools
    assert report.independent_readback_verified is True
