from __future__ import annotations

import asyncio
import json
from typing import Any, Self

import pytest
from pydantic import SecretStr

from toxicjoin.context import DataHubAssetMap
from toxicjoin.integrations.datahub_mcp import (
    DataHubMcpError,
    DataHubMcpSettings,
    McpToolDefinition,
)
from toxicjoin.integrations.datahub_spike import (
    DataHubSpikeReport,
    run_datahub_spike,
)


CUSTOMERS_URN = (
    "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.customers,PROD)"
)
SCORES_URN = (
    "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.retention_scores,PROD)"
)
DOCUMENT_URN = "urn:li:document:toxicjoin-mcp-verification"


class SessionFactory:
    def __init__(self, *, preserve_marker: bool = True) -> None:
        self.preserve_marker = preserve_marker
        self.created = 0
        self.saved_arguments: dict[str, Any] | None = None

    def __call__(self, settings: DataHubMcpSettings) -> "FakeTransport":
        self.created += 1
        role = "write" if self.created == 1 else "read"
        return FakeTransport(self, role=role)


class FakeTransport:
    def __init__(self, factory: SessionFactory, *, role: str) -> None:
        self.factory = factory
        self.role = role

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        return None

    async def list_tools(self) -> tuple[McpToolDefinition, ...]:
        contracts = _contracts()
        if self.role == "read":
            return contracts + (_grep_documents_contract(),)
        return contracts

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        if self.role == "write":
            return self._write_call(name, arguments)
        return self._read_call(name, arguments)

    def _write_call(self, name: str, arguments: dict[str, Any]) -> Any:
        if name == "get_entities":
            return [
                {"urn": CUSTOMERS_URN},
                {"urn": SCORES_URN},
            ]
        if name == "list_schema_fields":
            urn = arguments["urn"]
            if urn == CUSTOMERS_URN:
                fields = [
                    _field(
                        "customer_id",
                        "toxicjoin:stable-pseudonym",
                    ),
                    _field(
                        "coarse_region",
                        "toxicjoin:quasi-identifier",
                    ),
                ]
            elif urn == SCORES_URN:
                fields = [
                    _field(
                        "customer_id",
                        "toxicjoin:stable-pseudonym",
                    ),
                    _field("churn_score", "toxicjoin:model-output"),
                ]
            else:
                raise AssertionError(f"unexpected URN {urn}")
            return {
                "urn": urn,
                "fields": fields,
                "remainingCount": 0,
            }
        if name == "get_lineage":
            return {
                "relationships": [
                    {
                        "source": SCORES_URN,
                        "target": CUSTOMERS_URN,
                        "degree": 1,
                    }
                ],
                "count": 1,
            }
        if name == "save_document":
            self.factory.saved_arguments = dict(arguments)
            return {"document": {"urn": DOCUMENT_URN}}
        raise AssertionError(f"unexpected write-session tool {name}")

    def _read_call(self, name: str, arguments: dict[str, Any]) -> Any:
        if name != "grep_documents":
            raise AssertionError(f"unexpected read-session tool {name}")
        assert arguments["urns"] == [DOCUMENT_URN]
        marker = str(arguments["pattern"])
        saved = self.factory.saved_arguments or {}
        content = str(saved.get("content", ""))
        if not self.factory.preserve_marker:
            content = "read-back content without the expected token"
        if marker not in content:
            return {
                "results": [],
                "total_matches": 0,
                "documents_with_matches": 0,
            }
        return {
            "results": [
                {
                    "urn": DOCUMENT_URN,
                    "title": "ToxicJoin decision",
                    "matches": [
                        {
                            "excerpt": f"marker: {marker}",
                            "position": content.index(marker),
                        }
                    ],
                    "total_matches": 1,
                }
            ],
            "total_matches": 1,
            "documents_with_matches": 1,
        }


def _contracts() -> tuple[McpToolDefinition, ...]:
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
                }
            },
        ),
        McpToolDefinition(
            name="save_document",
            input_schema={
                "properties": {
                    "title": {},
                    "content": {},
                    "document_type": {"enum": ["Decision"]},
                    "related_assets": {},
                }
            },
        ),
    )



def _grep_documents_contract() -> McpToolDefinition:
    return McpToolDefinition(
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

def _field(path: str, tag: str) -> dict[str, Any]:
    return {
        "fieldPath": path,
        "tags": {
            "tags": [
                {"tag": {"properties": {"name": tag}}}
            ]
        },
        "glossaryTerms": {"terms": []},
    }


def _settings() -> DataHubMcpSettings:
    return DataHubMcpSettings(
        gms_url="http://localhost:8080",
        gms_token=SecretStr("TOP_SECRET_TOKEN"),
        command="fake-mcp",
        args=("server",),
    )


def _asset_map() -> DataHubAssetMap:
    return DataHubAssetMap(
        version="test",
        flagship_dataset="retention_scores",
        flagship_column="churn_score",
        datasets={
            "customers": CUSTOMERS_URN,
            "retention_scores": SCORES_URN,
        },
    )


def test_spike_proves_read_write_and_fresh_session_readback(tmp_path) -> None:
    factory = SessionFactory()
    output = tmp_path / "datahub-spike.json"

    report = asyncio.run(
        run_datahub_spike(
            settings=_settings(),
            asset_map=_asset_map(),
            output=output,
            external_url="https://example.test/toxicjoin/receipt",
            transport_factory=factory,
        )
    )

    assert factory.created == 2
    assert report.status == "verified"
    assert report.independent_readback_verified is True
    assert report.decision_document_urn == DOCUMENT_URN
    assert report.lineage_relationship_count == 1
    assert report.field_counts == {"customers": 2, "retention_scores": 2}
    assert set(report.verified_entities) == {CUSTOMERS_URN, SCORES_URN}
    assert factory.saved_arguments is not None
    assert factory.saved_arguments["document_type"] == "Decision"
    assert factory.saved_arguments["related_assets"] == [
        CUSTOMERS_URN,
        SCORES_URN,
    ]
    assert factory.saved_arguments["external_url"] == (
        "https://example.test/toxicjoin/receipt"
    )
    assert report.verification_marker in factory.saved_arguments["content"]

    encoded = output.read_text(encoding="utf-8")
    loaded = DataHubSpikeReport.model_validate(json.loads(encoded))
    assert loaded == report
    assert "TOP_SECRET_TOKEN" not in encoded
    assert "customer rows" not in encoded.lower()
    assert report.settings["token_present"] is True
    assert "gms_url" not in report.settings


def test_spike_rejects_readback_without_marker_and_writes_no_report(tmp_path) -> None:
    factory = SessionFactory(preserve_marker=False)
    output = tmp_path / "datahub-spike.json"

    with pytest.raises(DataHubMcpError, match="verification marker"):
        asyncio.run(
            run_datahub_spike(
                settings=_settings(),
                asset_map=_asset_map(),
                output=output,
                transport_factory=factory,
            )
        )

    assert factory.created == 2
    assert not output.exists()
