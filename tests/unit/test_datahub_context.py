from __future__ import annotations

import asyncio
from collections import deque
from typing import Any, Self

import pytest

from toxicjoin.context.datahub import (
    DataHubAssetMap,
    DataHubMetadataError,
    DataHubSnapshotContextResolver,
    DataHubSnapshotLoader,
)
from toxicjoin.integrations.datahub_mcp import DataHubMcpClient, McpToolDefinition
from toxicjoin.models import ColumnRef, QueryPlan, ReasonCode, SensitivityCategory


CUSTOMERS_URN = (
    "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.customers,PROD)"
)
SCORES_URN = (
    "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.retention_scores,PROD)"
)


class FakeTransport:
    def __init__(self, responses: dict[str, list[Any]]) -> None:
        self.responses = {
            name: deque(values) for name, values in responses.items()
        }

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        return None

    async def list_tools(self) -> tuple[McpToolDefinition, ...]:
        return _contracts()

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        queue = self.responses.get(name)
        if queue is None or not queue:
            raise AssertionError(f"no response configured for {name}")
        return queue.popleft()


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


def _entities(*, include_scores: bool = True) -> list[dict[str, Any]]:
    entities = [
        {
            "urn": CUSTOMERS_URN,
            "ownership": {
                "owners": [
                    {"owner": {"urn": "urn:li:corpuser:data-platform"}}
                ]
            },
            "domains": {
                "domains": [
                    {"domain": {"urn": "urn:li:domain:customer-analytics"}}
                ]
            },
        }
    ]
    if include_scores:
        entities.append(
            {
                "urn": SCORES_URN,
                "ownership": {
                    "owners": [
                        {"owner": {"urn": "urn:li:corpuser:ml-platform"}}
                    ]
                },
            }
        )
    return entities


def _field(
    path: str,
    *,
    tags: tuple[str, ...] = (),
    glossary_terms: tuple[str, ...] = (),
) -> dict[str, Any]:
    return {
        "fieldPath": path,
        "tags": {
            "tags": [
                {"tag": {"properties": {"name": tag}}}
                for tag in tags
            ]
        },
        "glossaryTerms": {
            "terms": [
                {"term": {"properties": {"name": term}}}
                for term in glossary_terms
            ]
        },
    }


def _transport(
    *,
    customer_fields: list[dict[str, Any]] | None = None,
    score_fields: list[dict[str, Any]] | None = None,
    include_scores_entity: bool = True,
) -> FakeTransport:
    return FakeTransport(
        {
            "get_entities": [_entities(include_scores=include_scores_entity)],
            "list_schema_fields": [
                {
                    "urn": CUSTOMERS_URN,
                    "fields": customer_fields
                    or [
                        _field(
                            "customer_id",
                            tags=("toxicjoin:stable-pseudonym",),
                        ),
                        _field(
                            "coarse_region",
                            tags=("toxicjoin:quasi-identifier",),
                        ),
                    ],
                    "remainingCount": 0,
                },
                {
                    "urn": SCORES_URN,
                    "fields": score_fields
                    or [
                        _field(
                            "customer_id",
                            glossary_terms=("StableCustomerIdentifier",),
                        ),
                        _field(
                            "churn_score",
                            tags=("toxicjoin:model-output",),
                        ),
                    ],
                    "remainingCount": 0,
                },
            ],
            "get_lineage": [
                {
                    "relationships": [
                        {
                            "source": SCORES_URN,
                            "target": CUSTOMERS_URN,
                            "degree": 1,
                        }
                    ],
                    "count": 1,
                }
            ],
        }
    )


def test_snapshot_normalizes_entities_fields_and_lineage() -> None:
    client = DataHubMcpClient(_transport())

    snapshot = asyncio.run(
        DataHubSnapshotLoader(client, _asset_map()).load(
            require_mutations=True
        )
    )

    assert snapshot.verified_entities == tuple(sorted((CUSTOMERS_URN, SCORES_URN)))
    assert snapshot.field_counts == {"customers": 2, "retention_scores": 2}
    assert snapshot.lineage_sample["count"] == 1
    assert "save_document" in snapshot.discovered_tools
    customers = snapshot.catalog.datasets["customers"]
    scores = snapshot.catalog.datasets["retention_scores"]
    assert customers.owner == "urn:li:corpuser:data-platform"
    assert customers.domain == "urn:li:domain:customer-analytics"
    assert (
        customers.fields["customer_id"].category
        == SensitivityCategory.STABLE_PSEUDONYM
    )
    assert (
        customers.fields["coarse_region"].category
        == SensitivityCategory.QUASI_IDENTIFIER
    )
    assert (
        scores.fields["churn_score"].category
        == SensitivityCategory.SENSITIVE_ATTRIBUTE
    )


def test_unclassified_live_field_remains_fail_closed() -> None:
    transport = _transport(
        customer_fields=[_field("customer_id")],
    )
    snapshot = asyncio.run(
        DataHubSnapshotLoader(
            DataHubMcpClient(transport),
            _asset_map(),
        ).load(require_mutations=False)
    )
    resolver = DataHubSnapshotContextResolver(snapshot)
    plan = QueryPlan(
        statement_type="SELECT",
        source_datasets=("customers",),
        projected_columns=(
            ColumnRef(dataset="customers", field_path="customer_id"),
        ),
        referenced_columns=(
            ColumnRef(dataset="customers", field_path="customer_id"),
        ),
    )

    resolution = resolver.resolve(plan)

    assert resolution.projected_context[0].category == SensitivityCategory.UNCLASSIFIED
    assert ReasonCode.UNCLASSIFIED_COLUMN in resolution.failures


def test_conflicting_live_classifications_are_rejected() -> None:
    transport = _transport(
        customer_fields=[
            _field(
                "customer_id",
                tags=(
                    "toxicjoin:stable-pseudonym",
                    "toxicjoin:quasi-identifier",
                ),
            )
        ]
    )

    with pytest.raises(DataHubMetadataError, match="conflicting sensitivity"):
        asyncio.run(
            DataHubSnapshotLoader(
                DataHubMcpClient(transport),
                _asset_map(),
            ).load(require_mutations=False)
        )


def test_missing_configured_entity_is_rejected() -> None:
    transport = _transport(include_scores_entity=False)

    with pytest.raises(DataHubMetadataError, match="did not return configured assets"):
        asyncio.run(
            DataHubSnapshotLoader(
                DataHubMcpClient(transport),
                _asset_map(),
            ).load(require_mutations=False)
        )


def test_duplicate_schema_field_paths_are_rejected() -> None:
    transport = _transport(
        customer_fields=[
            _field(
                "customer_id",
                tags=("toxicjoin:stable-pseudonym",),
            ),
            _field(
                "customer_id",
                tags=("toxicjoin:stable-pseudonym",),
            ),
        ]
    )

    with pytest.raises(DataHubMetadataError, match="duplicate field path"):
        asyncio.run(
            DataHubSnapshotLoader(
                DataHubMcpClient(transport),
                _asset_map(),
            ).load(require_mutations=False)
        )

def test_empty_live_lineage_fails_closed() -> None:
    transport = _transport()
    transport.responses["get_lineage"] = deque(
        [{"upstreams": {"searchResults": []}}]
    )

    with pytest.raises(DataHubMetadataError, match="no upstream lineage"):
        asyncio.run(
            DataHubSnapshotLoader(
                DataHubMcpClient(transport),
                _asset_map(),
            ).load(require_mutations=False)
        )

