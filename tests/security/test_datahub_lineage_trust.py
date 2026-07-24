from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from toxicjoin.context import FixtureContextResolver
from toxicjoin.context.datahub import DataHubAssetMap, DataHubSnapshotLoader
from toxicjoin.integrations.datahub_mcp import McpToolDefinition
from toxicjoin.models import Decision, ProjectionExposureKind, ReasonCode, SensitivityCategory
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.sql import analyze_sql


SOURCE_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.source,PROD)"
DERIVED_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.derived,PROD)"
UNKNOWN_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,external.unknown,PROD)"
OBSERVED_AT = datetime(2026, 7, 25, 20, 0, tzinfo=timezone.utc)


class _FakeDataHubClient:
    def __init__(self, *, derived_lineage: dict[str, Any]) -> None:
        self.derived_lineage = derived_lineage
        self.lineage_calls: list[tuple[str, str | None, int, int]] = []

    async def discover_and_validate(self, *, require_mutations: bool):
        del require_mutations
        return (
            McpToolDefinition(name="get_entities", input_schema={"properties": {}}),
            McpToolDefinition(name="get_lineage", input_schema={"properties": {}}),
            McpToolDefinition(name="list_schema_fields", input_schema={"properties": {}}),
        )

    async def get_entities(self, urns: tuple[str, ...]):
        return tuple({"urn": urn} for urn in urns)

    async def list_schema_fields(self, urn: str):
        if urn == SOURCE_URN:
            return (
                {
                    "fieldPath": "customer_id",
                    "tags": ["toxicjoin:stable-pseudonym"],
                },
                {
                    "fieldPath": "secret",
                    "tags": ["toxicjoin:sensitive-attribute"],
                },
            )
        if urn == DERIVED_URN:
            return (
                {
                    "fieldPath": "harmless_value",
                    "tags": ["toxicjoin:public-or-low-risk"],
                },
            )
        raise AssertionError(f"unexpected dataset urn: {urn}")

    async def get_lineage(
        self,
        urn: str,
        *,
        column: str | None = None,
        upstream: bool = True,
        max_hops: int = 2,
        max_results: int = 100,
    ) -> dict[str, Any]:
        assert upstream is True
        self.lineage_calls.append((urn, column, max_hops, max_results))
        if urn == DERIVED_URN and column == "harmless_value":
            return self.derived_lineage
        return _lineage_payload([])


def _lineage_payload(
    relationships: list[dict[str, Any]],
    *,
    has_more: bool = False,
    truncated_due_to_token_budget: bool = False,
) -> dict[str, Any]:
    return {
        "upstreams": {
            "searchResults": relationships,
            "returned": len(relationships),
            "hasMore": has_more,
            "truncatedDueToTokenBudget": truncated_due_to_token_budget,
        },
        "relationships": relationships,
        "metadata": {
            "queryType": "column-level-lineage",
            "groupedBy": "dataset",
        },
    }


def _relationship(
    urn: str,
    columns: list[str],
    *,
    degree: int | str = 1,
) -> dict[str, Any]:
    return {
        "entity": {"urn": urn, "type": "DATASET"},
        "lineageColumns": columns,
        "degree": degree,
    }


def _asset_map() -> DataHubAssetMap:
    return DataHubAssetMap(
        version="p3c-test-v1",
        datasets={"source": SOURCE_URN, "derived": DERIVED_URN},
        flagship_dataset="derived",
        flagship_column="harmless_value",
    )


def _load(derived_lineage: dict[str, Any]):
    client = _FakeDataHubClient(derived_lineage=derived_lineage)
    snapshot = asyncio.run(
        DataHubSnapshotLoader(
            client,  # type: ignore[arg-type]
            _asset_map(),
            clock=lambda: OBSERVED_AT,
        ).load(require_mutations=False)
    )
    return client, snapshot


def test_materialized_public_alias_inherits_upstream_pseudonym_risk() -> None:
    client, snapshot = _load(
        _lineage_payload([_relationship(SOURCE_URN, ["customer_id"])])
    )

    field = snapshot.catalog.datasets["derived"].fields["harmless_value"]
    assert field.category == SensitivityCategory.PUBLIC_OR_LOW_RISK
    assert [(source.ref.key, source.category) for source in field.lineage_sources] == [
        ("source.customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    ]
    assert all(call[2] == 3 for call in client.lineage_calls)

    plan = analyze_sql(
        "SELECT d.harmless_value, s.secret "
        "FROM derived AS d CROSS JOIN source AS s"
    )
    context = FixtureContextResolver(snapshot.catalog).resolve(plan)
    decision = PolicyEngine(load_policy()).evaluate(
        context.to_policy_input(
            task_purpose="P3-C materialized lineage regression",
            query_plan=plan,
        )
    )

    assert decision.decision == Decision.BLOCK
    assert ReasonCode.COMPOSITIONAL_REIDENTIFICATION_RISK in decision.reason_codes
    assert decision.evidence["lineage_sources"]["derived.harmless_value"][0][
        "ref"
    ] == {
        "dataset": "source",
        "field_path": "customer_id",
        "alias": None,
    }


def test_unknown_upstream_column_fails_closed_for_affected_field() -> None:
    _, snapshot = _load(
        _lineage_payload([_relationship(UNKNOWN_URN, ["customer_id"])])
    )
    field = snapshot.catalog.datasets["derived"].fields["harmless_value"]

    assert field.category == SensitivityCategory.PUBLIC_OR_LOW_RISK
    assert len(field.lineage_sources) == 1
    assert field.lineage_sources[0].category == SensitivityCategory.UNCLASSIFIED
    assert field.lineage_sources[0].datahub_urn == UNKNOWN_URN

    plan = analyze_sql("SELECT harmless_value FROM derived")
    context = FixtureContextResolver(snapshot.catalog).resolve(plan)
    assert context.failures == (ReasonCode.UNCLASSIFIED_COLUMN,)

    decision = PolicyEngine(load_policy()).evaluate(
        context.to_policy_input(
            task_purpose="P3-C unknown upstream fail closed",
            query_plan=plan,
        )
    )
    assert decision.decision == Decision.BLOCK
    assert ReasonCode.UNCLASSIFIED_COLUMN in decision.reason_codes


def test_truncated_lineage_fails_closed_instead_of_trusting_partial_graph() -> None:
    _, snapshot = _load(
        _lineage_payload(
            [_relationship(SOURCE_URN, ["customer_id"])],
            has_more=True,
        )
    )
    field = snapshot.catalog.datasets["derived"].fields["harmless_value"]

    assert any(
        source.category == SensitivityCategory.STABLE_PSEUDONYM
        for source in field.lineage_sources
    )
    assert any(
        source.category == SensitivityCategory.UNCLASSIFIED
        for source in field.lineage_sources
    )

    plan = analyze_sql("SELECT harmless_value FROM derived")
    context = FixtureContextResolver(snapshot.catalog).resolve(plan)
    assert context.failures == (ReasonCode.UNCLASSIFIED_COLUMN,)


def test_snapshot_fingerprint_changes_when_governed_lineage_changes() -> None:
    _, pseudonym_snapshot = _load(
        _lineage_payload([_relationship(SOURCE_URN, ["customer_id"])])
    )
    _, sensitive_snapshot = _load(
        _lineage_payload([_relationship(SOURCE_URN, ["secret"])])
    )

    assert pseudonym_snapshot.snapshot_sha256 != sensitive_snapshot.snapshot_sha256


def test_hash_alias_keeps_sql_source_lineage_regression() -> None:
    plan = analyze_sql("SELECT HASH(customer_id) AS harmless_value FROM source")

    assert plan.projected_columns[0].key == "source.customer_id"
    assert plan.projected_exposures[0].output_name == "harmless_value"
    assert plan.projected_exposures[0].kind == ProjectionExposureKind.TRANSFORMED_RAW_VALUE
    assert [ref.key for ref in plan.projected_exposures[0].source_columns] == [
        "source.customer_id"
    ]
