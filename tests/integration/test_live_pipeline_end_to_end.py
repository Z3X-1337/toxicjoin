"""The live runtime, exercised end to end against a simulated DataHub MCP server.

Everything below the transport is the real thing: the real snapshot loader, the real tag →
category normalization, the real freshness binding, the real policy engine, the real DuckDB
executor and the real receipt store. Only the MCP wire is faked, so this proves the assembly
that a live deployment actually depends on — including that governance genuinely drives the
decision, which is the project's central claim.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Self

import pytest

from toxicjoin.api.live import create_live_pipeline
from toxicjoin.auth import RequestIdentity, bind_request_identity
from toxicjoin.context.datahub import DataHubAssetMap
from toxicjoin.integrations.datahub_mcp import McpToolDefinition
from toxicjoin.models import ColumnRef, Decision, ReasonCode, SensitivityCategory
from toxicjoin.pipeline import PipelineRequest
from toxicjoin.receipts import ReceiptMode


PLATFORM = "urn:li:dataPlatform:duckdb"
CUSTOMERS_URN = f"urn:li:dataset:({PLATFORM},toxicjoin.customers,PROD)"
ORDERS_URN = f"urn:li:dataset:({PLATFORM},toxicjoin.orders,PROD)"
SCORES_URN = f"urn:li:dataset:({PLATFORM},toxicjoin.retention_scores,PROD)"

SUBJECT = ColumnRef(dataset="customers", field_path="customer_id", alias="c")


def _contracts() -> tuple[McpToolDefinition, ...]:
    return (
        McpToolDefinition(name="get_entities", input_schema={"properties": {"urns": {}}}),
        McpToolDefinition(
            name="list_schema_fields",
            input_schema={
                "properties": {"urn": {}, "keywords": {}, "limit": {}, "offset": {}}
            },
        ),
        McpToolDefinition(
            name="get_lineage",
            input_schema={
                "properties": {"urn": {}, "column": {}, "upstream": {}, "max_hops": {}}
            },
        ),
    )


def _field(path: str, *, tags: tuple[str, ...] = ()) -> dict[str, Any]:
    return {
        "fieldPath": path,
        "tags": {"tags": [{"tag": {"properties": {"name": tag}}} for tag in tags]},
        "glossaryTerms": {"terms": []},
    }


def _no_lineage() -> dict[str, Any]:
    return {
        "upstreams": {
            "searchResults": [],
            "returned": 0,
            "hasMore": False,
            "truncatedDueToTokenBudget": False,
        },
        "relationships": [],
    }


def _lineage_from(urn: str, columns: list[str]) -> dict[str, Any]:
    relationships = [
        {"entity": {"urn": urn, "type": "DATASET"}, "lineageColumns": columns, "degree": 1}
    ]
    return {
        "upstreams": {
            "searchResults": relationships,
            "returned": 1,
            "hasMore": False,
            "truncatedDueToTokenBudget": False,
        },
        "relationships": relationships,
    }


# The governed graph a real DataHub would serve. `churn_score` is the flagship column and is
# the one field whose upstream lineage must resolve, matching the loader's contract.
SCHEMAS: dict[str, list[dict[str, Any]]] = {
    CUSTOMERS_URN: [
        _field("customer_id", tags=("toxicjoin:stable-pseudonym",)),
        _field("age_band", tags=("toxicjoin:quasi-identifier",)),
        _field("precise_area", tags=("toxicjoin:quasi-identifier",)),
        _field("coarse_region", tags=("toxicjoin:quasi-identifier",)),
    ],
    ORDERS_URN: [
        _field("order_id", tags=("toxicjoin:public-or-low-risk",)),
        _field("customer_id", tags=("toxicjoin:stable-pseudonym",)),
        _field("purchase_amount", tags=("toxicjoin:financial",)),
        _field("category", tags=("toxicjoin:public-or-low-risk",)),
        _field("ordered_at", tags=("toxicjoin:public-or-low-risk",)),
    ],
    SCORES_URN: [
        _field("customer_id", tags=("toxicjoin:stable-pseudonym",)),
        _field("churn_score", tags=("toxicjoin:model-output",)),
        _field("model_timestamp", tags=("toxicjoin:public-or-low-risk",)),
    ],
}


class SimulatedDataHub:
    """A DataHub MCP server that answers from an in-memory governed graph."""

    def __init__(self, schemas: dict[str, list[dict[str, Any]]]) -> None:
        self.schemas = schemas
        self.snapshot_requests = 0

    def __call__(self, settings: Any) -> "SimulatedDataHub":
        del settings
        return self

    async def __aenter__(self) -> Self:
        self.snapshot_requests += 1
        return self

    async def __aexit__(self, *_: object) -> None:
        return None

    async def list_tools(self) -> tuple[McpToolDefinition, ...]:
        return _contracts()

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        if name == "get_entities":
            return [{"urn": urn} for urn in arguments["urns"]]
        if name == "list_schema_fields":
            fields = self.schemas[arguments["urn"]]
            return {"fields": fields, "remainingCount": 0}
        if name == "get_lineage":
            if arguments["urn"] == SCORES_URN and arguments.get("column") == "churn_score":
                return _lineage_from(ORDERS_URN, ["purchase_amount"])
            return _no_lineage()
        raise AssertionError(f"unexpected tool call: {name}")


def _asset_map() -> DataHubAssetMap:
    return DataHubAssetMap(
        version="live-e2e",
        flagship_dataset="retention_scores",
        flagship_column="churn_score",
        datasets={
            "customers": CUSTOMERS_URN,
            "orders": ORDERS_URN,
            "retention_scores": SCORES_URN,
        },
    )


@pytest.fixture
def live_env(
    monkeypatch: pytest.MonkeyPatch,
    seeded_database: Path,
    tmp_path: Path,
) -> Path:
    monkeypatch.setenv("DATAHUB_GMS_URL", "http://datahub.internal:8080")
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", "read-scoped-token")
    monkeypatch.setenv("TOXICJOIN_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setenv("TOXICJOIN_DATABASE", str(seeded_database))
    return tmp_path


def _runtime(datahub: SimulatedDataHub):
    return create_live_pipeline(asset_map=_asset_map(), transport_factory=datahub)


def _identity() -> RequestIdentity:
    return RequestIdentity(
        principal_id="live-analyst",
        credential_id="live-cred",
        agent_id="live-agent",
    )


def test_live_runtime_builds_governed_context_from_datahub(live_env: Path) -> None:
    datahub = SimulatedDataHub(SCHEMAS)
    runtime = _runtime(datahub)

    assert datahub.snapshot_requests == 1
    assert runtime.pipeline.mode is ReceiptMode.LIVE
    # Stateful privacy cannot be switched off in LIVE mode.
    assert runtime.pipeline.stateful_privacy_required is True
    assert runtime.pipeline.disclosure_ledger is not None

    catalog = runtime.snapshot.catalog
    assert catalog.version == "datahub-mcp:live-e2e"
    customers = catalog.datasets["customers"]
    assert customers.fields["customer_id"].category is SensitivityCategory.STABLE_PSEUDONYM
    assert customers.fields["age_band"].category is SensitivityCategory.QUASI_IDENTIFIER
    scores = catalog.datasets["retention_scores"]
    assert scores.fields["churn_score"].category is SensitivityCategory.SENSITIVE_ATTRIBUTE


def test_live_decisions_are_driven_by_datahub_tags(live_env: Path) -> None:
    """The central claim: change the governance, change the decision."""

    sql = (
        "SELECT c.customer_id, c.age_band, c.precise_area, r.churn_score "
        "FROM customers c JOIN retention_scores r ON c.customer_id = r.customer_id"
    )
    request = PipelineRequest(task_purpose="live governance", sql=sql, subject_key=SUBJECT)

    governed = _runtime(SimulatedDataHub(SCHEMAS))
    with bind_request_identity(_identity()):
        blocked = governed.pipeline.analyze(request)

    assert blocked.effective_decision == Decision.BLOCK
    assert ReasonCode.COMPOSITIONAL_REIDENTIFICATION_RISK in (
        blocked.initial_decision.reason_codes
    )


def test_untagged_datahub_fields_fail_closed(live_env: Path) -> None:
    """An unclassified field must block, not default to permissive."""

    untagged = dict(SCHEMAS)
    untagged[ORDERS_URN] = [
        _field("order_id", tags=("toxicjoin:public-or-low-risk",)),
        _field("customer_id", tags=("toxicjoin:stable-pseudonym",)),
        _field("purchase_amount"),  # governance forgot to classify this
        _field("category", tags=("toxicjoin:public-or-low-risk",)),
        _field("ordered_at", tags=("toxicjoin:public-or-low-risk",)),
    ]
    runtime = _runtime(SimulatedDataHub(untagged))

    request = PipelineRequest(
        task_purpose="unclassified spend",
        sql="SELECT o.category, AVG(o.purchase_amount) AS spend FROM orders o GROUP BY o.category",
        subject_key=SUBJECT,
    )
    with bind_request_identity(_identity()):
        result = runtime.pipeline.analyze(request)

    assert result.effective_decision == Decision.BLOCK
    assert ReasonCode.UNCLASSIFIED_COLUMN in result.initial_decision.reason_codes


def test_live_execution_releases_rows_and_binds_the_snapshot(live_env: Path) -> None:
    runtime = _runtime(SimulatedDataHub(SCHEMAS))
    request = PipelineRequest(
        task_purpose="regional churn",
        sql=(
            "SELECT c.coarse_region, AVG(r.churn_score) AS average_churn, "
            "COUNT(DISTINCT c.customer_id) AS subject_count "
            "FROM customers c JOIN retention_scores r ON c.customer_id = r.customer_id "
            "GROUP BY c.coarse_region HAVING COUNT(DISTINCT c.customer_id) >= 20"
        ),
        subject_key=SUBJECT,
    )
    with bind_request_identity(_identity()):
        result = runtime.pipeline.execute_safe(request)

    assert result.effective_decision == Decision.ALLOW
    assert result.verification is not None
    assert result.verification.execution is not None
    assert len(result.verification.execution.rows) == 3

    # The receipt must carry live provenance, not a fixture placeholder.
    assert result.receipt.mode is ReceiptMode.LIVE
    assert result.receipt.governance is not None
    assert result.receipt.governance.source == "datahub-mcp"
    assert result.receipt.governance.snapshot_sha256 == runtime.snapshot.snapshot_sha256


def test_refresher_reinstalls_governance_after_a_tag_change(live_env: Path) -> None:
    """A governance change in DataHub must reach decisions without a restart."""

    schemas = {urn: list(fields) for urn, fields in SCHEMAS.items()}
    datahub = SimulatedDataHub(schemas)
    runtime = _runtime(datahub)

    request = PipelineRequest(
        task_purpose="public order counts",
        sql="SELECT o.category, COUNT(*) AS order_count FROM orders o GROUP BY o.category",
        subject_key=SUBJECT,
    )
    with bind_request_identity(_identity()):
        assert runtime.pipeline.analyze(request).effective_decision == Decision.ALLOW

    # Governance reclassifies a previously public column as sensitive.
    schemas[ORDERS_URN] = [
        _field("order_id", tags=("toxicjoin:public-or-low-risk",)),
        _field("customer_id", tags=("toxicjoin:stable-pseudonym",)),
        _field("purchase_amount", tags=("toxicjoin:financial",)),
        _field("category", tags=("toxicjoin:sensitive-attribute",)),
        _field("ordered_at", tags=("toxicjoin:public-or-low-risk",)),
    ]
    runtime.refresher.refresh_now()

    with bind_request_identity(_identity()):
        after = runtime.pipeline.analyze(request)

    assert after.effective_decision != Decision.ALLOW
    assert datahub.snapshot_requests == 2


def test_live_mode_requires_an_existing_warehouse(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Live mode must not silently seed synthetic rows under real governance."""

    monkeypatch.setenv("DATAHUB_GMS_URL", "http://datahub.internal:8080")
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", "read-scoped-token")
    monkeypatch.setenv("TOXICJOIN_RUNTIME_DIR", str(tmp_path))
    monkeypatch.setenv("TOXICJOIN_DATABASE", str(tmp_path / "absent.duckdb"))

    with pytest.raises(ValueError, match="requires an existing warehouse database"):
        _runtime(SimulatedDataHub(SCHEMAS))
