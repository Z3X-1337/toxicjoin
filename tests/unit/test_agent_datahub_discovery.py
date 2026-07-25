from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from toxicjoin.agent import (
    AgentDataHubDiscoveryError,
    DataHubAgentDiscoverer,
    build_agent_data_context_from_snapshot,
)
from toxicjoin.context.datahub import DataHubAssetMap, DataHubSnapshot
from toxicjoin.context.fixture import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.integrations.datahub_authority import (
    DataHubMcpRole,
    ReadOnlyDataHubMcpSettings,
    read_only_credential_provenance_valid,
    read_only_settings_from_env,
)
from toxicjoin.integrations.datahub_mcp import McpToolDefinition
from toxicjoin.models import ColumnRef, LineageSource, SensitivityCategory

PATIENTS_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,patients,PROD)"
RAW_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,raw_patients,PROD)"
OBSERVED_AT = datetime(2026, 7, 25, 14, 0, tzinfo=timezone.utc)


def _settings(monkeypatch: pytest.MonkeyPatch) -> ReadOnlyDataHubMcpSettings:
    monkeypatch.setenv("DATAHUB_GMS_URL", "https://datahub.example")
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", "agent-discovery-secret-token")
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv("DATAHUB_MCP_ARGS", "mcp-server-datahub")
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")
    return read_only_settings_from_env()


def _asset_map() -> DataHubAssetMap:
    return DataHubAssetMap(
        version="agent-discovery-v1",
        datasets={"patients": PATIENTS_URN, "raw_patients": RAW_URN},
        flagship_dataset="patients",
        flagship_column="customer_id",
    )


class FakeReadOnlyTransport:
    def __init__(
        self,
        settings: ReadOnlyDataHubMcpSettings,
        *,
        fail_list_tools: bool = False,
    ) -> None:
        self.settings = settings
        self.fail_list_tools = fail_list_tools
        self.calls: list[tuple[str, dict]] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback) -> None:
        return None

    async def list_tools(self) -> tuple[McpToolDefinition, ...]:
        if self.fail_list_tools:
            raise RuntimeError(
                "transport leaked agent-discovery-secret-token https://datahub.example"
            )
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
        self.calls.append((name, dict(arguments)))
        if name == "get_entities":
            return [
                {
                    "urn": PATIENTS_URN,
                    "ownership": {"owner": "urn:li:corpuser:privacy-owner"},
                    "domains": {"domain": "urn:li:domain:privacy"},
                },
                {"urn": RAW_URN},
            ]
        if name == "list_schema_fields":
            return {
                "fields": [
                    {
                        "fieldPath": "country",
                        "tags": ["toxicjoin:public-or-low-risk"],
                    },
                    {
                        "fieldPath": "customer_id",
                        "tags": ["toxicjoin:stable-pseudonym"],
                    },
                ],
                "remainingCount": 0,
            }
        if name == "get_lineage":
            urn = arguments["urn"]
            column = arguments["column"]
            if urn == PATIENTS_URN:
                return {
                    "relationships": [
                        {
                            "entity": {"urn": RAW_URN},
                            "lineageColumns": [column],
                        }
                    ]
                }
            return {"relationships": []}
        raise AssertionError(f"unexpected tool call: {name}")


def test_discoverer_uses_dedicated_read_role_and_sanitizes_context(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = _settings(monkeypatch)
    captured: list[FakeReadOnlyTransport] = []

    def factory(settings: ReadOnlyDataHubMcpSettings) -> FakeReadOnlyTransport:
        transport = FakeReadOnlyTransport(settings)
        captured.append(transport)
        return transport

    context = asyncio.run(
        DataHubAgentDiscoverer(
            settings=original,
            asset_map=_asset_map(),
            transport_factory=factory,
        ).discover()
    )

    assert type(original) is ReadOnlyDataHubMcpSettings
    assert read_only_credential_provenance_valid(original) is True
    assert original.role == DataHubMcpRole.READ_ONLY
    assert original.credential_source == "DATAHUB_GMS_READ_TOKEN"
    assert original.mutation_enabled is False
    assert len(captured) == 1
    read_settings = captured[0].settings
    assert read_settings is not original
    assert type(read_settings) is ReadOnlyDataHubMcpSettings
    assert read_only_credential_provenance_valid(read_settings) is True
    assert read_settings.role == DataHubMcpRole.READ_ONLY
    assert read_settings.credential_source == "DATAHUB_GMS_READ_TOKEN"
    assert read_settings.mutation_enabled is False
    child_env = read_settings.child_environment()
    assert child_env["TOOLS_IS_MUTATION_ENABLED"] == "false"
    assert child_env["SAVE_DOCUMENT_TOOL_ENABLED"] == "false"
    assert all(name != "save_document" for name, _ in captured[0].calls)

    assert context.security_authoritative is False
    assert context.source == "DATAHUB"
    assert context.catalog_version == "datahub-mcp:agent-discovery-v1"
    assert tuple(dataset.logical_name for dataset in context.datasets) == (
        "patients",
        "raw_patients",
    )
    patients = context.datasets[0]
    assert patients.security_authoritative is False
    assert patients.owner == "urn:li:corpuser:privacy-owner"
    assert patients.domain == "urn:li:domain:privacy"
    assert all(field.security_authoritative is False for field in patients.fields)
    customer_id = next(field for field in patients.fields if field.field_path == "customer_id")
    assert customer_id.lineage[0].source_dataset_urn == RAW_URN
    assert customer_id.lineage[0].security_authoritative is False

    serialized = context.model_dump_json()
    assert "agent-discovery-secret-token" not in serialized
    assert "https://datahub.example" not in serialized
    assert "save_document" not in serialized
    assert "TOOLS_IS_MUTATION_ENABLED" not in serialized


def test_snapshot_conversion_is_deterministic(monkeypatch: pytest.MonkeyPatch) -> None:
    transport = FakeReadOnlyTransport(_settings(monkeypatch))

    def factory(settings: ReadOnlyDataHubMcpSettings) -> FakeReadOnlyTransport:
        assert type(settings) is ReadOnlyDataHubMcpSettings
        assert read_only_credential_provenance_valid(settings) is True
        assert settings.role == DataHubMcpRole.READ_ONLY
        assert settings.mutation_enabled is False
        return transport

    first = asyncio.run(
        DataHubAgentDiscoverer(
            settings=_settings(monkeypatch),
            asset_map=_asset_map(),
            transport_factory=factory,
        ).discover()
    )
    transport2 = FakeReadOnlyTransport(_settings(monkeypatch))
    second = asyncio.run(
        DataHubAgentDiscoverer(
            settings=_settings(monkeypatch),
            asset_map=_asset_map(),
            transport_factory=lambda settings: transport2,
        ).discover()
    )
    assert first == second
    assert first.context_sha256 == second.context_sha256


def test_unresolved_lineage_identity_fails_closed() -> None:
    snapshot = DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:unresolved",
            datasets={
                "patients": FixtureDataset(
                    urn=PATIENTS_URN,
                    fields={
                        "customer_id": FixtureField(
                            category=SensitivityCategory.STABLE_PSEUDONYM,
                            lineage_sources=(
                                LineageSource(
                                    ref=ColumnRef(
                                        dataset="@datahub-lineage",
                                        field_path="patients.customer_id:deadbeef",
                                    ),
                                    category=SensitivityCategory.UNCLASSIFIED,
                                    datahub_urn=None,
                                ),
                            ),
                        )
                    },
                )
            },
        ),
        verified_entities=(PATIENTS_URN,),
        field_counts={"patients": 1},
        lineage_sample={"relationships": [{"entity": {"urn": RAW_URN}}]},
        discovered_tools=("get_entities", "get_lineage", "list_schema_fields"),
        observed_at=OBSERVED_AT,
    )

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        build_agent_data_context_from_snapshot(snapshot)
    assert exc_info.value.code == "AGENT_DATAHUB_LINEAGE_IDENTITY_UNRESOLVED"


def test_unclassified_remote_lineage_with_exact_urn_remains_planning_only() -> None:
    snapshot = DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:remote",
            datasets={
                "patients": FixtureDataset(
                    urn=PATIENTS_URN,
                    fields={
                        "customer_id": FixtureField(
                            category=SensitivityCategory.STABLE_PSEUDONYM,
                            lineage_sources=(
                                LineageSource(
                                    ref=ColumnRef(
                                        dataset=f"@datahub:{RAW_URN}",
                                        field_path="external_customer_id",
                                    ),
                                    category=SensitivityCategory.UNCLASSIFIED,
                                    datahub_urn=RAW_URN,
                                ),
                            ),
                        )
                    },
                )
            },
        ),
        verified_entities=(PATIENTS_URN,),
        field_counts={"patients": 1},
        lineage_sample={"relationships": [{"entity": {"urn": RAW_URN}}]},
        discovered_tools=("get_entities", "get_lineage", "list_schema_fields"),
        observed_at=OBSERVED_AT,
    )

    context = build_agent_data_context_from_snapshot(snapshot)
    lineage = context.datasets[0].fields[0].lineage[0]
    assert lineage.source_dataset_urn == RAW_URN
    assert lineage.category == SensitivityCategory.UNCLASSIFIED
    assert lineage.security_authoritative is False


def test_invalid_dataset_identity_fails_closed() -> None:
    snapshot = DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:bad-dataset",
            datasets={
                "patients": FixtureDataset(
                    urn="not-a-datahub-dataset-urn",
                    fields={
                        "customer_id": FixtureField(
                            category=SensitivityCategory.STABLE_PSEUDONYM
                        )
                    },
                )
            },
        ),
        verified_entities=("not-a-datahub-dataset-urn",),
        field_counts={"patients": 1},
        lineage_sample={"relationships": []},
        discovered_tools=("get_entities",),
        observed_at=OBSERVED_AT,
    )

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        build_agent_data_context_from_snapshot(snapshot)
    assert exc_info.value.code == "AGENT_DATAHUB_DATASET_IDENTITY_INVALID"


def test_transport_exception_is_redacted(monkeypatch: pytest.MonkeyPatch) -> None:
    def factory(settings: ReadOnlyDataHubMcpSettings) -> FakeReadOnlyTransport:
        return FakeReadOnlyTransport(settings, fail_list_tools=True)

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        asyncio.run(
            DataHubAgentDiscoverer(
                settings=_settings(monkeypatch),
                asset_map=_asset_map(),
                transport_factory=factory,
            ).discover()
        )
    assert exc_info.value.code == "AGENT_DATAHUB_DISCOVERY_FAILED"
    assert "secret-token" not in str(exc_info.value)
    assert "datahub.example" not in str(exc_info.value)


def test_context_contains_no_tool_or_credential_handles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = asyncio.run(
        DataHubAgentDiscoverer(
            settings=_settings(monkeypatch),
            asset_map=_asset_map(),
            transport_factory=lambda settings: FakeReadOnlyTransport(settings),
        ).discover()
    )
    field_names = set(context.__class__.model_fields)
    assert "settings" not in field_names
    assert "client" not in field_names
    assert "transport" not in field_names
    assert "tools" not in field_names
    assert "token" not in field_names
