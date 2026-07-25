from __future__ import annotations

import asyncio
import traceback

import pytest
from pydantic import BaseModel, SecretStr

from toxicjoin.agent import AgentDataHubDiscoveryError, DataHubAgentDiscoverer
from toxicjoin.context.datahub import DataHubAssetMap
from toxicjoin.integrations.datahub_authority import (
    DataHubMcpRole,
    MutationDataHubMcpSettings,
    ReadOnlyDataHubMcpSettings,
    mutation_settings_from_env,
    read_only_credential_provenance_valid,
    read_only_settings_from_env,
)
from toxicjoin.integrations.datahub_mcp import DataHubMcpSettings, McpToolDefinition

PATIENTS_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,patients,PROD)"
_SECRET = "role-bound-agent-secret"
_WRITE_SECRET = "role-bound-writer-secret"
_ENDPOINT = "https://role-bound-datahub.example"


def _asset_map() -> DataHubAssetMap:
    return DataHubAssetMap(
        version="agent-authority-regression-v1",
        datasets={"patients": PATIENTS_URN},
        flagship_dataset="patients",
        flagship_column="customer_id",
    )


def _configure_role_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATAHUB_GMS_URL", _ENDPOINT)
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", _SECRET)
    monkeypatch.setenv("DATAHUB_GMS_WRITE_TOKEN", _WRITE_SECRET)
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv("DATAHUB_MCP_ARGS", "mcp-server-datahub")
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")


def _read_settings(monkeypatch: pytest.MonkeyPatch) -> ReadOnlyDataHubMcpSettings:
    _configure_role_env(monkeypatch)
    return read_only_settings_from_env()


def _mutation_settings(monkeypatch: pytest.MonkeyPatch) -> MutationDataHubMcpSettings:
    _configure_role_env(monkeypatch)
    return mutation_settings_from_env()


def _legacy_settings(*, mutation_enabled: bool) -> DataHubMcpSettings:
    return DataHubMcpSettings(
        gms_url=_ENDPOINT,
        gms_token=SecretStr(_SECRET),
        command="uvx",
        args=("mcp-server-datahub",),
        timeout_seconds=30,
        mutation_enabled=mutation_enabled,
    )


class MutationExposingTransport:
    def __init__(self) -> None:
        self.call_count = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
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
                    }
                },
            ),
            McpToolDefinition(
                name="save_document",
                input_schema={"properties": {"title": {}, "content": {}}},
            ),
        )

    async def call_tool(self, name: str, arguments: dict):
        self.call_count += 1
        raise AssertionError("mutation-exposure rejection must occur before any tool call")


def test_factory_issued_read_credential_retains_child_protections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = _read_settings(monkeypatch)
    assert read_only_credential_provenance_valid(original) is True
    discoverer = DataHubAgentDiscoverer(
        settings=original,
        asset_map=_asset_map(),
        transport_factory=lambda _: MutationExposingTransport(),
    )

    settings = discoverer._settings
    assert type(settings) is ReadOnlyDataHubMcpSettings
    assert settings is not original
    assert read_only_credential_provenance_valid(settings) is True
    assert settings.role == DataHubMcpRole.READ_ONLY
    assert settings.credential_source == "DATAHUB_GMS_READ_TOKEN"
    assert settings.mutation_enabled is False
    child_env = settings.child_environment()
    assert child_env["TOOLS_IS_MUTATION_ENABLED"] == "false"
    assert child_env["SAVE_DOCUMENT_TOOL_ENABLED"] == "false"


def test_direct_read_constructor_is_not_factory_issued() -> None:
    direct = ReadOnlyDataHubMcpSettings(
        gms_url=_ENDPOINT,
        gms_token=SecretStr(_SECRET),
        command="uvx",
        args=("mcp-server-datahub",),
        timeout_seconds=30,
    )
    assert read_only_credential_provenance_valid(direct) is False
    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        DataHubAgentDiscoverer(
            settings=direct,
            asset_map=_asset_map(),
            transport_factory=lambda _: MutationExposingTransport(),
        )
    assert exc_info.value.code == "AGENT_DATAHUB_READ_ROLE_REQUIRED"


@pytest.mark.parametrize("mutation_enabled", [False, True])
def test_legacy_base_credential_is_never_repurposed_for_discovery(
    mutation_enabled: bool,
) -> None:
    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        DataHubAgentDiscoverer(  # type: ignore[arg-type]
            settings=_legacy_settings(mutation_enabled=mutation_enabled),
            asset_map=_asset_map(),
            transport_factory=lambda _: MutationExposingTransport(),
        )
    assert exc_info.value.code == "AGENT_DATAHUB_READ_ROLE_REQUIRED"


def test_mutation_credential_type_is_not_repurposed_for_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        DataHubAgentDiscoverer(  # type: ignore[arg-type]
            settings=_mutation_settings(monkeypatch),
            asset_map=_asset_map(),
            transport_factory=lambda _: MutationExposingTransport(),
        )
    assert exc_info.value.code == "AGENT_DATAHUB_READ_ROLE_REQUIRED"


def test_role_bound_model_copy_cannot_relabel_or_replace_credential(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = _mutation_settings(monkeypatch)
    reader = _read_settings(monkeypatch)
    with pytest.raises(ValueError, match="authority/token fields cannot be changed"):
        writer.model_copy(
            update={
                "role": DataHubMcpRole.READ_ONLY,
                "mutation_enabled": False,
                "credential_source": "DATAHUB_GMS_READ_TOKEN",
            }
        )
    with pytest.raises(ValueError, match="authority/token fields cannot be changed"):
        reader.model_copy(update={"gms_token": writer.gms_token})


def test_concrete_type_rejects_writer_even_if_base_model_copy_bypasses_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writer = _mutation_settings(monkeypatch)
    relabelled = BaseModel.model_copy(
        writer,
        update={
            "role": DataHubMcpRole.READ_ONLY,
            "mutation_enabled": False,
            "credential_source": "DATAHUB_GMS_READ_TOKEN",
        },
    )
    assert type(relabelled) is MutationDataHubMcpSettings
    assert relabelled.role == DataHubMcpRole.READ_ONLY

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        DataHubAgentDiscoverer(  # type: ignore[arg-type]
            settings=relabelled,
            asset_map=_asset_map(),
            transport_factory=lambda _: MutationExposingTransport(),
        )
    assert exc_info.value.code == "AGENT_DATAHUB_READ_ROLE_REQUIRED"


def test_token_swap_via_base_model_copy_breaks_private_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = _read_settings(monkeypatch)
    writer = _mutation_settings(monkeypatch)
    swapped = BaseModel.model_copy(reader, update={"gms_token": writer.gms_token})

    assert type(swapped) is ReadOnlyDataHubMcpSettings
    assert swapped.role == DataHubMcpRole.READ_ONLY
    assert swapped.credential_source == "DATAHUB_GMS_READ_TOKEN"
    assert swapped.gms_token.get_secret_value() == _WRITE_SECRET
    assert read_only_credential_provenance_valid(swapped) is False

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        DataHubAgentDiscoverer(
            settings=swapped,
            asset_map=_asset_map(),
            transport_factory=lambda _: MutationExposingTransport(),
        )
    assert exc_info.value.code == "AGENT_DATAHUB_READ_ROLE_REQUIRED"


def test_read_client_fails_closed_when_server_exposes_mutation_tool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = MutationExposingTransport()
    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        asyncio.run(
            DataHubAgentDiscoverer(
                settings=_read_settings(monkeypatch),
                asset_map=_asset_map(),
                transport_factory=lambda _: transport,
            ).discover()
        )

    assert exc_info.value.code == "AGENT_DATAHUB_DISCOVERY_FAILED"
    assert transport.call_count == 0


def test_transport_cannot_forge_exported_error_to_bypass_redaction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    forged_code = f"forged {_SECRET} {_ENDPOINT}"

    def malicious_factory(_settings):
        try:
            raise RuntimeError(f"inner {_SECRET} {_ENDPOINT}")
        except RuntimeError as exc:
            raise AgentDataHubDiscoveryError(forged_code) from exc

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        asyncio.run(
            DataHubAgentDiscoverer(
                settings=_read_settings(monkeypatch),
                asset_map=_asset_map(),
                transport_factory=malicious_factory,
            ).discover()
        )

    assert exc_info.value.code == "AGENT_DATAHUB_DISCOVERY_FAILED"
    rendered = "".join(
        traceback.format_exception(
            type(exc_info.value),
            exc_info.value,
            exc_info.value.__traceback__,
        )
    )
    assert _SECRET not in rendered
    assert _ENDPOINT not in rendered
    assert "forged" not in rendered
    assert "inner" not in rendered
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__suppress_context__ is True
