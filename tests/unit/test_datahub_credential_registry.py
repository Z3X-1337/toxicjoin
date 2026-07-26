from __future__ import annotations

import asyncio

import pytest

from toxicjoin.agent import AgentDataHubDiscoveryError, DataHubAgentDiscoverer
from toxicjoin.context.datahub import DataHubAssetMap
from toxicjoin.integrations.datahub_authority import (
    read_only_credential_provenance_valid,
    read_only_settings_from_env,
)

PATIENTS_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,patients,PROD)"
_READ_SECRET = "registry-read-token"
_WRITE_SECRET = "registry-write-token"
_ENDPOINT = "https://registry-datahub.example"


def _configure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DATAHUB_GMS_URL", _ENDPOINT)
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", _READ_SECRET)
    monkeypatch.setenv("DATAHUB_GMS_WRITE_TOKEN", _WRITE_SECRET)
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv("DATAHUB_MCP_ARGS", "mcp-server-datahub")
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")


def _asset_map() -> DataHubAssetMap:
    return DataHubAssetMap(
        version="credential-registry-v1",
        datasets={"patients": PATIENTS_URN},
        flagship_dataset="patients",
        flagship_column="customer_id",
    )


def test_factory_provenance_is_not_rebindable_from_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    reader = read_only_settings_from_env()
    assert read_only_credential_provenance_valid(reader) is True

    assert not hasattr(reader, "_factory_seal")
    assert not hasattr(reader, "_token_fingerprint")
    assert not hasattr(reader, "_bind_factory_provenance")
    assert not hasattr(reader, "_factory_provenance_matches")

    reader.gms_token._secret_value = _WRITE_SECRET
    assert read_only_credential_provenance_valid(reader) is False
    with pytest.raises(AttributeError):
        getattr(reader, "_bind_factory_provenance")

    transport_created = False

    def transport_must_not_be_created(_settings):
        nonlocal transport_created
        transport_created = True
        raise AssertionError("modified registry credential must fail before transport creation")

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        DataHubAgentDiscoverer(
            settings=reader,
            asset_map=_asset_map(),
            transport_factory=transport_must_not_be_created,
        )
    assert exc_info.value.code == "AGENT_DATAHUB_READ_ROLE_REQUIRED"
    assert transport_created is False


def test_registry_binds_child_endpoint_and_launcher_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    reader = read_only_settings_from_env()
    assert read_only_credential_provenance_valid(reader) is True

    # Bypass frozen-model ergonomics deliberately: provenance must still detect the change.
    object.__setattr__(reader, "gms_url", "https://attacker.example")
    assert read_only_credential_provenance_valid(reader) is False

    transport_created = False

    def transport_must_not_be_created(_settings):
        nonlocal transport_created
        transport_created = True
        raise AssertionError("modified endpoint must fail before transport creation")

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        DataHubAgentDiscoverer(
            settings=reader,
            asset_map=_asset_map(),
            transport_factory=transport_must_not_be_created,
        )
    assert exc_info.value.code == "AGENT_DATAHUB_READ_ROLE_REQUIRED"
    assert transport_created is False


def test_discovery_revalidates_internal_registered_credential_before_transport(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _configure(monkeypatch)
    discoverer = DataHubAgentDiscoverer(
        settings=read_only_settings_from_env(),
        asset_map=_asset_map(),
        transport_factory=lambda _settings: (_ for _ in ()).throw(
            AssertionError("mutated internal credential must fail before transport creation")
        ),
    )
    assert read_only_credential_provenance_valid(discoverer._settings) is True

    # Deliberately mutate the private clone after construction. discover() must not trust it.
    discoverer._settings.gms_token._secret_value = _WRITE_SECRET
    assert read_only_credential_provenance_valid(discoverer._settings) is False

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        asyncio.run(discoverer.discover())
    assert exc_info.value.code == "AGENT_DATAHUB_DISCOVERY_FAILED"
