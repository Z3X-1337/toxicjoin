from __future__ import annotations

import pytest

from toxicjoin.agent import AgentDataHubDiscoveryError, DataHubAgentDiscoverer
from toxicjoin.context.datahub import DataHubAssetMap
from toxicjoin.integrations.datahub_authority import (
    read_only_credential_provenance_valid,
    read_only_settings_from_env,
)

PATIENTS_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,patients,PROD)"
_READ_SECRET = "agent-read-token"
_WRITE_SECRET = "agent-write-token"
_ENDPOINT = "https://datahub-token-normalization.example"


class FingerprintSpoofingWriteToken(str):
    """Hold write-token text while spoofing the bytes used by the old fingerprint path."""

    def __new__(cls, value: str, *, spoof_value: str):
        instance = super().__new__(cls, value)
        instance._spoof_value = spoof_value
        return instance

    def encode(self, encoding: str = "utf-8", errors: str = "strict") -> bytes:
        return self._spoof_value.encode(encoding, errors)


def _asset_map() -> DataHubAssetMap:
    return DataHubAssetMap(
        version="agent-token-subclass-v1",
        datasets={"patients": PATIENTS_URN},
        flagship_dataset="patients",
        flagship_column="customer_id",
    )


def test_str_subclass_cannot_spoof_read_token_provenance_after_normalization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATAHUB_GMS_URL", _ENDPOINT)
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", _READ_SECRET)
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv("DATAHUB_MCP_ARGS", "mcp-server-datahub")
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")

    reader = read_only_settings_from_env()
    spoofed = FingerprintSpoofingWriteToken(
        _WRITE_SECRET,
        spoof_value=_READ_SECRET,
    )
    reader.gms_token._secret_value = spoofed

    # Demonstrate the exact adversarial precondition: the legacy fingerprint operation is fooled
    # because it invokes the subclass override of encode().
    assert reader.gms_token.get_secret_value() is spoofed
    assert str.__str__(spoofed) == _WRITE_SECRET
    assert type(str.__str__(spoofed)) is str
    assert read_only_credential_provenance_valid(reader) is True

    transport_created = False

    def transport_must_not_be_created(_settings):
        nonlocal transport_created
        transport_created = True
        raise AssertionError("spoofed bearer must fail before transport creation")

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        DataHubAgentDiscoverer(
            settings=reader,
            asset_map=_asset_map(),
            transport_factory=transport_must_not_be_created,
        )

    assert exc_info.value.code == "AGENT_DATAHUB_READ_ROLE_REQUIRED"
    assert transport_created is False
