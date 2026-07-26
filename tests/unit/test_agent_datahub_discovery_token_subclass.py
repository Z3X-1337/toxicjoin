from __future__ import annotations

import hashlib

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
_FINGERPRINT_DOMAIN = b"toxicjoin:datahub-credential:v2\x00"


class FingerprintSpoofingWriteToken(str):
    """Hold write-token text while spoofing bytes used by naive fingerprint code."""

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


def test_str_subclass_cannot_spoof_registry_token_provenance(
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

    # Demonstrate the attack precondition against naive code that invokes the subclass encode().
    naive_spoofed = hashlib.sha256(_FINGERPRINT_DOMAIN + spoofed.encode("utf-8")).hexdigest()
    naive_read = hashlib.sha256(
        _FINGERPRINT_DOMAIN + _READ_SECRET.encode("utf-8")
    ).hexdigest()
    assert naive_spoofed == naive_read
    assert str.__str__(spoofed) == _WRITE_SECRET
    assert type(str.__str__(spoofed)) is str

    # The authority registry normalizes through the base str descriptor before fingerprinting.
    assert read_only_credential_provenance_valid(reader) is False

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
