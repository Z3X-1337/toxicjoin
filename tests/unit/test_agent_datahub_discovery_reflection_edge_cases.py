from __future__ import annotations

import pytest

from toxicjoin.agent.datahub_discovery import _AgentMetadataSecretGuard
from toxicjoin.agent.models import (
    AgentDatasetView,
    AgentFieldView,
    build_agent_data_context,
)
from toxicjoin.integrations.datahub_authority import (
    ReadOnlyDataHubMcpSettings,
    read_only_settings_from_env,
)
from toxicjoin.models import SensitivityCategory

DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,reflection_edges,PROD)"
_DEFAULT_TOKEN = "unrelated-read-token-for-edge-tests"
_DEFAULT_ENDPOINT = "https://datahub-reflection-edge.example"


def _settings(
    monkeypatch: pytest.MonkeyPatch,
    *,
    token: str = _DEFAULT_TOKEN,
    endpoint: str = _DEFAULT_ENDPOINT,
) -> ReadOnlyDataHubMcpSettings:
    monkeypatch.setenv("DATAHUB_GMS_URL", endpoint)
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", token)
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv("DATAHUB_MCP_ARGS", "mcp-server-datahub")
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")
    return read_only_settings_from_env()


def _context_with_tag(value: str):
    return build_agent_data_context(
        source_snapshot_sha256="0" * 64,
        catalog_version="reflection-edge-tests-v1",
        datasets=(
            AgentDatasetView(
                logical_name="patients",
                dataset_urn=DATASET_URN,
                fields=(
                    AgentFieldView(
                        field_path="customer_id",
                        category=SensitivityCategory.STABLE_PSEUDONYM,
                        tags=(value,),
                    ),
                ),
            ),
        ),
    )


@pytest.mark.parametrize(
    "encoded",
    (
        "cTc=",
        "cTd=",
        "cTe=",
        "cTf=",
        "cTc",
        "cTd",
        "cTe",
        "cTf",
    ),
)
def test_guard_rejects_equivalent_noncanonical_base64_pad_bits(
    monkeypatch: pytest.MonkeyPatch,
    encoded: str,
) -> None:
    settings = _settings(monkeypatch, token="q7")
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag(f"classification:{encoded}:marker")) is False


def test_guard_does_not_confuse_neighboring_base64_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(monkeypatch, token="q7")
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    # cTg= decodes to q8, not the protected q7 bearer.
    assert guard.context_is_safe(_context_with_tag("classification:cTg=:marker")) is True


def test_guard_extracts_short_secret_marked_endpoint_path_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(
        monkeypatch,
        endpoint="https://datahub-reflection-edge.example/access_token=q7",
    )
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag("classification:prefix-q7-suffix")) is False


def test_guard_keeps_short_ordinary_endpoint_path_component_non_strong(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(
        monkeypatch,
        endpoint="https://datahub-reflection-edge.example/api",
    )
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag("classification:safe-api-metadata")) is True


@pytest.mark.parametrize("env_name", ("NO_PROXY", "no_proxy"))
def test_guard_protects_each_forwarded_no_proxy_entry(
    monkeypatch: pytest.MonkeyPatch,
    env_name: str,
) -> None:
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.setenv(
        env_name,
        "localhost, internal-datahub.example ,10.0.0.0/8",
    )
    settings = _settings(monkeypatch)
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert (
        guard.context_is_safe(
            _context_with_tag("classification:internal-datahub.example:marker")
        )
        is False
    )


def test_guard_does_not_make_short_no_proxy_entry_a_broad_secret_pattern(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.setenv("NO_PROXY", "db")
    settings = _settings(monkeypatch)
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag("classification:safe-db-metadata")) is True
