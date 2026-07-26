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

DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,launch_material_edges,PROD)"
_DEFAULT_TOKEN = "launch-material-default-read-token"
_DEFAULT_ENDPOINT = "https://datahub-launch-material.example"


def _settings(
    monkeypatch: pytest.MonkeyPatch,
    *,
    token: str = _DEFAULT_TOKEN,
    endpoint: str = _DEFAULT_ENDPOINT,
    args: str = "mcp-server-datahub",
) -> ReadOnlyDataHubMcpSettings:
    monkeypatch.setenv("DATAHUB_GMS_URL", endpoint)
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", token)
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv("DATAHUB_MCP_ARGS", args)
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")
    return read_only_settings_from_env()


def _context_with_tag(value: str):
    return build_agent_data_context(
        source_snapshot_sha256="0" * 64,
        catalog_version="launch-material-edge-tests-v1",
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


def test_guard_extracts_credentials_from_ordinary_launcher_url_argument(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(
        monkeypatch,
        args="mcp-server-datahub --server-url https://user:q7@launcher.example",
    )
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag("classification:prefix-q7-suffix")) is False


def test_guard_extracts_credentials_from_url_assignment_launcher_argument(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(
        monkeypatch,
        args="mcp-server-datahub --server-url=https://user:q7@launcher.example",
    )
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag("classification:prefix-q7-suffix")) is False


def test_guard_allows_unrelated_metadata_with_noncredentialed_launcher_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(
        monkeypatch,
        args="mcp-server-datahub --server-url https://launcher.example/api",
    )
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag("classification:safe-api-launcher")) is True


def test_guard_bounds_compound_endpoint_secret_marker_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(
        monkeypatch,
        endpoint="https://datahub-launch-material.example/access_token=q7;mode=prod",
    )
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag("classification:prefix-q7-suffix")) is False


def test_guard_extracts_each_secret_from_compound_launcher_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(
        monkeypatch,
        args="mcp-server-datahub --metadata token=q7;password=p8",
    )
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag("classification:prefix-q7-suffix")) is False
    assert guard.context_is_safe(_context_with_tag("classification:prefix-p8-suffix")) is False


def test_guard_allows_nonsecret_compound_launcher_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(
        monkeypatch,
        args="mcp-server-datahub --metadata mode=prod;region=us",
    )
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag("classification:prod-marker")) is True


@pytest.mark.parametrize("env_name", ("NO_PROXY", "no_proxy"))
def test_guard_preserves_exact_forwarded_no_proxy_value_before_trimming(
    monkeypatch: pytest.MonkeyPatch,
    env_name: str,
) -> None:
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.setenv(env_name, " db ")
    settings = _settings(monkeypatch)
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag(" db ")) is False
    assert guard.context_is_safe(_context_with_tag("db")) is False
    assert guard.context_is_safe(_context_with_tag("classification:safe-db-metadata")) is True
