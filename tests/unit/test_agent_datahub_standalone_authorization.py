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

DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,standalone_auth,PROD)"
_READ_TOKEN = "unrelated-standalone-auth-read-token"
_ENDPOINT = "https://standalone-auth.example"


def _settings(
    monkeypatch: pytest.MonkeyPatch,
    *,
    args: str,
) -> ReadOnlyDataHubMcpSettings:
    monkeypatch.setenv("DATAHUB_GMS_URL", _ENDPOINT)
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", _READ_TOKEN)
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv("DATAHUB_MCP_ARGS", args)
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")
    return read_only_settings_from_env()


def _context_with_tag(value: str):
    return build_agent_data_context(
        source_snapshot_sha256="0" * 64,
        catalog_version="standalone-authorization-v1",
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


def test_standalone_authorization_digest_protects_response_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(
        monkeypatch,
        args='mcp-server-datahub --authorization \'Digest username="u", response="q7"\'',
    )
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag("classification:prefix-q7-suffix")) is False
    assert guard.context_is_safe(_context_with_tag("classification:username-u")) is True


@pytest.mark.parametrize("option", ("--auth", "--authorization"))
def test_standalone_authorization_bearer_protects_token_without_tainting_scheme(
    monkeypatch: pytest.MonkeyPatch,
    option: str,
) -> None:
    settings = _settings(
        monkeypatch,
        args=f"mcp-server-datahub {option} 'Bearer q7'",
    )
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag("classification:prefix-q7-suffix")) is False
    assert guard.context_is_safe(_context_with_tag("classification:Bearer-compatible")) is True


def test_auth_assignment_digest_protects_response_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(
        monkeypatch,
        args='mcp-server-datahub --auth=\'Digest username="u", response="q7"\'',
    )
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag("classification:prefix-q7-suffix")) is False
    assert guard.context_is_safe(_context_with_tag("classification:username-u")) is True


@pytest.mark.parametrize(
    ("args", "metadata"),
    (
        ("mcp-server-datahub --auth bearer", "classification:bearer-compatible"),
        ("mcp-server-datahub --auth none", "classification:nonetheless"),
        ("mcp-server-datahub --auth=bearer", "classification:bearer-compatible"),
        ("mcp-server-datahub --auth=none", "classification:nonetheless"),
    ),
)
def test_auth_mode_selectors_do_not_become_short_substring_secrets(
    monkeypatch: pytest.MonkeyPatch,
    args: str,
    metadata: str,
) -> None:
    settings = _settings(monkeypatch, args=args)
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag(metadata)) is True
