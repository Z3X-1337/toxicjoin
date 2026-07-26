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

DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,auth_boundary,PROD)"
_READ_TOKEN = "unrelated-auth-boundary-read-token"
_ENDPOINT = "https://datahub-auth-boundary.example"


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
        catalog_version="authorization-marker-boundary-v1",
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
    "argument",
    (
        "--label=noauthorization:prod",
        "--label=xauthorization=prod",
    ),
)
def test_embedded_authorization_substring_does_not_taint_unrelated_metadata(
    monkeypatch: pytest.MonkeyPatch,
    argument: str,
) -> None:
    settings = _settings(monkeypatch, args=f"mcp-server-datahub {argument}")
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag("classification:production")) is True
    assert guard.context_is_safe(_context_with_tag("classification:prod-marker")) is True


@pytest.mark.parametrize(
    "args",
    (
        "mcp-server-datahub --header 'Authorization: Bearer q7'",
        "mcp-server-datahub --header='Authorization=Bearer q7'",
    ),
)
def test_real_authorization_field_still_protects_bearer_credential(
    monkeypatch: pytest.MonkeyPatch,
    args: str,
) -> None:
    settings = _settings(monkeypatch, args=args)
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag("classification:prefix-q7-suffix")) is False


def test_authorization_marker_after_explicit_separator_is_recognized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(
        monkeypatch,
        args="mcp-server-datahub '--header=Authorization: Bearer q7'",
    )
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag("classification:prefix-q7-suffix")) is False
