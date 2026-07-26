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

DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,digest_auth,PROD)"
_READ_TOKEN = "unrelated-digest-read-token"
_ENDPOINT = "https://datahub-digest.example"


def _settings(
    monkeypatch: pytest.MonkeyPatch,
    *,
    authorization: str,
) -> ReadOnlyDataHubMcpSettings:
    monkeypatch.setenv("DATAHUB_GMS_URL", _ENDPOINT)
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", _READ_TOKEN)
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv(
        "DATAHUB_MCP_ARGS",
        f"mcp-server-datahub --header '{authorization}'",
    )
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")
    return read_only_settings_from_env()


def _context_with_tag(value: str):
    return build_agent_data_context(
        source_snapshot_sha256="0" * 64,
        catalog_version="digest-authorization-tests-v1",
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


def test_guard_rejects_digest_response_after_comma(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(
        monkeypatch,
        authorization='Authorization: Digest username="u", response="q7"',
    )
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag("classification:prefix-q7-suffix")) is False


def test_guard_rejects_digest_response_after_quoted_comma(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(
        monkeypatch,
        authorization='Authorization: Digest realm="a,b", response="q7"',
    )
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag("classification:prefix-q7-suffix")) is False


def test_guard_keeps_short_descriptive_digest_parameters_exact_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(
        monkeypatch,
        authorization='Authorization: Digest username="u", response="q7"',
    )
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag("classification:unrelated-value")) is True
    assert guard.context_is_safe(_context_with_tag("classification:digest-metadata")) is True
    assert guard.context_is_safe(_context_with_tag("u")) is False


def test_guard_rejects_exact_descriptive_digest_value_without_broad_substring_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(
        monkeypatch,
        authorization='Authorization: Digest realm="a,b", response="q7"',
    )
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag("a,b")) is False
    assert guard.context_is_safe(_context_with_tag("classification:a,b:metadata")) is True
