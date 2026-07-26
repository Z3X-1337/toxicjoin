from __future__ import annotations

import pytest

from toxicjoin.agent.datahub_discovery import _AgentMetadataSecretGuard
from toxicjoin.agent.models import AgentDatasetView, AgentFieldView, build_agent_data_context
from toxicjoin.integrations.datahub_authority import read_only_settings_from_env
from toxicjoin.models import SensitivityCategory

DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,url_guard_fail_closed,PROD)"
_UNRELATED_TOKEN = "url-guard-unrelated-read-token"


def _settings(
    monkeypatch: pytest.MonkeyPatch,
    *,
    endpoint: str,
):
    monkeypatch.setenv("DATAHUB_GMS_URL", endpoint)
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", _UNRELATED_TOKEN)
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv("DATAHUB_MCP_ARGS", "mcp-server-datahub")
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")
    return read_only_settings_from_env()


def _context_with_tag(value: str):
    return build_agent_data_context(
        source_snapshot_sha256="0" * 64,
        catalog_version="url-guard-fail-closed-v1",
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


def test_non_sensitive_parameter_value_still_exposes_embedded_marked_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(
        monkeypatch,
        endpoint="https://example.test/api?mode=prod;access_token=q7",
    )
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag("classification:prefix-q7-suffix")) is False


def test_non_sensitive_parameter_does_not_promote_ordinary_short_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = _settings(
        monkeypatch,
        endpoint="https://example.test/api?mode=prod;label=q7",
    )
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag("classification:prefix-q7-suffix")) is True


def test_malformed_url_preserves_and_scans_explicit_marked_secret(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    malformed = "https://[access_token=q7"
    settings = _settings(monkeypatch, endpoint=malformed)
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag("classification:prefix-q7-suffix")) is False
    assert guard.context_is_safe(_context_with_tag(malformed)) is False


def test_malformed_nonsecret_url_does_not_create_broad_short_secret_pattern(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    malformed = "https://[mode=q7"
    settings = _settings(monkeypatch, endpoint=malformed)
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag("classification:prefix-q7-suffix")) is True
    assert guard.context_is_safe(_context_with_tag(malformed)) is False


def test_malformed_url_preserves_exact_child_visible_whitespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    malformed = "https://[mode=q7 "
    settings = _settings(monkeypatch, endpoint=malformed)
    guard = _AgentMetadataSecretGuard.from_runtime_settings(settings)

    assert guard.context_is_safe(_context_with_tag(malformed)) is False
