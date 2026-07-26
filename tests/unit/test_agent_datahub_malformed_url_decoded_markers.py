from __future__ import annotations

from toxicjoin.agent.datahub_discovery import (
    _AgentMetadataSecretGuard,
    _add_url_guard_values,
)
from toxicjoin.agent.models import AgentDatasetView, AgentFieldView, build_agent_data_context
from toxicjoin.models import SensitivityCategory

DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,malformed_url_markers,PROD)"


def _context_with_tag(value: str):
    return build_agent_data_context(
        source_snapshot_sha256="0" * 64,
        catalog_version="malformed-url-decoded-markers-v1",
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


def _guard_for_url(value: str) -> tuple[_AgentMetadataSecretGuard, set[str], set[str]]:
    values: set[str] = set()
    strong_secret_values: set[str] = set()
    _add_url_guard_values(
        values,
        value,
        strong_secret_values=strong_secret_values,
    )
    return (
        _AgentMetadataSecretGuard(
            values,
            strong_secret_values=strong_secret_values,
        ),
        values,
        strong_secret_values,
    )


def test_malformed_url_scans_percent_decoded_secret_marker() -> None:
    malformed = "https://[mode=prod;%61ccess_token=q7"
    guard, values, strong = _guard_for_url(malformed)

    assert malformed in values
    assert "q7" in strong
    assert guard.context_is_safe(_context_with_tag("classification:prefix-q7-suffix")) is False


def test_malformed_url_scans_selectively_encoded_secret_marker() -> None:
    malformed = "https://[mode=prod;%61ccess_%74oken=q7"
    guard, _, strong = _guard_for_url(malformed)

    assert "q7" in strong
    assert guard.context_is_safe(_context_with_tag("classification:prefix-q7-suffix")) is False


def test_malformed_encoded_nonsecret_name_does_not_promote_short_value() -> None:
    malformed = "https://[mode=prod;%6cabel=q7"
    guard, values, strong = _guard_for_url(malformed)

    assert malformed in values
    assert "q7" not in strong
    assert guard.context_is_safe(_context_with_tag(malformed)) is False
    assert guard.context_is_safe(_context_with_tag("classification:prefix-q7-suffix")) is True


def test_decoded_url_shaped_marked_secret_scan_terminates_and_protects_inner_secret() -> None:
    malformed = "https://[mode=prod;%61ccess_token=https://[token=q7"
    guard, _, strong = _guard_for_url(malformed)

    # Construction completing without RecursionError is part of this regression. The decoded
    # outer access_token value is URL-shaped, and its nested marked credential must still be bound.
    assert "https://[token=q7" in strong
    assert "q7" in strong
    assert guard.context_is_safe(_context_with_tag("classification:prefix-q7-suffix")) is False
