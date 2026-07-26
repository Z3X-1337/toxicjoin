from __future__ import annotations

from toxicjoin.agent.datahub_discovery import (
    _AgentMetadataSecretGuard,
    _add_authorization_guard_values,
)
from toxicjoin.agent.models import AgentDatasetView, AgentFieldView, build_agent_data_context
from toxicjoin.models import SensitivityCategory

DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,authorization_fail_closed,PROD)"


def _context_with_tag(value: str):
    return build_agent_data_context(
        source_snapshot_sha256="0" * 64,
        catalog_version="authorization-fail-closed-v1",
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


def test_unmatched_quoted_authorization_credential_fails_closed() -> None:
    values: set[str] = set()
    strong_secret_values: set[str] = set()

    _add_authorization_guard_values(
        values,
        strong_secret_values,
        'Authorization: Bearer "abc; def',
    )

    assert "abc; def" in strong_secret_values
    assert "abc" not in strong_secret_values
    assert "bearer" not in {value.lower() for value in strong_secret_values}

    guard = _AgentMetadataSecretGuard(
        values,
        strong_secret_values=strong_secret_values,
    )
    assert (
        guard.context_is_safe(
            _context_with_tag("classification:prefix-abc; def-suffix")
        )
        is False
    )
    assert guard.context_is_safe(_context_with_tag("Bearer")) is True
