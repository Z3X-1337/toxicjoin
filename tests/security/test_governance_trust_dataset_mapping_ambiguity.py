from __future__ import annotations

from types import SimpleNamespace

import pytest

from toxicjoin.agent.governance_trust import (
    GovernanceTrustBindingError,
    _required_governance_facts,
)


def test_source_dataset_mapping_candidates_must_be_unique() -> None:
    evaluation = SimpleNamespace(
        evidence_bundle=SimpleNamespace(
            source_identity="datahub-mcp:test-source",
            catalog_version="datahub-mcp:test-v1",
            claims=(
                SimpleNamespace(
                    subject="urn:li:dataset:(urn:li:dataPlatform:duckdb,patients_a,PROD)",
                    predicate="datahub.logical_name",
                    value="patients",
                ),
                SimpleNamespace(
                    subject="urn:li:dataset:(urn:li:dataPlatform:duckdb,patients_b,PROD)",
                    predicate="datahub.logical_name",
                    value="patients",
                ),
            ),
        ),
        source_snapshot_sha256="1" * 64,
        query_plan=SimpleNamespace(source_datasets=("patients",)),
        resolution=SimpleNamespace(projected_context=(), all_referenced_context=()),
    )

    with pytest.raises(
        GovernanceTrustBindingError,
        match="GOVERNANCE_TRUST_DATASET_MAPPING_AMBIGUOUS",
    ):
        _required_governance_facts(evaluation)
