from __future__ import annotations

from datetime import datetime, timezone

import pytest

from toxicjoin.agent import (
    AgentDataHubDiscoveryError,
    build_agent_data_context_from_snapshot,
)
from toxicjoin.context.datahub import DataHubSnapshot
from toxicjoin.context.fixture import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.models import ColumnRef, LineageSource, SensitivityCategory

PATIENTS_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,patients,PROD)"
RAW_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,raw_patients,PROD)"
OBSERVED_AT = datetime(2026, 7, 25, 14, 0, tzinfo=timezone.utc)


def _snapshot(*, dataset_urn: str = PATIENTS_URN, lineage_urn: str | None = None) -> DataHubSnapshot:
    lineage = ()
    if lineage_urn is not None:
        lineage = (
            LineageSource(
                ref=ColumnRef(dataset="raw_patients", field_path="customer_id"),
                category=SensitivityCategory.UNCLASSIFIED,
                datahub_urn=lineage_urn,
            ),
        )
    return DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:urn-validation",
            datasets={
                "patients": FixtureDataset(
                    urn=dataset_urn,
                    fields={
                        "customer_id": FixtureField(
                            category=SensitivityCategory.STABLE_PSEUDONYM,
                            lineage_sources=lineage,
                        )
                    },
                )
            },
        ),
        verified_entities=(dataset_urn,),
        field_counts={"patients": 1},
        lineage_sample={"relationships": []},
        discovered_tools=("get_entities", "get_lineage", "list_schema_fields"),
        observed_at=OBSERVED_AT,
    )


@pytest.mark.parametrize(
    "malformed",
    [
        "urn:li:dataset:",
        "urn:li:dataset:not-a-valid-dataset-urn",
        "urn:li:dataset:(urn:li:dataPlatform:duckdb,,PROD)",
        "urn:li:dataset:(urn:li:dataPlatform:,patients,PROD)",
        "urn:li:dataset:(urn:li:dataPlatform:duckdb,patients,)",
        "urn:li:dataset:(urn:li:dataPlatform:duckdb,patients PROD,PROD)",
        "urn:li:dataset:(urn:li:dataPlatform:duckdb,patients,PROD",
    ],
)
def test_dataset_identity_requires_canonical_datahub_urn(malformed: str) -> None:
    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        build_agent_data_context_from_snapshot(_snapshot(dataset_urn=malformed))
    assert exc_info.value.code == "AGENT_DATAHUB_DATASET_IDENTITY_INVALID"


@pytest.mark.parametrize(
    "malformed",
    [
        "urn:li:dataset:",
        "urn:li:dataset:not-a-valid-dataset-urn",
        "urn:li:dataset:(urn:li:dataPlatform:duckdb,,PROD)",
        "urn:li:dataset:(urn:li:dataPlatform:duckdb,raw patients,PROD)",
    ],
)
def test_lineage_identity_requires_canonical_datahub_urn(malformed: str) -> None:
    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        build_agent_data_context_from_snapshot(_snapshot(lineage_urn=malformed))
    assert exc_info.value.code == "AGENT_DATAHUB_LINEAGE_IDENTITY_INVALID"


def test_canonical_dataset_and_lineage_urns_are_accepted() -> None:
    context = build_agent_data_context_from_snapshot(
        _snapshot(dataset_urn=PATIENTS_URN, lineage_urn=RAW_URN)
    )
    assert context.datasets[0].dataset_urn == PATIENTS_URN
    assert context.datasets[0].fields[0].lineage[0].source_dataset_urn == RAW_URN
