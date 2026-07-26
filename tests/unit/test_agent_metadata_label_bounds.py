from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from toxicjoin.agent import AgentDataHubDiscoveryError, build_agent_data_context_from_snapshot
from toxicjoin.agent.models import AgentFieldView
from toxicjoin.context.datahub import DataHubSnapshot
from toxicjoin.context.fixture import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.models import SensitivityCategory


DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,metadata_label_bounds,PROD)"
OBSERVED_AT = datetime(2026, 7, 26, 2, 20, tzinfo=timezone.utc)
MAX_LABEL_LENGTH = 512


@pytest.mark.parametrize("field_name", ("tags", "glossary_terms"))
def test_agent_field_view_bounds_each_metadata_label(field_name: str) -> None:
    values = {field_name: ("x" * (MAX_LABEL_LENGTH + 1),)}

    with pytest.raises(ValidationError):
        AgentFieldView(
            field_path="customer_id",
            category=SensitivityCategory.STABLE_PSEUDONYM,
            **values,
        )


@pytest.mark.parametrize("field_name", ("tags", "glossary_terms"))
def test_snapshot_projection_fails_closed_on_oversized_metadata_label(field_name: str) -> None:
    field_kwargs = {field_name: ("x" * (MAX_LABEL_LENGTH + 1),)}
    snapshot = DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:metadata-label-bounds-v1",
            datasets={
                "patients": FixtureDataset(
                    urn=DATASET_URN,
                    fields={
                        "customer_id": FixtureField(
                            category=SensitivityCategory.STABLE_PSEUDONYM,
                            **field_kwargs,
                        )
                    },
                )
            },
        ),
        verified_entities=(DATASET_URN,),
        field_counts={"patients": 1},
        lineage_sample={"relationships": []},
        discovered_tools=("get_entities", "get_lineage", "list_schema_fields"),
        observed_at=OBSERVED_AT,
    )

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        build_agent_data_context_from_snapshot(snapshot)

    assert exc_info.value.code == "AGENT_DATAHUB_PROJECTION_FAILED"
