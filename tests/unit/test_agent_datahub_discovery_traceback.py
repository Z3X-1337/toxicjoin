from __future__ import annotations

import asyncio
import traceback
from datetime import datetime, timezone

import pytest
from pydantic import SecretStr

from toxicjoin.agent import (
    AgentDataHubDiscoveryError,
    DataHubAgentDiscoverer,
    build_agent_data_context_from_snapshot,
)
from toxicjoin.context.datahub import DataHubAssetMap, DataHubSnapshot
from toxicjoin.context.fixture import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.integrations.datahub_authority import ReadOnlyDataHubMcpSettings
from toxicjoin.models import SensitivityCategory

PATIENTS_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,patients,PROD)"
_SECRET = "agent-discovery-secret-token"
_ENDPOINT = "https://datahub.example"


class LeakingTransport:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        return None

    async def list_tools(self):
        raise RuntimeError(f"transport leaked {_SECRET} {_ENDPOINT}")

    async def call_tool(self, name: str, arguments: dict):
        raise AssertionError("call_tool must not be reached after list_tools failure")


class NonSerializableMetadata:
    def __repr__(self) -> str:
        return f"NonSerializableMetadata({_SECRET!r}, {_ENDPOINT!r})"


def _read_settings() -> ReadOnlyDataHubMcpSettings:
    return ReadOnlyDataHubMcpSettings(
        gms_url=_ENDPOINT,
        gms_token=SecretStr(_SECRET),
        command="uvx",
        args=("mcp-server-datahub",),
        timeout_seconds=30,
    )


def _render_exception(exc: BaseException) -> str:
    return "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))


def test_discovery_suppresses_sensitive_transport_exception_chain() -> None:
    asset_map = DataHubAssetMap(
        version="traceback-redaction-v1",
        datasets={"patients": PATIENTS_URN},
        flagship_dataset="patients",
        flagship_column="customer_id",
    )

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        asyncio.run(
            DataHubAgentDiscoverer(
                settings=_read_settings(),
                asset_map=asset_map,
                transport_factory=lambda _: LeakingTransport(),
            ).discover()
        )

    assert exc_info.value.code == "AGENT_DATAHUB_DISCOVERY_FAILED"
    rendered = _render_exception(exc_info.value)
    assert _SECRET not in rendered
    assert _ENDPOINT not in rendered
    assert "transport leaked" not in rendered
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__suppress_context__ is True


def test_snapshot_serialization_failure_does_not_echo_raw_metadata() -> None:
    snapshot = DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:serialization-redaction",
            datasets={
                "patients": FixtureDataset(
                    urn=PATIENTS_URN,
                    fields={
                        "customer_id": FixtureField(
                            category=SensitivityCategory.STABLE_PSEUDONYM,
                        )
                    },
                )
            },
        ),
        verified_entities=(PATIENTS_URN,),
        field_counts={"patients": 1},
        lineage_sample={
            "relationships": [],
            "opaque": NonSerializableMetadata(),
        },
        discovered_tools=("get_entities", "get_lineage", "list_schema_fields"),
        observed_at=datetime(2026, 7, 25, 14, 0, tzinfo=timezone.utc),
    )

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        build_agent_data_context_from_snapshot(snapshot)

    assert exc_info.value.code == "AGENT_DATAHUB_SNAPSHOT_INVALID"
    rendered = _render_exception(exc_info.value)
    assert _SECRET not in rendered
    assert _ENDPOINT not in rendered
    assert "NonSerializableMetadata" not in rendered
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__suppress_context__ is True


def test_projection_validation_failure_does_not_echo_raw_metadata() -> None:
    leaking_owner = "urn:li:corpuser:" + _SECRET + _ENDPOINT + ("x" * 3000)
    snapshot = DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:projection-redaction",
            datasets={
                "patients": FixtureDataset(
                    urn=PATIENTS_URN,
                    owner=leaking_owner,
                    fields={
                        "customer_id": FixtureField(
                            category=SensitivityCategory.STABLE_PSEUDONYM,
                        )
                    },
                )
            },
        ),
        verified_entities=(PATIENTS_URN,),
        field_counts={"patients": 1},
        lineage_sample={"relationships": []},
        discovered_tools=("get_entities", "get_lineage", "list_schema_fields"),
        observed_at=datetime(2026, 7, 25, 14, 0, tzinfo=timezone.utc),
    )

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        build_agent_data_context_from_snapshot(snapshot)

    assert exc_info.value.code == "AGENT_DATAHUB_PROJECTION_FAILED"
    rendered = _render_exception(exc_info.value)
    assert _SECRET not in rendered
    assert _ENDPOINT not in rendered
    assert "corpuser" not in rendered
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__suppress_context__ is True
