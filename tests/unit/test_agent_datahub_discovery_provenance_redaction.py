from __future__ import annotations

import traceback

import pytest
from pydantic import BaseModel

from toxicjoin.agent import AgentDataHubDiscoveryError, DataHubAgentDiscoverer
from toxicjoin.context.datahub import DataHubAssetMap
from toxicjoin.integrations.datahub_authority import (
    ReadOnlyDataHubMcpSettings,
    read_only_settings_from_env,
)

PATIENTS_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,patients,PROD)"
_SECRET = "provenance-redaction-secret"
_ENDPOINT = "https://provenance-redaction.example"


class ExplodingBearer:
    def get_secret_value(self) -> str:
        raise RuntimeError(f"malformed bearer leaked {_SECRET} {_ENDPOINT}")


def _asset_map() -> DataHubAssetMap:
    return DataHubAssetMap(
        version="agent-provenance-redaction-v1",
        datasets={"patients": PATIENTS_URN},
        flagship_dataset="patients",
        flagship_column="customer_id",
    )


def _discovery_frame_locals(exc: BaseException) -> str:
    rendered: list[str] = []
    cursor = exc.__traceback__
    while cursor is not None:
        frame = cursor.tb_frame
        if frame.f_globals.get("__name__") == "toxicjoin.agent.datahub_discovery":
            rendered.append(repr(frame.f_locals))
        cursor = cursor.tb_next
    return "\n".join(rendered)


def test_initial_provenance_failure_is_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("DATAHUB_GMS_URL", _ENDPOINT)
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", _SECRET)
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv("DATAHUB_MCP_ARGS", "mcp-server-datahub")
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")

    reader = read_only_settings_from_env()
    corrupted = BaseModel.model_copy(
        reader,
        update={"gms_token": ExplodingBearer()},
    )
    assert type(corrupted) is ReadOnlyDataHubMcpSettings

    def transport_must_not_be_created(_settings):
        raise AssertionError("invalid provenance must fail before transport creation")

    with pytest.raises(AgentDataHubDiscoveryError) as exc_info:
        DataHubAgentDiscoverer(
            settings=corrupted,  # type: ignore[arg-type]
            asset_map=_asset_map(),
            transport_factory=transport_must_not_be_created,
        )

    assert exc_info.value.code == "AGENT_DATAHUB_SETTINGS_INVALID"
    rendered = "".join(
        traceback.format_exception(
            type(exc_info.value),
            exc_info.value,
            exc_info.value.__traceback__,
        )
    )
    assert _SECRET not in rendered
    assert _ENDPOINT not in rendered
    assert "malformed bearer leaked" not in rendered
    assert "ExplodingBearer" not in rendered
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None
    assert exc_info.value.__suppress_context__ is True

    rendered_locals = _discovery_frame_locals(exc_info.value)
    assert _SECRET not in rendered_locals
    assert _ENDPOINT not in rendered_locals
    assert "ExplodingBearer" not in rendered_locals
    assert "malformed bearer leaked" not in rendered_locals
