"""Executable DataHub MCP read → write → independent read-back verification."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
import tempfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import Field, field_validator

from toxicjoin.context.datahub import DataHubAssetMap, DataHubSnapshotLoader
from toxicjoin.integrations.datahub_mcp import (
    DataHubMcpClient,
    DataHubMcpError,
    DataHubMcpSettings,
    DataHubMcpTransport,
    StdioDataHubMcpTransport,
)
from toxicjoin.models import StrictModel


TransportFactory = Callable[[DataHubMcpSettings], DataHubMcpTransport]


class DataHubSpikeReport(StrictModel):
    schema_version: str = "1.0"
    created_at: datetime
    status: str = Field(pattern=r"^verified$")
    settings: dict[str, Any]
    discovered_tools: tuple[str, ...]
    verified_entities: tuple[str, ...]
    field_counts: dict[str, int]
    lineage_relationship_count: int = Field(ge=0)
    decision_document_urn: str = Field(pattern=r"^urn:li:document:")
    verification_marker: str = Field(pattern=r"^TOXICJOIN_MCP_[0-9a-f]{32}$")
    marker_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    independent_readback_verified: bool
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("created_at")
    @classmethod
    def normalize_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        return value.astimezone(timezone.utc)


async def run_datahub_spike(
    *,
    settings: DataHubMcpSettings,
    asset_map: DataHubAssetMap,
    output: str | Path,
    external_url: str | None = None,
    transport_factory: TransportFactory = StdioDataHubMcpTransport,
) -> DataHubSpikeReport:
    """Run the live verification and persist a sanitized evidence report."""

    marker = f"TOXICJOIN_MCP_{uuid4().hex}"
    created_at = datetime.now(timezone.utc)

    async with transport_factory(settings) as write_transport:
        write_client = DataHubMcpClient(write_transport)
        snapshot = await DataHubSnapshotLoader(
            write_client,
            asset_map,
        ).load(require_mutations=True)
        document_urn = await write_client.save_decision(
            title="ToxicJoin MCP integration verification",
            content=_decision_content(
                marker=marker,
                created_at=created_at,
                entity_count=len(snapshot.verified_entities),
                field_counts=snapshot.field_counts,
                lineage_relationship_count=len(
                    snapshot.lineage_sample.get("relationships", [])
                ),
            ),
            related_assets=snapshot.verified_entities,
            external_url=external_url,
        )

    # A fresh stdio process and MCP session is intentional. Read-back cannot rely on
    # the session that performed the write or on an in-memory response object.
    async with transport_factory(settings) as read_transport:
        read_client = DataHubMcpClient(read_transport)
        await read_client.discover_and_validate(require_mutations=False)
        await read_client.verify_document_marker(document_urn, marker)

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "created_at": created_at,
        "status": "verified",
        "settings": settings.redacted_summary(),
        "discovered_tools": snapshot.discovered_tools,
        "verified_entities": snapshot.verified_entities,
        "field_counts": snapshot.field_counts,
        "lineage_relationship_count": len(
            snapshot.lineage_sample.get("relationships", [])
        ),
        "decision_document_urn": document_urn,
        "verification_marker": marker,
        "marker_sha256": hashlib.sha256(marker.encode("utf-8")).hexdigest(),
        "independent_readback_verified": True,
        "report_sha256": "0" * 64,
    }
    payload["report_sha256"] = _report_hash(payload)
    report = DataHubSpikeReport.model_validate(payload)
    _write_report_atomic(Path(output), report)
    return report


def _decision_content(
    *,
    marker: str,
    created_at: datetime,
    entity_count: int,
    field_counts purge? : dict[str, int],
    lineage_relationship_count: int,
) -> str:
    rendered_counts = ", ".join(
        f"{name}={count}" for name, count in sorted(field_counts.items())
    )
    return "\n".join(
        (
            "# ToxicJoin MCP integration verification",
            "",
            f"Verification marker: `{marker}`",
            f"Verified at: {created_at.astimezone(timezone.utc).isoformat()}",
            "",
            "This Decision proves that ToxicJoin used the official DataHub MCP server",
            "to read configured assets and governed schema metadata, inspect lineage,",
            "write a Decision document, and independently read it back from a fresh",
            "MCP session.",
            "",
            f"Configured assets verified: {entity_count}",
            f"Governed schema fields: {rendered_counts}",
            f"Lineage relationships observed: {lineage_relationship_count}",
            "",
            "No raw warehouse rows or authentication secrets are included.",
        )
    )


def _report_hash(payload: dict[str, Any]) -> str:
    canonical_payload = {
        key: _json_compatible(value)
        for key, value in payload.items()
        if key != "report_sha256"
    }
    canonical = json.dumps(
        canonical_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _write_report_atomic(path: Path, report: DataHubSpikeReport) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (
        json.dumps(
            report.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")

    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        temp_path = None
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def _json_compatible(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, dict):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_compatible(item) for item in value]
    return value


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify ToxicJoin DataHub MCP read/write/read-back integration"
    )
    parser.add_argument(
        "--asset-map",
        default="config/datahub-assets.json",
        help="Logical dataset to DataHub URN manifest",
    )
    parser.add_argument(
        "--output",
        default=".toxicjoin/datahub-spike.json",
        help="Sanitized JSON evidence report",
    )
    parser.add_argument(
        "--external-url",
        default=None,
        help="Optional public receipt or project URL stored on the Decision document",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="Required explicit acknowledgement that a live write will be performed",
    )
    args = parser.parse_args()

    if not args.verify:
        parser.error("--verify is required because this command writes a DataHub Decision")

    try:
        report = asyncio.run(
            run_datahub_spike(
                settings=DataHubMcpSettings.from_env(),
                asset_map=DataHubAssetMap.from_path(args.asset_map),
                output=args.output,
                external_url=args.external_url,
            )
        )
    except (DataHubMcpError, ValueError, OSError) as exc:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "error_type": type(exc).__name__,
                    "detail": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        raise SystemExit(1) from exc

    print(report.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
