"""Executable DataHub MCP read-only → isolated writer → read-only verification."""

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
from toxicjoin.integrations.datahub_authority import (
    DataHubMcpRole,
    RoleBoundDataHubMcpClient,
    mutation_settings_from_env,
    read_only_settings_from_env,
    writer_allowlisted_transport,
)
from toxicjoin.integrations.datahub_mcp import (
    DataHubMcpError,
    DataHubMcpSettings,
    DataHubMcpTransport,
    StdioDataHubMcpTransport,
)
from toxicjoin.models import SensitivityCategory, StrictModel


TransportFactory = Callable[[DataHubMcpSettings], DataHubMcpTransport]


class DataHubSpikeReport(StrictModel):
    schema_version: str = "1.3"
    created_at: datetime
    status: str = Field(pattern=r"^verified$")
    read_settings: dict[str, Any]
    write_settings: dict[str, Any]
    read_discovered_tools: tuple[str, ...]
    write_server_discovered_tools: tuple[str, ...]
    write_discovered_tools: tuple[str, ...]
    readback_discovered_tools: tuple[str, ...]
    verified_entities: tuple[str, ...]
    field_counts: dict[str, int]
    lineage_relationship_count: int = Field(ge=1)
    lineage_bound_field_count: int = Field(ge=1)
    lineage_source_count: int = Field(ge=1)
    flagship_lineage_source_keys: tuple[str, ...]
    flagship_lineage_categories: tuple[SensitivityCategory, ...]
    unclassified_lineage_source_count: int = Field(ge=0)
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
    read_settings: DataHubMcpSettings,
    write_settings: DataHubMcpSettings,
    asset_map: DataHubAssetMap,
    output: str | Path,
    external_url: str | None = None,
    transport_factory: TransportFactory = StdioDataHubMcpTransport,
) -> DataHubSpikeReport:
    """Run a role-separated live verification and persist sanitized evidence."""

    if read_settings.mutation_enabled:
        raise DataHubMcpError("read DataHub MCP settings must disable mutations")
    if not write_settings.mutation_enabled:
        raise DataHubMcpError("write DataHub MCP settings must enable the isolated writer role")

    marker = f"TOXICJOIN_MCP_{uuid4().hex}"
    created_at = datetime.now(timezone.utc)

    # Context acquisition has no mutation capability. This snapshot is the only source
    # of governed read evidence used to prepare the write-back payload.
    async with transport_factory(read_settings) as read_transport:
        read_client = RoleBoundDataHubMcpClient(
            read_transport,
            role=DataHubMcpRole.READ_ONLY,
        )
        snapshot = await DataHubSnapshotLoader(
            read_client,
            asset_map,
        ).load(require_mutations=False)

    lineage_bound_fields = [
        (logical_name, field_path, field)
        for logical_name, dataset in snapshot.catalog.datasets.items()
        for field_path, field in dataset.fields.items()
        if field.lineage_sources
    ]
    lineage_sources = [
        source
        for _, _, field in lineage_bound_fields
        for source in field.lineage_sources
    ]
    unclassified_lineage_sources = [
        source
        for source in lineage_sources
        if source.category == SensitivityCategory.UNCLASSIFIED
    ]
    if unclassified_lineage_sources:
        raise DataHubMcpError(
            "live DataHub snapshot contains unclassified or incomplete upstream lineage"
        )

    flagship_sources = ()
    if asset_map.flagship_column is not None:
        flagship_dataset = snapshot.catalog.datasets[asset_map.flagship_dataset]
        flagship_field = flagship_dataset.fields.get(asset_map.flagship_column)
        if flagship_field is None:
            raise DataHubMcpError("configured flagship lineage field is missing")
        flagship_sources = flagship_field.lineage_sources
    if not flagship_sources:
        raise DataHubMcpError("configured flagship field has no governed upstream lineage")

    # mcp-server-datahub 0.6.x requires its general mutation registration path before
    # save_document exists. Keep that child isolated and put a mandatory transport
    # allowlist in front of it. The raw server inventory is retained in the report so
    # evidence never hides the broader upstream registration.
    async with transport_factory(write_settings) as raw_write_transport:
        write_transport = writer_allowlisted_transport(raw_write_transport)
        write_client = RoleBoundDataHubMcpClient(
            write_transport,
            role=DataHubMcpRole.MUTATION,
        )
        write_definitions = await write_client.discover_and_validate(
            require_mutations=True
        )
        write_server_discovered_tools = write_transport.raw_tool_names
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
                lineage_bound_field_count=len(lineage_bound_fields),
                lineage_source_count=len(lineage_sources),
            ),
            related_assets=snapshot.verified_entities,
            external_url=external_url,
        )

    # A third, fresh read-only stdio process proves persistence without trusting the
    # writer session's response or in-memory state.
    async with transport_factory(read_settings) as readback_transport:
        readback_client = RoleBoundDataHubMcpClient(
            readback_transport,
            role=DataHubMcpRole.READ_ONLY,
        )
        readback_definitions = await readback_client.discover_and_validate(
            require_mutations=False
        )
        await readback_client.verify_document_marker(document_urn, marker)

    payload: dict[str, Any] = {
        "schema_version": "1.3",
        "created_at": created_at,
        "status": "verified",
        "read_settings": read_settings.redacted_summary(),
        "write_settings": write_settings.redacted_summary(),
        "read_discovered_tools": snapshot.discovered_tools,
        "write_server_discovered_tools": write_server_discovered_tools,
        "write_discovered_tools": tuple(
            sorted(definition.name for definition in write_definitions)
        ),
        "readback_discovered_tools": tuple(
            sorted(definition.name for definition in readback_definitions)
        ),
        "verified_entities": snapshot.verified_entities,
        "field_counts": snapshot.field_counts,
        "lineage_relationship_count": len(
            snapshot.lineage_sample.get("relationships", [])
        ),
        "lineage_bound_field_count": len(lineage_bound_fields),
        "lineage_source_count": len(lineage_sources),
        "flagship_lineage_source_keys": tuple(
            sorted(source.ref.key for source in flagship_sources)
        ),
        "flagship_lineage_categories": tuple(
            sorted(
                {source.category for source in flagship_sources},
                key=lambda category: category.value,
            )
        ),
        "unclassified_lineage_source_count": len(unclassified_lineage_sources),
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
    field_counts: dict[str, int],
    lineage_relationship_count: int,
    lineage_bound_field_count: int,
    lineage_source_count: int,
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
            "This Decision proves that ToxicJoin used a read-only DataHub MCP process ",
            "to acquire governed context, an isolated writer process behind a ",
            "save_document-only transport allowlist, and a fresh read-only process ",
            "to verify persisted content.",
            "",
            f"Configured assets verified: {entity_count}",
            f"Governed schema fields: {rendered_counts}",
            f"Lineage relationships observed: {lineage_relationship_count}",
            f"Fields with governed upstream lineage: {lineage_bound_field_count}",
            f"Governed upstream column sources: {lineage_source_count}",
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
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, dict):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_compatible(item) for item in value]
    if hasattr(value, "value") and isinstance(value.value, str):
        return value.value
    return value


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify role-separated ToxicJoin DataHub MCP read/write/read-back integration"
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
                read_settings=read_only_settings_from_env(),
                write_settings=mutation_settings_from_env(),
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
