"""Produce sanitized exact-source live Agent/DataHub discovery evidence."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from toxicjoin.agent import DataHubAgentDiscoverer
from toxicjoin.context import DataHubAssetMap
from toxicjoin.integrations.datahub_authority import (
    DataHubMcpRole,
    read_only_settings_from_env,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _hash(value: dict[str, Any]) -> str:
    payload = {key: item for key, item in value.items() if key != "report_sha256"}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _write(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    temp: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as handle:
            temp = Path(handle.name)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        temp = None
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


async def _discover(asset_map_path: str) -> tuple[Any, DataHubAssetMap]:
    settings = read_only_settings_from_env()
    if settings.role != DataHubMcpRole.READ_ONLY or settings.mutation_enabled:
        raise RuntimeError("Agent discovery did not acquire read-only settings")
    child = settings.child_environment()
    if child.get("TOOLS_IS_MUTATION_ENABLED") != "false":
        raise RuntimeError("Agent discovery child enabled mutations")
    if child.get("SAVE_DOCUMENT_TOOL_ENABLED") != "false":
        raise RuntimeError("Agent discovery child enabled save_document")
    asset_map = DataHubAssetMap.from_path(asset_map_path)
    context = await DataHubAgentDiscoverer(
        settings=settings,
        asset_map=asset_map,
    ).discover()
    return context, asset_map


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--asset-map", default="config/datahub-assets.json")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    context, asset_map = asyncio.run(_discover(args.asset_map))
    if context.security_authoritative is not False or context.source != "DATAHUB":
        raise RuntimeError("Agent discovery returned an invalid authority state")
    if tuple(dataset.logical_name for dataset in context.datasets) != tuple(
        sorted(asset_map.datasets)
    ):
        raise RuntimeError("Agent discovery dataset inventory mismatch")

    tags = tuple(
        sorted(
            {
                tag
                for dataset in context.datasets
                for field in dataset.fields
                for tag in field.tags
            }
        )
    )
    terms = tuple(
        sorted(
            {
                term
                for dataset in context.datasets
                for field in dataset.fields
                for term in field.glossary_terms
            }
        )
    )
    if not tags or not terms:
        raise RuntimeError("Agent discovery did not retain tags and glossary terms")

    serialized = context.model_dump_json()
    forbidden = (
        os.environ.get("DATAHUB_GMS_READ_TOKEN", ""),
        os.environ.get("DATAHUB_GMS_WRITE_TOKEN", ""),
        os.environ.get("DATAHUB_GMS_TOKEN", ""),
        os.environ.get("DATAHUB_GMS_URL", ""),
        "save_document",
        "TOOLS_IS_MUTATION_ENABLED",
        "SAVE_DOCUMENT_TOOL_ENABLED",
    )
    if any(value and value in serialized for value in forbidden):
        raise RuntimeError("Agent discovery reflected protected launch material")

    report: dict[str, Any] = {
        "schema_version": "1.1",
        "status": "verified",
        "created_at": _now(),
        "source": context.source,
        "security_authoritative": context.security_authoritative,
        "source_snapshot_sha256": context.source_snapshot_sha256,
        "context_sha256": context.context_sha256,
        "catalog_version": context.catalog_version,
        "dataset_count": len(context.datasets),
        "field_count": sum(len(dataset.fields) for dataset in context.datasets),
        "lineage_edge_count": sum(
            len(field.lineage)
            for dataset in context.datasets
            for field in dataset.fields
        ),
        "tag_label_count": len(tags),
        "tag_labels": list(tags),
        "glossary_term_label_count": len(terms),
        "glossary_term_labels": list(terms),
        "dedicated_read_role": True,
        "mutation_tools_exposed_to_agent": False,
        "report_sha256": "0" * 64,
    }
    report["report_sha256"] = _hash(report)
    _write(Path(args.output), report)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
