#!/usr/bin/env python3
"""Observe official DataHub MCP metadata before evaluating frozen external expectations.

This is a research diagnostic, not a relaxed verifier. It writes what the MCP server
actually exposes (schema metadata and lineage identifiers only) before checking the
preregistered expectations. No warehouse rows are queried or retained.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from toxicjoin.context.datahub import (
    DataHubAssetMap,
    DataHubSnapshotLoader,
    _extract_entity_urn,
    _extract_glossary_names,
    _extract_tag_names,
    _field_path,
    _normalize_field,
)
from toxicjoin.integrations.datahub_mcp import (
    DataHubMcpClient,
    DataHubMcpSettings,
    StdioDataHubMcpTransport,
)

EXPECTED_CATEGORY_COUNTS = {
    "DIRECT_IDENTIFIER": 5,
    "STABLE_PSEUDONYM": 5,
    "QUASI_IDENTIFIER": 3,
    "SENSITIVE_ATTRIBUTE": 44,
    "PUBLIC_OR_LOW_RISK": 2,
}
EXPECTED_ENTITY_COUNT = 5
EXPECTED_FIELD_COUNT = 59


def _canonical_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        {key: value for key, value in payload.items() if key != "report_sha256"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _write_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload["report_sha256"] = _canonical_hash(payload)
    content = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(content, encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _safe_lineage(value: Any, *, key: str | None = None) -> Any:
    """Retain identifiers/structure useful for lineage diagnosis, never data rows."""

    allowed_scalar_keys = {
        "urn",
        "sourceurn",
        "destinationurn",
        "upstreamurn",
        "downstreamurn",
        "entityurn",
        "fieldpath",
        "sourcefield",
        "destinationfield",
        "upstreamfield",
        "downstreamfield",
        "column",
        "type",
        "relationshiptype",
        "degree",
        "hop",
        "hops",
        "direction",
    }
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for child_key, child_value in value.items():
            normalized_key = "".join(ch for ch in str(child_key).lower() if ch.isalnum())
            if isinstance(child_value, (dict, list, tuple)):
                sanitized = _safe_lineage(child_value, key=str(child_key))
                if sanitized not in ({}, [], None):
                    result[str(child_key)] = sanitized
            elif normalized_key in allowed_scalar_keys or (
                isinstance(child_value, str) and child_value.startswith("urn:li:")
            ):
                result[str(child_key)] = child_value
        return result
    if isinstance(value, (list, tuple)):
        return [_safe_lineage(item, key=key) for item in value]
    if isinstance(value, str) and value.startswith("urn:li:"):
        return value
    return None


async def _observe(
    *,
    asset_map_path: Path,
    warehouse_profile_path: Path,
    output: Path,
) -> int:
    asset_map = DataHubAssetMap.from_path(asset_map_path)
    warehouse_profile = json.loads(warehouse_profile_path.read_text(encoding="utf-8"))

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "experiment": "external-validation-01-datahub-mcp-observation",
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "warehouse_profile_sha256": warehouse_profile.get("warehouse_profile_sha256"),
        "expected": {
            "entity_count": EXPECTED_ENTITY_COUNT,
            "field_count": EXPECTED_FIELD_COUNT,
            "category_counts": EXPECTED_CATEGORY_COUNTS,
            "unclassified_count": 0,
            "raw_upstream_lineage_required": True,
        },
        "observed": {
            "discovered_tools": [],
            "entities": [],
            "datasets": {},
            "category_counts": {},
            "lineage": None,
            "lineage_relationship_count": None,
            "raw_upstream_lineage_observed": False,
        },
        "manual_observation_error": None,
        "snapshot_loader": {"passed": False, "error": None},
        "expectation_failures": [],
        "contains_patient_rows": False,
        "report_sha256": "",
    }

    settings = DataHubMcpSettings.from_env()
    categories: Counter[str] = Counter()

    try:
        async with StdioDataHubMcpTransport(settings) as transport:
            client = DataHubMcpClient(transport)
            definitions = await client.discover_and_validate(require_mutations=False)
            payload["observed"]["discovered_tools"] = sorted(
                definition.name for definition in definitions
            )

            entities = await client.get_entities(tuple(asset_map.datasets.values()))
            observed_entities = sorted(
                urn
                for entity in entities
                if (urn := _extract_entity_urn(entity)) is not None
            )
            payload["observed"]["entities"] = observed_entities

            for logical_name, urn in asset_map.datasets.items():
                fields = await client.list_schema_fields(urn)
                safe_fields: list[dict[str, Any]] = []
                for raw_field in fields:
                    field_record: dict[str, Any] = {
                        "field_path": None,
                        "tags": [],
                        "glossary_terms": [],
                        "normalized_category": None,
                        "normalization_error": None,
                    }
                    try:
                        field_record["field_path"] = _field_path(raw_field)
                    except Exception as exc:  # diagnostic captures exact adapter failure
                        field_record["normalization_error"] = (
                            f"{type(exc).__name__}: {exc}"
                        )
                        safe_fields.append(field_record)
                        continue

                    field_record["tags"] = list(_extract_tag_names(raw_field))
                    field_record["glossary_terms"] = list(
                        _extract_glossary_names(raw_field)
                    )
                    try:
                        normalized = _normalize_field(raw_field)
                        category = normalized.category.value
                        field_record["normalized_category"] = category
                        categories[category] += 1
                    except Exception as exc:
                        field_record["normalization_error"] = (
                            f"{type(exc).__name__}: {exc}"
                        )
                    safe_fields.append(field_record)

                payload["observed"]["datasets"][logical_name] = {
                    "urn": urn,
                    "field_count": len(fields),
                    "fields": sorted(
                        safe_fields,
                        key=lambda item: str(item.get("field_path") or ""),
                    ),
                }

            lineage = await client.get_lineage(
                asset_map.flagship_urn,
                column=asset_map.flagship_column,
                upstream=True,
                max_hops=2,
                max_results=100,
            )
            relationships = lineage.get("relationships")
            safe_lineage = _safe_lineage(lineage)
            payload["observed"]["lineage"] = safe_lineage
            payload["observed"]["lineage_relationship_count"] = (
                len(relationships) if isinstance(relationships, list) else None
            )
            payload["observed"]["raw_upstream_lineage_observed"] = (
                "raw_diabetic_data" in json.dumps(safe_lineage, sort_keys=True)
            )
    except Exception as exc:
        payload["manual_observation_error"] = f"{type(exc).__name__}: {exc}"

    payload["observed"]["category_counts"] = dict(sorted(categories.items()))

    # Exercise the production snapshot loader separately so its failure is preserved
    # independently from the manual observation above.
    try:
        async with StdioDataHubMcpTransport(settings) as transport:
            client = DataHubMcpClient(transport)
            snapshot = await DataHubSnapshotLoader(client, asset_map).load(
                require_mutations=False
            )
            payload["snapshot_loader"] = {
                "passed": True,
                "error": None,
                "verified_entity_count": len(snapshot.verified_entities),
                "field_counts": snapshot.field_counts,
                "lineage_relationship_count": len(
                    snapshot.lineage_sample.get("relationships", [])
                ),
            }
    except Exception as exc:
        payload["snapshot_loader"] = {
            "passed": False,
            "error": f"{type(exc).__name__}: {exc}",
        }

    failures: list[str] = []
    observed_entities = payload["observed"]["entities"]
    if len(observed_entities) != EXPECTED_ENTITY_COUNT:
        failures.append(
            f"entity_count:{len(observed_entities)}!={EXPECTED_ENTITY_COUNT}"
        )
    if set(observed_entities) != set(asset_map.datasets.values()):
        failures.append("entity_set_mismatch")

    observed_field_count = sum(
        int(dataset["field_count"])
        for dataset in payload["observed"]["datasets"].values()
    )
    payload["observed"]["field_count"] = observed_field_count
    if observed_field_count != EXPECTED_FIELD_COUNT:
        failures.append(
            f"field_count:{observed_field_count}!={EXPECTED_FIELD_COUNT}"
        )

    observed_categories = payload["observed"]["category_counts"]
    if observed_categories != EXPECTED_CATEGORY_COUNTS:
        failures.append("category_counts_mismatch")
    if observed_categories.get("UNCLASSIFIED", 0) != 0:
        failures.append("unclassified_fields_present")

    if not payload["observed"]["lineage_relationship_count"]:
        failures.append("lineage_relationships_empty_or_invalid")
    if not payload["observed"]["raw_upstream_lineage_observed"]:
        failures.append("raw_upstream_lineage_not_observed")
    if payload["manual_observation_error"] is not None:
        failures.append("manual_observation_error")
    if not payload["snapshot_loader"]["passed"]:
        failures.append("production_snapshot_loader_failed")

    payload["expectation_failures"] = failures
    payload["status"] = "verified" if not failures else "failed"
    _write_atomic(output, payload)

    print(
        json.dumps(
            {
                "status": payload["status"],
                "manual_observation_error": payload["manual_observation_error"],
                "snapshot_loader": payload["snapshot_loader"],
                "observed_entity_count": len(observed_entities),
                "observed_field_count": observed_field_count,
                "observed_category_counts": observed_categories,
                "lineage_relationship_count": payload["observed"][
                    "lineage_relationship_count"
                ],
                "raw_upstream_lineage_observed": payload["observed"][
                    "raw_upstream_lineage_observed"
                ],
                "expectation_failures": failures,
                "report_sha256": payload["report_sha256"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if not failures else 1


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--asset-map", required=True, type=Path)
    parser.add_argument("--warehouse-profile", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    raise SystemExit(
        asyncio.run(
            _observe(
                asset_map_path=args.asset_map.resolve(),
                warehouse_profile_path=args.warehouse_profile.resolve(),
                output=args.output.resolve(),
            )
        )
    )


if __name__ == "__main__":
    main()
