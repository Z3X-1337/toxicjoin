#!/usr/bin/env python3
"""Seed the preregistered external UCI warehouse into a real DataHub OSS instance.

This research-only seed derives schema from the actual DuckDB file and governance
classifications from the frozen stewardship map. It does not inspect ToxicJoin policy
outputs and does not modify warehouse rows.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import duckdb

DATASET_PREFIX = "toxicjoin.external.uci_diabetes"
DATASET_DOI = "10.24432/C5230J"
GOVERNED_TABLES = ("encounters", "diagnoses", "labs", "medications", "outcomes")
RAW_TABLE = "raw_diabetic_data"

CATEGORY_TAGS = {
    "DIRECT_IDENTIFIER": "toxicjoin:direct-identifier",
    "STABLE_PSEUDONYM": "toxicjoin:stable-pseudonym",
    "QUASI_IDENTIFIER": "toxicjoin:quasi-identifier",
    "SENSITIVE_ATTRIBUTE": "toxicjoin:sensitive-attribute",
    "PUBLIC_OR_LOW_RISK": "toxicjoin:public-or-low-risk",
}


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def table_schema(connection: duckdb.DuckDBPyConnection, table: str) -> list[tuple[str, str]]:
    rows = connection.execute(f'PRAGMA table_info("{table}")').fetchall()
    if not rows:
        raise ValueError(f"warehouse table missing or empty schema: {table}")
    return [(str(row[1]), str(row[2])) for row in rows]


def classify_table(
    stewardship: dict[str, Any],
    table: str,
    columns: list[tuple[str, str]],
) -> dict[str, str]:
    tables = stewardship.get("tables")
    if not isinstance(tables, dict) or table not in tables:
        raise ValueError(f"stewardship map missing table: {table}")
    spec = tables[table]
    if not isinstance(spec, dict):
        raise ValueError(f"invalid stewardship table spec: {table}")

    explicit = spec.get("fields", {})
    overrides = spec.get("overrides", {})
    default = spec.get("default_category")
    if not isinstance(explicit, dict) or not isinstance(overrides, dict):
        raise ValueError(f"invalid field mapping for table: {table}")

    categories: dict[str, str] = {}
    for field_name, _native_type in columns:
        category = explicit.get(field_name, overrides.get(field_name, default))
        if category not in CATEGORY_TAGS:
            raise ValueError(
                "field has no frozen recognized stewardship category: "
                f"{table}.{field_name} -> {category!r}"
            )
        categories[field_name] = str(category)

    unexpected_explicit = sorted(set(explicit) - set(categories))
    unexpected_overrides = sorted(set(overrides) - set(categories))
    if unexpected_explicit or unexpected_overrides:
        raise ValueError(
            f"stewardship map references absent fields for {table}: "
            f"{unexpected_explicit + unexpected_overrides}"
        )
    return categories


def report_hash(payload: dict[str, Any]) -> str:
    canonical = json.dumps(
        {k: v for k, v in payload.items() if k != "report_sha256"},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def write_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8")
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


def seed(
    *,
    database: Path,
    stewardship_path: Path,
    warehouse_profile_path: Path,
    report_path: Path,
    asset_map_path: Path,
) -> dict[str, Any]:
    try:
        from datahub.metadata.urns import DatasetUrn, TagUrn
        from datahub.sdk import DataHubClient, Dataset
        from datahub.sdk.tag import Tag
    except ImportError as exc:
        raise RuntimeError("install ToxicJoin with the [datahub] extra") from exc

    stewardship = load_json(stewardship_path)
    warehouse_profile = load_json(warehouse_profile_path)
    if stewardship.get("frozen_before_measured_policy_run") is not True:
        raise ValueError("stewardship map is not marked frozen")
    if warehouse_profile.get("rows_filtered") != 0:
        raise ValueError("external warehouse unexpectedly filtered rows")
    if warehouse_profile.get("rows_synthesized") != 0:
        raise ValueError("external warehouse unexpectedly synthesized rows")

    connection = duckdb.connect(str(database), read_only=True)
    try:
        schemas = {
            table: table_schema(connection, table)
            for table in (RAW_TABLE, *GOVERNED_TABLES)
        }
    finally:
        connection.close()

    classifications = {
        table: classify_table(stewardship, table, schemas[table])
        for table in GOVERNED_TABLES
    }

    client = DataHubClient.from_env()

    all_tag_names = {
        "toxicjoin:external-validation",
        "toxicjoin:external-source-raw",
        *CATEGORY_TAGS.values(),
    }
    for tag_name in sorted(all_tag_names):
        client.entities.upsert(
            Tag(
                name=tag_name,
                display_name=tag_name,
                description=(
                    "ToxicJoin external-validation governance tag. "
                    "Field sensitivity assignments are frozen in "
                    "research/external_validation/stewardship-map.json."
                ),
            )
        )

    dataset_urns: dict[str, Any] = {}

    raw_name = f"{DATASET_PREFIX}.{RAW_TABLE}"
    raw_dataset = Dataset(
        platform="duckdb",
        name=raw_name,
        env="PROD",
        display_name="UCI Diabetes raw source",
        description=(
            "Raw external UCI Diabetes 130-US Hospitals source table. "
            "Source values are preserved as released tokens; agent-facing analysis "
            "uses governed typed projections."
        ),
        tags=[
            TagUrn("toxicjoin:external-validation"),
            TagUrn("toxicjoin:external-source-raw"),
        ],
        custom_properties={
            "toxicjoin.synthetic": "false",
            "toxicjoin.external_dataset_doi": DATASET_DOI,
            "toxicjoin.experiment": "external-validation-01",
            "toxicjoin.warehouse_profile_sha256": str(
                warehouse_profile["warehouse_profile_sha256"]
            ),
        },
        schema=[
            (field_name, native_type, f"Raw UCI source field {field_name}.")
            for field_name, native_type in schemas[RAW_TABLE]
        ],
    )
    client.entities.upsert(raw_dataset)
    dataset_urns[RAW_TABLE] = DatasetUrn(
        platform="duckdb", name=raw_name, env="PROD"
    )

    category_counts: dict[str, int] = {category: 0 for category in CATEGORY_TAGS}
    governed_field_count = 0
    for table in GOVERNED_TABLES:
        datahub_name = f"{DATASET_PREFIX}.{table}"
        dataset = Dataset(
            platform="duckdb",
            name=datahub_name,
            env="PROD",
            display_name=f"UCI Diabetes {table}",
            description=(
                f"Typed 1:1 projection '{table}' of the external UCI Diabetes "
                "130-US Hospitals dataset. No synthetic patient or encounter rows "
                "are introduced."
            ),
            tags=[TagUrn("toxicjoin:external-validation")],
            custom_properties={
                "toxicjoin.synthetic": "false",
                "toxicjoin.external_dataset_doi": DATASET_DOI,
                "toxicjoin.experiment": "external-validation-01",
                "toxicjoin.warehouse_profile_sha256": str(
                    warehouse_profile["warehouse_profile_sha256"]
                ),
                "toxicjoin.stewardship_map_version": str(
                    stewardship["schema_version"]
                ),
            },
            schema=[
                (
                    field_name,
                    native_type,
                    (
                        f"External UCI field {field_name}. Frozen stewardship "
                        f"category: {classifications[table][field_name]}."
                    ),
                )
                for field_name, native_type in schemas[table]
            ],
        )

        for field_name, _native_type in schemas[table]:
            category = classifications[table][field_name]
            dataset[field_name].add_tag(TagUrn(CATEGORY_TAGS[category]))
            category_counts[category] += 1
            governed_field_count += 1

        client.entities.upsert(dataset)
        dataset_urns[table] = DatasetUrn(
            platform="duckdb", name=datahub_name, env="PROD"
        )

    raw_columns = {name for name, _type in schemas[RAW_TABLE]}
    for table in GOVERNED_TABLES:
        projection_columns = [name for name, _type in schemas[table]]
        missing_from_raw = sorted(set(projection_columns) - raw_columns)
        if missing_from_raw:
            raise ValueError(
                f"projection lineage cannot be proven for {table}: {missing_from_raw}"
            )
        client.lineage.add_lineage(
            upstream=dataset_urns[RAW_TABLE],
            downstream=dataset_urns[table],
            column_lineage={
                field_name: [field_name] for field_name in projection_columns
            },
        )

    asset_map = {
        "version": f"external:{warehouse_profile['warehouse_profile_sha256'][:16]}",
        "flagship_dataset": "outcomes",
        "flagship_column": "readmitted",
        "datasets": {
            table: str(dataset_urns[table]) for table in GOVERNED_TABLES
        },
    }
    write_atomic(asset_map_path, asset_map)

    created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "created_at": created_at,
        "status": "seeded",
        "dataset_doi": DATASET_DOI,
        "warehouse_profile_sha256": warehouse_profile["warehouse_profile_sha256"],
        "stewardship_map_frozen": True,
        "raw_dataset_urn": str(dataset_urns[RAW_TABLE]),
        "governed_dataset_urns": {
            table: str(dataset_urns[table]) for table in GOVERNED_TABLES
        },
        "governed_dataset_count": len(GOVERNED_TABLES),
        "governed_field_count": governed_field_count,
        "category_counts": category_counts,
        "lineage_write_count": len(GOVERNED_TABLES),
        "synthetic_records_added": 0,
        "patient_rows_in_report": False,
        "report_sha256": "",
    }
    payload["report_sha256"] = report_hash(payload)
    write_atomic(report_path, payload)
    return payload


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--stewardship", required=True, type=Path)
    parser.add_argument("--warehouse-profile", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--asset-map", required=True, type=Path)
    parser.add_argument("--yes", action="store_true")
    args = parser.parse_args()

    if not args.yes:
        parser.error("--yes is required because this command mutates live DataHub metadata")

    payload = seed(
        database=args.database.resolve(),
        stewardship_path=args.stewardship.resolve(),
        warehouse_profile_path=args.warehouse_profile.resolve(),
        report_path=args.report.resolve(),
        asset_map_path=args.asset_map.resolve(),
    )
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
