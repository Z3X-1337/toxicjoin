"""Build a regression catalog from the frozen external stewardship map.

This is not a substitute for the live DataHub validation gate. It exists only to replay
already-retained SQL proposals quickly while kernel changes are isolated. Promotion
still requires a real DataHub OSS + MCP confirmation run.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import duckdb

from toxicjoin.context import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.models import SensitivityCategory


CATEGORY_MAP = {
    "DIRECT_IDENTIFIER": SensitivityCategory.DIRECT_IDENTIFIER,
    "STABLE_PSEUDONYM": SensitivityCategory.STABLE_PSEUDONYM,
    "QUASI_IDENTIFIER": SensitivityCategory.QUASI_IDENTIFIER,
    "SENSITIVE_ATTRIBUTE": SensitivityCategory.SENSITIVE_ATTRIBUTE,
    "PUBLIC_OR_LOW_RISK": SensitivityCategory.PUBLIC_OR_LOW_RISK,
}


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected object: {path}")
    return value


def build_external_regression_catalog(
    *,
    database: Path,
    stewardship_path: Path,
    version: str,
) -> FixtureCatalog:
    stewardship = _load_object(stewardship_path)
    if stewardship.get("frozen_before_measured_policy_run") is not True:
        raise ValueError("external stewardship map is not marked frozen")

    table_specs = stewardship.get("tables")
    if not isinstance(table_specs, dict):
        raise ValueError("stewardship map has no tables object")

    connection = duckdb.connect(str(database), read_only=True)
    try:
        datasets: dict[str, FixtureDataset] = {}
        for table_name in sorted(table_specs):
            rows = connection.execute(
                f'PRAGMA table_info("{table_name}")'
            ).fetchall()
            if not rows:
                raise ValueError(f"warehouse table missing: {table_name}")

            spec = table_specs[table_name]
            if not isinstance(spec, dict):
                raise ValueError(f"invalid stewardship table spec: {table_name}")
            explicit = spec.get("fields", {})
            overrides = spec.get("overrides", {})
            default = spec.get("default_category")
            if not isinstance(explicit, dict) or not isinstance(overrides, dict):
                raise ValueError(f"invalid stewardship mapping for {table_name}")

            fields: dict[str, FixtureField] = {}
            for row in rows:
                field_name = str(row[1])
                category_name = explicit.get(
                    field_name,
                    overrides.get(field_name, default),
                )
                if category_name not in CATEGORY_MAP:
                    raise ValueError(
                        f"no frozen category for {table_name}.{field_name}: "
                        f"{category_name!r}"
                    )
                tag = stewardship["datahub_tag_mapping"][category_name]
                fields[field_name] = FixtureField(
                    category=CATEGORY_MAP[category_name],
                    tags=(str(tag),),
                    glossary_terms=(),
                )

            datasets[table_name] = FixtureDataset(
                urn=(
                    "urn:li:dataset:(urn:li:dataPlatform:duckdb,"
                    f"toxicjoin.external.uci_diabetes.{table_name},PROD)"
                ),
                fields=fields,
            )

        return FixtureCatalog(version=version, datasets=datasets)
    finally:
        connection.close()
