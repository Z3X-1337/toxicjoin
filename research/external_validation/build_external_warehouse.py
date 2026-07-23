#!/usr/bin/env python3
"""Build the typed external-validation DuckDB profile from the official UCI source.

The raw CSV is retained unchanged in ``raw_diabetic_data`` as VARCHAR source tokens.
Typed 1:1 projections normalize the UCI ``?`` missing marker to NULL and cast only
fields whose public UCI semantics are integer/identifier values. No rows are filtered,
deduplicated, imputed, or synthesized.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

import duckdb

from ingest_uci_diabetes import (
    EXPECTED_ROWS,
    OFFICIAL_SOURCE_URL,
    PROJECTIONS,
    extract_source,
    inspect_csv,
    sha256_file,
)

INTEGER_FIELDS = {
    "admission_type_id",
    "discharge_disposition_id",
    "admission_source_id",
    "time_in_hospital",
    "num_lab_procedures",
    "num_procedures",
    "num_medications",
    "number_outpatient",
    "number_emergency",
    "number_inpatient",
    "number_diagnoses",
}
BIGINT_FIELDS = {"encounter_id", "patient_nbr"}


def quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def typed_expression(column: str) -> str:
    quoted = quote_identifier(column)
    cleaned = f"NULLIF({quoted}, '?')"
    if column in BIGINT_FIELDS:
        return f"CAST({cleaned} AS BIGINT) AS {quoted}"
    if column in INTEGER_FIELDS:
        return f"CAST({cleaned} AS INTEGER) AS {quoted}"
    return f"{cleaned} AS {quoted}"


def projection_definition() -> dict[str, Any]:
    return {
        table: {
            column: (
                "BIGINT"
                if column in BIGINT_FIELDS
                else "INTEGER"
                if column in INTEGER_FIELDS
                else "VARCHAR"
            )
            for column in columns
        }
        for table, columns in sorted(PROJECTIONS.items())
    }


def sha256_json(value: Any) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def build(source: Path, database: Path) -> dict[str, Any]:
    source = source.resolve()
    database = database.resolve()
    database.parent.mkdir(parents=True, exist_ok=True)
    database.unlink(missing_ok=True)

    with tempfile.TemporaryDirectory(prefix="toxicjoin-external-warehouse-") as temp:
        diabetic_csv, mapping_csv = extract_source(source, Path(temp))
        inspection = inspect_csv(diabetic_csv)

        connection = duckdb.connect(str(database))
        try:
            connection.execute(
                """
                CREATE TABLE raw_diabetic_data AS
                SELECT *
                FROM read_csv_auto(
                    ?,
                    header = true,
                    all_varchar = true,
                    ignore_errors = false,
                    null_padding = false
                )
                """,
                [str(diabetic_csv)],
            )

            raw_count = int(
                connection.execute("SELECT COUNT(*) FROM raw_diabetic_data").fetchone()[0]
            )
            if raw_count != EXPECTED_ROWS:
                raise RuntimeError(
                    f"raw warehouse row count mismatch: {raw_count} != {EXPECTED_ROWS}"
                )

            cast_failures: dict[str, int] = {}
            for column in sorted(BIGINT_FIELDS | INTEGER_FIELDS):
                quoted = quote_identifier(column)
                target = "BIGINT" if column in BIGINT_FIELDS else "INTEGER"
                count = int(
                    connection.execute(
                        f"""
                        SELECT COUNT(*)
                        FROM raw_diabetic_data
                        WHERE {quoted} NOT IN ('?', '')
                          AND TRY_CAST({quoted} AS {target}) IS NULL
                        """
                    ).fetchone()[0]
                )
                cast_failures[column] = count

            nonzero_cast_failures = {
                column: count for column, count in cast_failures.items() if count
            }
            if nonzero_cast_failures:
                raise RuntimeError(
                    "typed projection assumptions failed: "
                    + json.dumps(nonzero_cast_failures, sort_keys=True)
                )

            table_counts: dict[str, int] = {}
            table_schemas: dict[str, list[dict[str, str]]] = {}
            for table_name, columns in PROJECTIONS.items():
                select_list = ", ".join(typed_expression(column) for column in columns)
                connection.execute(
                    f"CREATE TABLE {quote_identifier(table_name)} AS "
                    f"SELECT {select_list} FROM raw_diabetic_data"
                )
                count = int(
                    connection.execute(
                        f"SELECT COUNT(*) FROM {quote_identifier(table_name)}"
                    ).fetchone()[0]
                )
                if count != raw_count:
                    raise RuntimeError(
                        f"{table_name} row cardinality changed: {count} != {raw_count}"
                    )
                table_counts[table_name] = count
                table_schemas[table_name] = [
                    {"name": str(row[1]), "type": str(row[2])}
                    for row in connection.execute(
                        f"PRAGMA table_info({quote_identifier(table_name)})"
                    ).fetchall()
                ]

            projection = projection_definition()
            projection_hash = sha256_json(projection)
            source_csv_hash = sha256_file(diabetic_csv)
            warehouse_profile_hash = hashlib.sha256(
                f"{source_csv_hash}:{projection_hash}".encode("ascii")
            ).hexdigest()

            return {
                "schema_version": "1.0",
                "experiment": "external-validation-01-warehouse-profile",
                "official_source_url": OFFICIAL_SOURCE_URL,
                "source_archive_sha256": sha256_file(source),
                "diabetic_data_csv_sha256": source_csv_hash,
                "ids_mapping_csv_sha256": (
                    sha256_file(mapping_csv) if mapping_csv is not None else None
                ),
                "source_row_count": inspection["row_count"],
                "source_column_count": inspection["column_count"],
                "raw_table_row_count": raw_count,
                "typed_table_row_counts": table_counts,
                "typed_table_schemas": table_schemas,
                "cast_failure_counts": cast_failures,
                "projection_definition": projection,
                "projection_definition_sha256": projection_hash,
                "warehouse_profile_sha256": warehouse_profile_hash,
                "raw_table_preserves_source_tokens": True,
                "typed_projection_normalizes_question_mark_to_null": True,
                "rows_filtered": 0,
                "rows_synthesized": 0,
                "rows_deduplicated": 0,
                "contains_patient_rows": False,
            }
        finally:
            connection.close()


def write_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(content, encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()

    payload = build(args.source, args.database)
    write_atomic(args.report.resolve(), payload)
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
