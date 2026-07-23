#!/usr/bin/env python3
"""Acquire and fingerprint the preregistered UCI Diabetes external validation source.

This tool intentionally does not run ToxicJoin policy evaluation. It performs only
source fingerprinting, strict schema validation, raw preservation, deterministic
1:1 relational projections, and sanitized provenance output with no patient rows.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import tempfile
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any

import duckdb

DATASET_DOI = "10.24432/C5230J"
OFFICIAL_SOURCE_URL = (
    "https://archive.ics.uci.edu/static/public/296/"
    "diabetes%2B130-us%2Bhospitals%2Bfor%2Byears%2B1999-2008.zip"
)
EXPECTED_ROWS = 101_766
EXPECTED_COLUMNS = (
    "encounter_id", "patient_nbr", "race", "gender", "age", "weight",
    "admission_type_id", "discharge_disposition_id", "admission_source_id",
    "time_in_hospital", "payer_code", "medical_specialty", "num_lab_procedures",
    "num_procedures", "num_medications", "number_outpatient", "number_emergency",
    "number_inpatient", "diag_1", "diag_2", "diag_3", "number_diagnoses",
    "max_glu_serum", "A1Cresult", "metformin", "repaglinide", "nateglinide",
    "chlorpropamide", "glimepiride", "acetohexamide", "glipizide", "glyburide",
    "tolbutamide", "pioglitazone", "rosiglitazone", "acarbose", "miglitol",
    "troglitazone", "tolazamide", "examide", "citoglipton", "insulin",
    "glyburide-metformin", "glipizide-metformin", "glimepiride-pioglitazone",
    "metformin-rosiglitazone", "metformin-pioglitazone", "change", "diabetesMed",
    "readmitted",
)

PROJECTIONS: dict[str, tuple[str, ...]] = {
    "encounters": (
        "encounter_id", "patient_nbr", "race", "gender", "age", "weight",
        "admission_type_id", "discharge_disposition_id", "admission_source_id",
        "time_in_hospital", "payer_code", "medical_specialty", "num_lab_procedures",
        "num_procedures", "num_medications", "number_outpatient", "number_emergency",
        "number_inpatient", "number_diagnoses",
    ),
    "diagnoses": ("encounter_id", "patient_nbr", "diag_1", "diag_2", "diag_3"),
    "labs": ("encounter_id", "patient_nbr", "max_glu_serum", "A1Cresult"),
    "medications": (
        "encounter_id", "patient_nbr", "metformin", "repaglinide", "nateglinide",
        "chlorpropamide", "glimepiride", "acetohexamide", "glipizide", "glyburide",
        "tolbutamide", "pioglitazone", "rosiglitazone", "acarbose", "miglitol",
        "troglitazone", "tolazamide", "examide", "citoglipton", "insulin",
        "glyburide-metformin", "glipizide-metformin", "glimepiride-pioglitazone",
        "metformin-rosiglitazone", "metformin-pioglitazone", "change", "diabetesMed",
    ),
    "outcomes": (
        "encounter_id", "patient_nbr", "discharge_disposition_id", "readmitted"
    ),
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_json(value: Any) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def extract_source(source: Path, destination: Path) -> tuple[Path, Path | None]:
    if source.suffix.lower() != ".zip":
        if source.name != "diabetic_data.csv":
            raise ValueError("non-ZIP source must be the official diabetic_data.csv file")
        return source, None

    with zipfile.ZipFile(source) as archive:
        names = archive.namelist()
        diabetic_members = [
            name for name in names if Path(name).name == "diabetic_data.csv"
        ]
        mapping_members = [
            name for name in names if Path(name).name == "IDS_mapping.csv"
        ]
        if len(diabetic_members) != 1:
            raise ValueError(
                "expected exactly one diabetic_data.csv in archive, "
                f"got {diabetic_members}"
            )
        diabetic_path = destination / "diabetic_data.csv"
        with archive.open(diabetic_members[0]) as src, diabetic_path.open("wb") as dst:
            dst.write(src.read())

        mapping_path: Path | None = None
        if len(mapping_members) == 1:
            mapping_path = destination / "IDS_mapping.csv"
            with archive.open(mapping_members[0]) as src, mapping_path.open("wb") as dst:
                dst.write(src.read())
        elif len(mapping_members) > 1:
            raise ValueError(f"expected at most one IDS_mapping.csv, got {mapping_members}")

    return diabetic_path, mapping_path


def inspect_csv(path: Path) -> dict[str, Any]:
    question_mark_counts: Counter[str] = Counter()
    encounter_ids: set[str] = set()
    patient_ids: set[str] = set()
    row_count = 0

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        if reader.fieldnames is None:
            raise ValueError("CSV has no header")
        header = tuple(reader.fieldnames)
        if header != EXPECTED_COLUMNS:
            raise ValueError(
                "official source header changed; refusing to silently adapt. "
                f"expected {len(EXPECTED_COLUMNS)} columns, got {len(header)}"
            )

        for row in reader:
            row_count += 1
            encounter_ids.add(row["encounter_id"])
            patient_ids.add(row["patient_nbr"])
            for column, value in row.items():
                if value == "?":
                    question_mark_counts[column] += 1

    if row_count != EXPECTED_ROWS:
        raise ValueError(
            "official source row count changed; refusing measured evaluation "
            f"without a new preregistration: expected {EXPECTED_ROWS}, got {row_count}"
        )

    return {
        "row_count": row_count,
        "column_count": len(EXPECTED_COLUMNS),
        "header_sha256": hashlib.sha256(
            ",".join(EXPECTED_COLUMNS).encode("utf-8")
        ).hexdigest(),
        "distinct_encounter_id_count": len(encounter_ids),
        "duplicate_encounter_id_count": row_count - len(encounter_ids),
        "distinct_patient_nbr_count": len(patient_ids),
        "question_mark_counts": dict(sorted(question_mark_counts.items())),
    }


def quote_identifier(identifier: str) -> str:
    return '"' + identifier.replace('"', '""') + '"'


def build_warehouse(csv_path: Path, database: Path) -> dict[str, int]:
    database.parent.mkdir(parents=True, exist_ok=True)
    database.unlink(missing_ok=True)

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
            [str(csv_path)],
        )

        table_counts: dict[str, int] = {
            "raw_diabetic_data": int(
                connection.execute("SELECT COUNT(*) FROM raw_diabetic_data").fetchone()[0]
            )
        }

        for table_name, columns in PROJECTIONS.items():
            select_list = ", ".join(quote_identifier(column) for column in columns)
            connection.execute(
                f"CREATE TABLE {quote_identifier(table_name)} AS "
                f"SELECT {select_list} FROM raw_diabetic_data"
            )
            table_counts[table_name] = int(
                connection.execute(
                    f"SELECT COUNT(*) FROM {quote_identifier(table_name)}"
                ).fetchone()[0]
            )

        raw_count = table_counts["raw_diabetic_data"]
        if any(count != raw_count for count in table_counts.values()):
            raise RuntimeError(
                "a relational projection changed row cardinality; refusing to continue"
            )
        return table_counts
    finally:
        connection.close()


def make_report(
    *,
    source: Path,
    diabetic_csv: Path,
    mapping_csv: Path | None,
    inspection: dict[str, Any],
    table_counts: dict[str, int],
) -> dict[str, Any]:
    projection_spec = {
        name: list(columns) for name, columns in sorted(PROJECTIONS.items())
    }
    report: dict[str, Any] = {
        "schema_version": "1.0",
        "experiment": "external-validation-01-source-acquisition",
        "dataset_doi": DATASET_DOI,
        "official_source_url": OFFICIAL_SOURCE_URL,
        "source_file_name": source.name,
        "source_archive_sha256": sha256_file(source),
        "diabetic_data_csv_sha256": sha256_file(diabetic_csv),
        "ids_mapping_csv_sha256": (
            sha256_file(mapping_csv) if mapping_csv is not None else None
        ),
        **inspection,
        "projection_spec": projection_spec,
        "projection_definition_sha256": sha256_json(projection_spec),
        "table_row_counts": table_counts,
        "raw_values_modified": False,
        "synthetic_patient_or_encounter_records_added": False,
        "contains_patient_rows": False,
        "limitations": [
            "This stage fingerprints and projects the external source only.",
            "No ToxicJoin policy decision is measured in this stage.",
            "Question-mark missing-value tokens are retained as source values.",
        ],
        "report_sha256": "",
    }
    report["report_sha256"] = sha256_json(
        {key: value for key, value in report.items() if key != "report_sha256"}
    )
    return report


def write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(content, encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    source = args.source.resolve()
    if not source.is_file():
        raise FileNotFoundError(source)

    with tempfile.TemporaryDirectory(prefix="toxicjoin-external-source-") as temp:
        temp_root = Path(temp)
        diabetic_csv, mapping_csv = extract_source(source, temp_root)
        inspection = inspect_csv(diabetic_csv)
        table_counts = build_warehouse(diabetic_csv, args.database.resolve())
        report = make_report(
            source=source,
            diabetic_csv=diabetic_csv,
            mapping_csv=mapping_csv,
            inspection=inspection,
            table_counts=table_counts,
        )

    write_atomic(args.report.resolve(), json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
