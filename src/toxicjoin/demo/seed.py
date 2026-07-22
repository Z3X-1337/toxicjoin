"""Build the deterministic synthetic DuckDB warehouse used by ToxicJoin.

The dataset contains no real people and no direct identifiers. Coarse regions have
at least twenty subjects in the default seed, while precise areas deliberately have
small groups. This creates a reproducible privacy boundary for the flagship rewrite.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path
from typing import Any

import duckdb
from pydantic import Field

from toxicjoin.models import StrictModel


DEFAULT_SEED = 1337
DEFAULT_CUSTOMER_COUNT = 120
MODEL_TIMESTAMP = "2026-07-22T00:00:00Z"


class SeedSummary(StrictModel):
    output: str = Field(min_length=1)
    seed: int
    customer_count: int = Field(ge=1)
    row_counts: dict[str, int]
    data_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")


def seed_database(
    output: str | Path,
    *,
    seed: int = DEFAULT_SEED,
    customer_count: int = DEFAULT_CUSTOMER_COUNT,
) -> SeedSummary:
    """Create a fresh deterministic warehouse and return a reproducibility summary."""

    if customer_count < 60:
        raise ValueError("customer_count must be at least 60 for meaningful privacy groups")

    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.unlink(missing_ok=True)

    generated = _generate_rows(seed=seed, customer_count=customer_count)
    fingerprint = _fingerprint(generated)

    connection = duckdb.connect(str(output_path))
    try:
        connection.execute("BEGIN TRANSACTION")
        _create_schema(connection)
        _insert_rows(connection, generated)
        connection.execute("COMMIT")
        row_counts = {
            table: int(connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])
            for table in generated
        }
    except Exception:
        connection.execute("ROLLBACK")
        raise
    finally:
        connection.close()

    return SeedSummary(
        output=str(output_path),
        seed=seed,
        customer_count=customer_count,
        row_counts=row_counts,
        data_fingerprint=fingerprint,
    )


def _generate_rows(*, seed: int, customer_count: int) -> dict[str, list[tuple[Any, ...]]]:
    rng = random.Random(seed)
    regions = ("north", "central", "south")
    age_bands = ("18-24", "25-34", "35-44", "45-54", "55+")
    purchase_categories = ("essentials", "electronics", "home", "travel")

    customers: list[tuple[Any, ...]] = []
    orders: list[tuple[Any, ...]] = []
    support_cases: list[tuple[Any, ...]] = []
    location_activity: list[tuple[Any, ...]] = []
    retention_scores: list[tuple[Any, ...]] = []

    order_number = 1
    case_number = 1

    for index in range(1, customer_count + 1):
        customer_id = f"cust_{index:04d}"
        region = regions[(index - 1) % len(regions)]
        area_number = ((index - 1) // len(regions)) % 4 + 1
        precise_area = f"{region}_district_{area_number}"
        age_band = age_bands[(index + rng.randrange(len(age_bands))) % len(age_bands)]

        customers.append((customer_id, age_band, precise_area, region))

        # Three deterministic transactions per subject produce enough realistic
        # aggregate behavior without introducing direct identifiers.
        for order_offset in range(3):
            category = purchase_categories[(index + order_offset) % len(purchase_categories)]
            amount = round(18 + ((index * 17 + order_offset * 31) % 260) + rng.random(), 2)
            ordered_at = f"2026-06-{((index + order_offset) % 28) + 1:02d}T12:00:00Z"
            orders.append(
                (
                    f"ord_{order_number:05d}",
                    customer_id,
                    amount,
                    category,
                    ordered_at,
                )
            )
            order_number += 1

        if index % 11 == 0:
            case_category = "financial_hardship"
            sensitivity_level = "restricted"
            risk_bonus = 0.34
        elif index % 17 == 0:
            case_category = "medical_accommodation"
            sensitivity_level = "restricted"
            risk_bonus = 0.29
        elif index % 5 == 0:
            case_category = "billing_dispute"
            sensitivity_level = "confidential"
            risk_bonus = 0.17
        else:
            case_category = "technical_support"
            sensitivity_level = "internal"
            risk_bonus = 0.04

        support_cases.append(
            (
                f"case_{case_number:05d}",
                customer_id,
                case_category,
                sensitivity_level,
            )
        )
        case_number += 1

        location_activity.append(
            (
                customer_id,
                precise_area,
                3 + ((index * 7) % 38),
            )
        )

        area_bonus = area_number * 0.025
        region_bonus = {"north": 0.03, "central": 0.07, "south": 0.05}[region]
        churn_score = min(
            0.99,
            round(0.11 + region_bonus + area_bonus + risk_bonus + rng.random() * 0.16, 4),
        )
        retention_scores.append((customer_id, churn_score, MODEL_TIMESTAMP))

    return {
        "customers": customers,
        "orders": orders,
        "support_cases": support_cases,
        "location_activity": location_activity,
        "retention_scores": retention_scores,
    }


def _create_schema(connection: duckdb.DuckDBPyConnection) -> None:
    connection.execute(
        """
        CREATE TABLE customers (
            customer_id VARCHAR PRIMARY KEY,
            age_band VARCHAR NOT NULL,
            precise_area VARCHAR NOT NULL,
            coarse_region VARCHAR NOT NULL
        );

        CREATE TABLE orders (
            order_id VARCHAR PRIMARY KEY,
            customer_id VARCHAR NOT NULL,
            purchase_amount DECIMAL(12, 2) NOT NULL,
            category VARCHAR NOT NULL,
            ordered_at TIMESTAMP NOT NULL
        );

        CREATE TABLE support_cases (
            case_id VARCHAR PRIMARY KEY,
            customer_id VARCHAR NOT NULL,
            case_category VARCHAR NOT NULL,
            sensitivity_level VARCHAR NOT NULL
        );

        CREATE TABLE location_activity (
            customer_id VARCHAR PRIMARY KEY,
            precise_area VARCHAR NOT NULL,
            activity_count INTEGER NOT NULL
        );

        CREATE TABLE retention_scores (
            customer_id VARCHAR PRIMARY KEY,
            churn_score DOUBLE NOT NULL,
            model_timestamp TIMESTAMP NOT NULL
        );
        """
    )


def _insert_rows(
    connection: duckdb.DuckDBPyConnection,
    generated: dict[str, list[tuple[Any, ...]]],
) -> None:
    connection.executemany(
        "INSERT INTO customers VALUES (?, ?, ?, ?)",
        generated["customers"],
    )
    connection.executemany(
        "INSERT INTO orders VALUES (?, ?, ?, ?, ?)",
        generated["orders"],
    )
    connection.executemany(
        "INSERT INTO support_cases VALUES (?, ?, ?, ?)",
        generated["support_cases"],
    )
    connection.executemany(
        "INSERT INTO location_activity VALUES (?, ?, ?)",
        generated["location_activity"],
    )
    connection.executemany(
        "INSERT INTO retention_scores VALUES (?, ?, ?)",
        generated["retention_scores"],
    )


def _fingerprint(generated: dict[str, list[tuple[Any, ...]]]) -> str:
    canonical = json.dumps(
        generated,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed the ToxicJoin synthetic warehouse")
    parser.add_argument("--output", default=".toxicjoin/demo.duckdb")
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--customers", type=int, default=DEFAULT_CUSTOMER_COUNT)
    args = parser.parse_args()

    summary = seed_database(
        args.output,
        seed=args.seed,
        customer_count=args.customers,
    )
    print(summary.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
