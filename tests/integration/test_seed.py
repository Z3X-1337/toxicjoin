from __future__ import annotations

import re

import duckdb

from toxicjoin.demo import seed_database


def test_seed_is_deterministic(tmp_path) -> None:
    first = seed_database(tmp_path / "first.duckdb")
    second = seed_database(tmp_path / "second.duckdb")

    assert first.data_fingerprint == second.data_fingerprint
    assert first.row_counts == second.row_counts == {
        "customers": 120,
        "orders": 360,
        "support_cases": 120,
        "location_activity": 120,
        "retention_scores": 120,
    }


def test_seed_creates_safe_coarse_groups_and_unsafe_precise_groups(tmp_path) -> None:
    database = tmp_path / "demo.duckdb"
    seed_database(database)

    connection = duckdb.connect(str(database), read_only=True)
    try:
        coarse_sizes = [
            row[1]
            for row in connection.execute(
                """
                SELECT coarse_region, COUNT(DISTINCT customer_id) AS subjects
                FROM customers
                GROUP BY coarse_region
                ORDER BY coarse_region
                """
            ).fetchall()
        ]
        precise_sizes = [
            row[1]
            for row in connection.execute(
                """
                SELECT precise_area, COUNT(DISTINCT customer_id) AS subjects
                FROM customers
                GROUP BY precise_area
                ORDER BY precise_area
                """
            ).fetchall()
        ]
    finally:
        connection.close()

    assert coarse_sizes == [40, 40, 40]
    assert len(precise_sizes) == 12
    assert set(precise_sizes) == {10}
    assert min(coarse_sizes) >= 20
    assert max(precise_sizes) < 20


def test_public_seed_contains_no_direct_identity_fields(tmp_path) -> None:
    database = tmp_path / "demo.duckdb"
    seed_database(database)

    connection = duckdb.connect(str(database), read_only=True)
    try:
        customer_columns = {
            row[1].lower()
            for row in connection.execute("PRAGMA table_info('customers')").fetchall()
        }
        customer_ids = [
            row[0]
            for row in connection.execute(
                "SELECT customer_id FROM customers ORDER BY customer_id"
            ).fetchall()
        ]
    finally:
        connection.close()

    forbidden_names = {"name", "full_name", "email", "phone", "address"}
    assert customer_columns.isdisjoint(forbidden_names)
    assert all(re.fullmatch(r"cust_\d{4}", customer_id) for customer_id in customer_ids)


def test_seed_contains_sensitive_cases_for_flagship_policy(tmp_path) -> None:
    database = tmp_path / "demo.duckdb"
    seed_database(database)

    connection = duckdb.connect(str(database), read_only=True)
    try:
        categories = {
            row[0]
            for row in connection.execute(
                "SELECT DISTINCT case_category FROM support_cases"
            ).fetchall()
        }
        restricted_count = connection.execute(
            "SELECT COUNT(*) FROM support_cases WHERE sensitivity_level = 'restricted'"
        ).fetchone()[0]
    finally:
        connection.close()

    assert {"financial_hardship", "medical_accommodation"}.issubset(categories)
    assert restricted_count > 0
