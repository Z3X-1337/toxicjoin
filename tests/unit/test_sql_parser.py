from __future__ import annotations

import pytest

from toxicjoin.models import ReasonCode
from toxicjoin.sql import SqlAnalysisError, analyze_sql


def _ref_keys(refs: tuple) -> set[str]:
    return {ref.key for ref in refs}


def test_extracts_flagship_sources_joins_and_grouping() -> None:
    plan = analyze_sql(
        """
        SELECT
          c.coarse_region,
          AVG(r.churn_score) AS average_churn,
          COUNT(DISTINCT c.customer_id) AS subject_count
        FROM customers AS c
        JOIN retention_scores AS r
          ON c.customer_id = r.customer_id
        GROUP BY c.coarse_region
        HAVING COUNT(DISTINCT c.customer_id) >= 20
        """
    )

    assert plan.statement_type == "SELECT"
    assert set(plan.source_datasets) == {"customers", "retention_scores"}
    assert _ref_keys(plan.projected_columns) == {
        "customers.coarse_region",
        "retention_scores.churn_score",
        "customers.customer_id",
    }
    assert _ref_keys(plan.join_columns) == {
        "customers.customer_id",
        "retention_scores.customer_id",
    }
    assert _ref_keys(plan.group_by_columns) == {"customers.coarse_region"}
    assert set(plan.aggregate_functions) == {"AVG", "COUNT"}
    assert plan.is_grouped is True
    assert plan.contains_wildcard is False


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO audit_log SELECT * FROM customers",
        "UPDATE customers SET coarse_region = 'x'",
        "DELETE FROM customers",
        "CREATE TABLE copied AS SELECT * FROM customers",
        "DROP TABLE customers",
    ],
)
def test_rejects_non_select_statements(sql: str) -> None:
    with pytest.raises(SqlAnalysisError) as captured:
        analyze_sql(sql)

    assert captured.value.reason_code == ReasonCode.UNSUPPORTED_STATEMENT


def test_rejects_multiple_statements() -> None:
    with pytest.raises(SqlAnalysisError) as captured:
        analyze_sql("SELECT 1; SELECT 2")

    assert captured.value.reason_code == ReasonCode.MULTIPLE_STATEMENTS


def test_rejects_ambiguous_unqualified_column() -> None:
    with pytest.raises(SqlAnalysisError) as captured:
        analyze_sql(
            """
            SELECT customer_id
            FROM customers c
            JOIN retention_scores r ON c.customer_id = r.customer_id
            """
        )

    assert captured.value.reason_code == ReasonCode.AMBIGUOUS_COLUMN


def test_marks_select_star_for_schema_expansion() -> None:
    plan = analyze_sql("SELECT * FROM customers")

    assert plan.contains_wildcard is True
    assert "SELECT_STAR_REQUIRES_SCHEMA_EXPANSION" in plan.analysis_warnings


def test_extracts_physical_sources_from_cte() -> None:
    plan = analyze_sql(
        """
        WITH risk AS (
          SELECT customer_id, churn_score
          FROM retention_scores
        )
        SELECT risk.customer_id, risk.churn_score
        FROM risk
        """
    )

    assert set(plan.source_datasets) == {"retention_scores"}
    assert plan.statement_type == "SELECT"


def test_rejects_cross_join() -> None:
    with pytest.raises(SqlAnalysisError) as captured:
        analyze_sql("SELECT c.customer_id FROM customers c CROSS JOIN orders o")

    assert captured.value.reason_code == ReasonCode.UNSUPPORTED_STATEMENT


def test_rejects_join_using_until_explicitly_supported() -> None:
    with pytest.raises(SqlAnalysisError) as captured:
        analyze_sql("SELECT c.customer_id FROM customers c JOIN orders o USING (customer_id)")

    assert captured.value.reason_code == ReasonCode.UNSUPPORTED_STATEMENT
