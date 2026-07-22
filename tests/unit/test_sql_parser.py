from __future__ import annotations

import pytest

from toxicjoin.models import ReasonCode
from toxicjoin.sql import SqlAnalysisError, analyze_sql


def _ref_keys(refs: tuple) -> set[str]:
    return {ref.key for ref in refs}


def test_extracts_flagship_sources_joins_grouping_references_and_threshold() -> None:
    plan = analyze_sql(
        """
        SELECT
          c.coarse_region,
          AVG(r.churn_score) AS average_churn,
          COUNT(DISTINCT c.customer_id) AS subject_count
        FROM customers AS c
        JOIN retention_scores AS r
          ON c.customer_id = r.customer_id
        WHERE r.churn_score >= 0.65
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
    assert _ref_keys(plan.referenced_columns) == {
        "customers.coarse_region",
        "customers.customer_id",
        "retention_scores.churn_score",
        "retention_scores.customer_id",
    }
    assert set(plan.aggregate_functions) == {"AVG", "COUNT"}
    assert plan.minimum_group_size_present == 20
    assert plan.minimum_group_size_subject is not None
    assert plan.minimum_group_size_subject.key == "customers.customer_id"
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
        "COPY customers TO 'customers.csv'",
        "ATTACH 'other.duckdb' AS other",
    ],
)
def test_rejects_non_select_or_external_access_statements(sql: str) -> None:
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


def test_resolves_cte_output_to_physical_columns() -> None:
    plan = analyze_sql(
        """
        WITH risk AS (
          SELECT customer_id, churn_score
          FROM retention_scores
        )
        SELECT risk.customer_id, risk.churn_score
        FROM risk
        WHERE risk.churn_score > 0.8
        """
    )

    assert set(plan.source_datasets) == {"retention_scores"}
    assert _ref_keys(plan.projected_columns) == {
        "retention_scores.customer_id",
        "retention_scores.churn_score",
    }
    assert _ref_keys(plan.referenced_columns) == {
        "retention_scores.customer_id",
        "retention_scores.churn_score",
    }
    assert not any(ref.dataset.startswith("@") for ref in plan.referenced_columns)


def test_resolves_aliased_cte_expression_to_physical_input() -> None:
    plan = analyze_sql(
        """
        WITH risk AS (
          SELECT customer_id, churn_score * 100 AS churn_percent
          FROM retention_scores
        )
        SELECT risk.churn_percent
        FROM risk
        """
    )

    assert _ref_keys(plan.projected_columns) == {"retention_scores.churn_score"}


def test_does_not_trust_or_based_group_threshold() -> None:
    plan = analyze_sql(
        """
        SELECT c.coarse_region, AVG(r.churn_score)
        FROM customers c
        JOIN retention_scores r ON c.customer_id = r.customer_id
        GROUP BY c.coarse_region
        HAVING COUNT(DISTINCT c.customer_id) >= 20
            OR AVG(r.churn_score) > 0.9
        """
    )

    assert plan.minimum_group_size_present is None
    assert plan.minimum_group_size_subject is None
    assert "UNTRUSTED_GROUP_THRESHOLD_OR_EXPRESSION" in plan.analysis_warnings


def test_tracks_threshold_subject_even_when_it_is_not_the_customer() -> None:
    plan = analyze_sql(
        """
        SELECT c.coarse_region, COUNT(DISTINCT o.order_id)
        FROM customers c
        JOIN orders o ON c.customer_id = o.customer_id
        GROUP BY c.coarse_region
        HAVING COUNT(DISTINCT o.order_id) >= 20
        """
    )

    assert plan.minimum_group_size_present == 20
    assert plan.minimum_group_size_subject is not None
    assert plan.minimum_group_size_subject.key == "orders.order_id"


def test_rejects_cross_join() -> None:
    with pytest.raises(SqlAnalysisError) as captured:
        analyze_sql("SELECT c.customer_id FROM customers c CROSS JOIN orders o")

    assert captured.value.reason_code == ReasonCode.UNSUPPORTED_STATEMENT


def test_rejects_join_using_until_explicitly_supported() -> None:
    with pytest.raises(SqlAnalysisError) as captured:
        analyze_sql("SELECT c.customer_id FROM customers c JOIN orders o USING (customer_id)")

    assert captured.value.reason_code == ReasonCode.UNSUPPORTED_STATEMENT
