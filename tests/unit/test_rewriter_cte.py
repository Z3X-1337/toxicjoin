from toxicjoin.models import ColumnRef
from toxicjoin.rewrite import RewriteError, enforce_minimum_group_size


CTE_SQL = """
WITH scored AS (
  SELECT c.customer_id, c.coarse_region, r.churn_score
  FROM customers c
  JOIN retention_scores r ON c.customer_id = r.customer_id
)
SELECT
  s.coarse_region,
  AVG(s.churn_score) AS average_churn,
  COUNT(DISTINCT s.customer_id) AS subject_count
FROM scored s
GROUP BY s.coarse_region
"""


def test_rewrite_binds_physical_subject_to_root_cte_alias() -> None:
    result = enforce_minimum_group_size(
        CTE_SQL,
        subject_key=ColumnRef(
            dataset="customers",
            field_path="customer_id",
            alias="c",
        ),
        minimum_group_size=20,
    )

    assert result.safe_plan.minimum_group_size_present == 20
    assert result.safe_plan.minimum_group_size_subject is not None
    assert result.safe_plan.minimum_group_size_subject.key == "customers.customer_id"
    assert "COUNT(DISTINCT s.customer_id) >= 20" in result.safe_sql
    assert "COUNT(DISTINCT c.customer_id) >= 20" not in result.safe_sql


def test_rewrite_rejects_ambiguous_root_subject_aliases() -> None:
    sql = """
    SELECT
      c.coarse_region,
      AVG(r.churn_score) AS average_churn,
      COUNT(DISTINCT c.customer_id) AS left_subjects,
      COUNT(DISTINCT x.customer_id) AS right_subjects
    FROM customers c
    JOIN customers x ON c.coarse_region = x.coarse_region
    JOIN retention_scores r ON c.customer_id = r.customer_id
    GROUP BY c.coarse_region
    """

    try:
        enforce_minimum_group_size(
            sql,
            subject_key=ColumnRef(
                dataset="customers",
                field_path="customer_id",
                alias="missing_alias",
            ),
            minimum_group_size=20,
        )
    except RewriteError as exc:
        assert "multiple root query aliases" in str(exc)
    else:
        raise AssertionError("ambiguous root subject binding must fail closed")
