from __future__ import annotations

from pathlib import Path

import pytest

from toxicjoin.context import FixtureContextResolver
from toxicjoin.models import ColumnRef, Decision
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.rewrite import RewriteError, enforce_minimum_group_size


ROOT = Path(__file__).parents[2]
CATALOG = ROOT / "demo" / "fixtures" / "catalog.json"
POLICY = ROOT / "config" / "policy.yaml"
SUBJECT = ColumnRef(dataset="customers", field_path="customer_id", alias="c")


FLAGSHIP_SQL = """
SELECT
  c.coarse_region,
  AVG(r.churn_score) AS average_churn,
  COUNT(DISTINCT c.customer_id) AS subject_count
FROM customers c
JOIN retention_scores r ON c.customer_id = r.customer_id
GROUP BY c.coarse_region
"""


def test_adds_subject_bound_minimum_group_threshold() -> None:
    result = enforce_minimum_group_size(
        FLAGSHIP_SQL,
        subject_key=SUBJECT,
        minimum_group_size=20,
    )

    assert result.operations == ("ADD_MINIMUM_SUBJECT_THRESHOLD",)
    assert result.safe_plan.minimum_group_size_present == 20
    assert result.safe_plan.minimum_group_size_subject is not None
    assert result.safe_plan.minimum_group_size_subject.key == SUBJECT.key
    assert "HAVING" in result.safe_sql.upper()


def test_strengthens_lower_threshold() -> None:
    result = enforce_minimum_group_size(
        FLAGSHIP_SQL + "\nHAVING COUNT(DISTINCT c.customer_id) >= 5",
        subject_key=SUBJECT,
        minimum_group_size=20,
    )

    assert result.operations == ("STRENGTHEN_MINIMUM_SUBJECT_THRESHOLD",)
    assert result.safe_plan.minimum_group_size_present == 20


def test_preserves_already_safe_threshold() -> None:
    sql = FLAGSHIP_SQL + "\nHAVING COUNT(DISTINCT c.customer_id) >= 30"
    result = enforce_minimum_group_size(
        sql,
        subject_key=SUBJECT,
        minimum_group_size=20,
    )

    assert result.operations == ("NO_OP_TRUSTED_THRESHOLD_PRESENT",)
    assert result.safe_sql == sql
    assert result.safe_plan.minimum_group_size_present == 30


def test_rewritten_query_passes_policy_reevaluation() -> None:
    result = enforce_minimum_group_size(
        FLAGSHIP_SQL,
        subject_key=SUBJECT,
        minimum_group_size=20,
    )
    resolution = FixtureContextResolver.from_path(CATALOG).resolve(result.safe_plan)
    decision = PolicyEngine(load_policy(POLICY)).evaluate(
        resolution.to_policy_input(
            task_purpose="Find regions with elevated churn risk",
            query_plan=result.safe_plan,
            subject_key=SUBJECT,
        )
    )

    assert decision.decision == Decision.ALLOW
    assert decision.evidence["trusted_minimum_group_size"] == 20
    assert decision.evidence["trusted_threshold_subject"] == SUBJECT.key


def test_rejects_ungrouped_query() -> None:
    with pytest.raises(RewriteError):
        enforce_minimum_group_size(
            "SELECT c.customer_id, c.precise_area FROM customers c",
            subject_key=SUBJECT,
            minimum_group_size=20,
        )


def test_rejects_threshold_for_different_subject() -> None:
    sql = """
    SELECT
      c.coarse_region,
      AVG(r.churn_score) AS average_churn,
      COUNT(DISTINCT o.order_id) AS order_count
    FROM customers c
    JOIN retention_scores r ON c.customer_id = r.customer_id
    JOIN orders o ON c.customer_id = o.customer_id
    GROUP BY c.coarse_region
    HAVING COUNT(DISTINCT o.order_id) >= 20
    """

    with pytest.raises(RewriteError, match="different subject key"):
        enforce_minimum_group_size(
            sql,
            subject_key=SUBJECT,
            minimum_group_size=20,
        )


def test_rejects_or_based_having_expression() -> None:
    sql = FLAGSHIP_SQL + """
    HAVING COUNT(DISTINCT c.customer_id) >= 20
       OR AVG(r.churn_score) > 0.9
    """

    with pytest.raises(RewriteError, match="containing OR"):
        enforce_minimum_group_size(
            sql,
            subject_key=SUBJECT,
            minimum_group_size=20,
        )
