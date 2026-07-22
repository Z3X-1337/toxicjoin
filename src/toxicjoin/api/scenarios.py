"""Curated deterministic scenarios used by the API and judge experience."""

from __future__ import annotations

from toxicjoin.api.models import DEFAULT_SUBJECT_KEY, DemoScenario
from toxicjoin.models import Decision
from toxicjoin.pipeline import PipelineRequest


FLAGSHIP_REWRITE_SQL = """
SELECT
  c.coarse_region,
  AVG(r.churn_score) AS average_churn,
  COUNT(DISTINCT c.customer_id) AS subject_count
FROM customers c
JOIN retention_scores r ON c.customer_id = r.customer_id
GROUP BY c.coarse_region
""".strip()


BLOCKED_EXPORT_SQL = """
SELECT c.customer_id, c.age_band, c.precise_area, s.case_category
FROM customers c
JOIN support_cases s ON c.customer_id = s.customer_id
""".strip()


ALLOW_PUBLIC_AGGREGATE_SQL = """
SELECT o.category, COUNT(*) AS order_count
FROM orders o
GROUP BY o.category
ORDER BY o.category
""".strip()


SCENARIOS: tuple[DemoScenario, ...] = (
    DemoScenario(
        scenario_id="rewrite-churn-regions",
        title="Rewrite a sensitive churn analysis",
        description=(
            "The query is analytically useful but lacks a minimum distinct-subject "
            "threshold. ToxicJoin adds a subject-bound HAVING clause, re-evaluates the "
            "query, executes the safe version, and verifies observed group sizes."
        ),
        request=PipelineRequest(
            task_purpose="Identify regions with elevated churn risk",
            sql=FLAGSHIP_REWRITE_SQL,
            subject_key=DEFAULT_SUBJECT_KEY,
        ),
        expected_initial_decision=Decision.REWRITE,
        expected_effective_decision=Decision.ALLOW,
    ),
    DemoScenario(
        scenario_id="block-sensitive-export",
        title="Block compositional re-identification risk",
        description=(
            "A stable pseudonym, two quasi-identifiers, and a sensitive support-case "
            "attribute are projected at individual granularity. The query is blocked "
            "before DuckDB is called."
        ),
        request=PipelineRequest(
            task_purpose="Export customers with sensitive support cases",
            sql=BLOCKED_EXPORT_SQL,
            subject_key=DEFAULT_SUBJECT_KEY,
        ),
        expected_initial_decision=Decision.BLOCK,
        expected_effective_decision=Decision.BLOCK,
    ),
    DemoScenario(
        scenario_id="allow-public-order-counts",
        title="Allow a low-risk aggregate",
        description=(
            "A public category count contains no sensitive attribute and requires no "
            "privacy threshold. ToxicJoin allows and executes it with a bounded preview."
        ),
        request=PipelineRequest(
            task_purpose="Count orders by public category",
            sql=ALLOW_PUBLIC_AGGREGATE_SQL,
            subject_key=DEFAULT_SUBJECT_KEY,
        ),
        expected_initial_decision=Decision.ALLOW,
        expected_effective_decision=Decision.ALLOW,
    ),
)
