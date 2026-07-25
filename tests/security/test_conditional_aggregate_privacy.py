from __future__ import annotations

from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog
from toxicjoin.models import (
    ColumnRef,
    Decision,
    ProjectionExposureKind,
    ReasonCode,
)
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.sql import analyze_sql


_SUBJECT = ColumnRef(dataset="customers", field_path="customer_id", alias="c")


def _conditional_probe(threshold: float, *, customer_id: str = "cust_0011") -> str:
    return f"""
    SELECT
        COUNT(
            CASE
                WHEN c.customer_id = '{customer_id}'
                 AND r.churn_score > {threshold}
                THEN 1
            END
        ) AS probe,
        COUNT(DISTINCT c.customer_id) AS subject_count
    FROM customers c
    JOIN retention_scores r ON c.customer_id = r.customer_id
    HAVING COUNT(DISTINCT c.customer_id) >= 20
    """.strip()


def _exposure(plan, output_name: str):
    matches = [
        exposure
        for exposure in plan.projected_exposures
        if exposure.output_name == output_name
    ]
    assert len(matches) == 1
    return matches[0]


def test_conditional_count_is_not_classified_as_cardinality_only() -> None:
    plan = analyze_sql(_conditional_probe(0.60))

    probe = _exposure(plan, "probe")
    subject_count = _exposure(plan, "subject_count")

    assert probe.kind == ProjectionExposureKind.CONDITIONAL_AGGREGATE
    assert {ref.key for ref in probe.source_columns} == {
        "customers.customer_id",
        "retention_scores.churn_score",
    }
    assert subject_count.kind == ProjectionExposureKind.AGGREGATE_VALUE


def test_outer_k_threshold_does_not_authorize_protected_conditional_count() -> None:
    sql = _conditional_probe(0.60)
    plan = analyze_sql(sql)
    resolver = FixtureContextResolver(default_fixture_catalog())
    context = resolver.resolve(plan)

    decision = PolicyEngine(load_policy()).evaluate(
        context.to_policy_input(
            task_purpose="Regression: predicate oracle against one protected subject",
            query_plan=plan,
            subject_key=_SUBJECT,
        )
    )

    assert plan.minimum_group_size_present == 20
    assert decision.decision == Decision.BLOCK
    assert ReasonCode.COMPOSITIONAL_REIDENTIFICATION_RISK in decision.reason_codes


def test_threshold_binary_search_variants_are_distinct_cohort_inputs() -> None:
    from toxicjoin.disclosure import (
        build_composition_metadata,
        build_semantic_release,
        canonicalize_cohort_sql,
    )

    first = _conditional_probe(0.60)
    second = _conditional_probe(0.70)
    catalog = default_fixture_catalog()
    first_semantic = build_semantic_release(catalog, analyze_sql(first))
    second_semantic = build_semantic_release(catalog, analyze_sql(second))
    secret = b"x" * 32

    assert canonicalize_cohort_sql(first) != canonicalize_cohort_sql(second)
    assert (
        build_composition_metadata(first_semantic, first, secret_key=secret).cohort_hmac_sha256
        != build_composition_metadata(second_semantic, second, secret_key=secret).cohort_hmac_sha256
    )


def test_target_subject_variants_are_distinct_cohort_inputs() -> None:
    from toxicjoin.disclosure import build_composition_metadata, build_semantic_release

    first = _conditional_probe(0.60, customer_id="cust_0011")
    second = _conditional_probe(0.60, customer_id="cust_0012")
    catalog = default_fixture_catalog()
    first_semantic = build_semantic_release(catalog, analyze_sql(first))
    second_semantic = build_semantic_release(catalog, analyze_sql(second))
    secret = b"x" * 32

    assert (
        build_composition_metadata(first_semantic, first, secret_key=secret).cohort_hmac_sha256
        != build_composition_metadata(second_semantic, second, secret_key=secret).cohort_hmac_sha256
    )
