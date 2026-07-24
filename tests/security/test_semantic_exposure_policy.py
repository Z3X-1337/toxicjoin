from __future__ import annotations

from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog
from toxicjoin.models import Decision, ProjectionExposureKind, ReasonCode
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.sql import analyze_sql


def _exposure(plan, output_name: str):
    matches = [
        exposure
        for exposure in plan.projected_exposures
        if exposure.output_name == output_name
    ]
    assert len(matches) == 1
    return matches[0]


def test_transformed_subject_identifier_retains_raw_lineage() -> None:
    plan = analyze_sql(
        """
        SELECT UPPER(c.customer_id) AS subject_token
        FROM customers c
        ORDER BY c.customer_id
        LIMIT 5
        """
    )

    exposure = _exposure(plan, "subject_token")
    assert exposure.kind == ProjectionExposureKind.TRANSFORMED_RAW_VALUE
    assert {ref.key for ref in exposure.source_columns} == {"customers.customer_id"}


def test_count_operand_is_cardinality_only_output() -> None:
    plan = analyze_sql(
        """
        SELECT COUNT(c.customer_id) AS customer_count
        FROM customers c
        """
    )

    exposure = _exposure(plan, "customer_count")
    assert exposure.kind == ProjectionExposureKind.AGGREGATE_VALUE
    assert {ref.key for ref in exposure.source_columns} == {"customers.customer_id"}


def test_min_identifier_remains_value_exposing_aggregate_operand() -> None:
    plan = analyze_sql(
        """
        SELECT MIN(c.customer_id) AS min_customer_id
        FROM customers c
        """
    )

    exposure = _exposure(plan, "min_customer_id")
    assert exposure.kind == ProjectionExposureKind.AGGREGATE_OPERAND
    assert {ref.key for ref in exposure.source_columns} == {"customers.customer_id"}


def test_min_identifier_exposure_survives_cte_boundary() -> None:
    plan = analyze_sql(
        """
        WITH aggregated AS (
          SELECT MIN(customer_id) AS min_customer_id
          FROM customers
        )
        SELECT aggregated.min_customer_id
        FROM aggregated
        """
    )

    exposure = _exposure(plan, "min_customer_id")
    assert exposure.kind == ProjectionExposureKind.AGGREGATE_OPERAND
    assert {ref.key for ref in exposure.source_columns} == {"customers.customer_id"}


def test_transformed_identifier_lineage_survives_cte_boundary() -> None:
    plan = analyze_sql(
        """
        WITH transformed AS (
          SELECT UPPER(customer_id) AS subject_token
          FROM customers
        )
        SELECT transformed.subject_token
        FROM transformed
        LIMIT 5
        """
    )

    exposure = _exposure(plan, "subject_token")
    assert exposure.kind == ProjectionExposureKind.TRANSFORMED_RAW_VALUE
    assert {ref.key for ref in exposure.source_columns} == {"customers.customer_id"}


def test_policy_v02_blocks_pseudonym_plus_sensitive_without_quasi_identifiers() -> None:
    sql = """
    SELECT c.customer_id, r.churn_score
    FROM customers c
    JOIN retention_scores r ON c.customer_id = r.customer_id
    LIMIT 5
    """.strip()
    plan = analyze_sql(sql)
    resolver = FixtureContextResolver(default_fixture_catalog())
    context = resolver.resolve(plan)
    decision = PolicyEngine(load_policy()).evaluate(
        context.to_policy_input(
            task_purpose="Regression: individual pseudonym plus sensitive value",
            query_plan=plan,
            subject_key=next(
                ref for ref in plan.projected_columns if ref.key == "customers.customer_id"
            ),
        )
    )

    assert decision.decision == Decision.BLOCK
    assert ReasonCode.COMPOSITIONAL_REIDENTIFICATION_RISK in decision.reason_codes


def test_transformed_subject_identifier_is_in_semantic_policy_evidence() -> None:
    sql = """
    SELECT UPPER(c.customer_id) AS subject_token, r.churn_score
    FROM customers c
    JOIN retention_scores r ON c.customer_id = r.customer_id
    LIMIT 5
    """.strip()
    plan = analyze_sql(sql)
    resolver = FixtureContextResolver(default_fixture_catalog())
    context = resolver.resolve(plan)
    subject_key = next(
        ref for ref in plan.projected_columns if ref.key == "customers.customer_id"
    )
    decision = PolicyEngine(load_policy()).evaluate(
        context.to_policy_input(
            task_purpose="Regression: wrapped identifier exposure",
            query_plan=plan,
            subject_key=subject_key,
        )
    )

    assert decision.decision == Decision.BLOCK
    assert ReasonCode.COMPOSITIONAL_REIDENTIFICATION_RISK in decision.reason_codes
    assert any(
        exposure["kind"] == ProjectionExposureKind.TRANSFORMED_RAW_VALUE.value
        for exposure in decision.evidence["projected_exposures"]
    )
