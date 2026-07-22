from __future__ import annotations

from pathlib import Path

from toxicjoin.context import FixtureContextResolver
from toxicjoin.models import ColumnRef, Decision, ReasonCode, SensitivityCategory
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.sql import analyze_sql


ROOT = Path(__file__).parents[2]
CATALOG = ROOT / "demo" / "fixtures" / "catalog.json"
SUBJECT = ColumnRef(dataset="customers", field_path="customer_id", alias="c")


def _resolver() -> FixtureContextResolver:
    return FixtureContextResolver.from_path(CATALOG)


def _engine() -> PolicyEngine:
    return PolicyEngine(load_policy())


def test_resolves_governed_context_with_datahub_identifiers() -> None:
    plan = analyze_sql(
        """
        SELECT c.customer_id, c.age_band, c.precise_area, s.case_category
        FROM customers c
        JOIN support_cases s ON c.customer_id = s.customer_id
        """
    )

    resolution = _resolver().resolve(plan)

    assert resolution.failures == ()
    by_key = {context.ref.key: context for context in resolution.projected_context}
    assert by_key["customers.customer_id"].category == SensitivityCategory.STABLE_PSEUDONYM
    assert by_key["customers.age_band"].category == SensitivityCategory.QUASI_IDENTIFIER
    assert by_key["customers.precise_area"].category == SensitivityCategory.QUASI_IDENTIFIER
    assert (
        by_key["support_cases.case_category"].category
        == SensitivityCategory.SENSITIVE_ATTRIBUTE
    )
    assert all(context.datahub_urn for context in resolution.projected_context)


def test_compositional_individual_query_blocks() -> None:
    plan = analyze_sql(
        """
        SELECT c.customer_id, c.age_band, c.precise_area, s.case_category
        FROM customers c
        JOIN support_cases s ON c.customer_id = s.customer_id
        """
    )
    resolution = _resolver().resolve(plan)

    decision = _engine().evaluate(
        resolution.to_policy_input(
            task_purpose="Export customers with sensitive support cases",
            query_plan=plan,
            subject_key=SUBJECT,
        )
    )

    assert decision.decision == Decision.BLOCK
    assert ReasonCode.COMPOSITIONAL_REIDENTIFICATION_RISK in decision.reason_codes


def test_sensitive_grouped_query_rewrites_without_threshold() -> None:
    plan = analyze_sql(
        """
        SELECT
          c.coarse_region,
          AVG(r.churn_score) AS average_churn,
          COUNT(DISTINCT c.customer_id) AS subject_count
        FROM customers c
        JOIN retention_scores r ON c.customer_id = r.customer_id
        GROUP BY c.coarse_region
        """
    )
    resolution = _resolver().resolve(plan)

    decision = _engine().evaluate(
        resolution.to_policy_input(
            task_purpose="Find regions with elevated churn risk",
            query_plan=plan,
            subject_key=SUBJECT,
        )
    )

    assert decision.decision == Decision.REWRITE
    assert decision.reason_codes == (ReasonCode.SMALL_GROUP_RISK,)
    assert decision.rewrite_required is True


def test_sensitive_grouped_query_allows_with_required_threshold() -> None:
    plan = analyze_sql(
        """
        SELECT
          c.coarse_region,
          AVG(r.churn_score) AS average_churn,
          COUNT(DISTINCT c.customer_id) AS subject_count
        FROM customers c
        JOIN retention_scores r ON c.customer_id = r.customer_id
        GROUP BY c.coarse_region
        HAVING COUNT(DISTINCT c.customer_id) >= 20
        """
    )
    resolution = _resolver().resolve(plan)

    decision = _engine().evaluate(
        resolution.to_policy_input(
            task_purpose="Find regions with elevated churn risk",
            query_plan=plan,
            subject_key=SUBJECT,
        )
    )

    assert plan.minimum_group_size_present == 20
    assert plan.minimum_group_size_subject is not None
    assert plan.minimum_group_size_subject.key == SUBJECT.key
    assert decision.decision == Decision.ALLOW
    assert decision.reason_codes == (ReasonCode.NO_COMPOSITIONAL_RISK,)


def test_missing_dataset_fails_closed() -> None:
    plan = analyze_sql("SELECT x.customer_id FROM unknown_customers x")
    resolution = _resolver().resolve(plan)

    assert ReasonCode.UNRESOLVED_DATASET in resolution.failures
    assert resolution.projected_context[0].resolved is False

    decision = _engine().evaluate(
        resolution.to_policy_input(
            task_purpose="Unknown data request",
            query_plan=plan,
            subject_key=SUBJECT,
        )
    )
    assert decision.decision == Decision.BLOCK
    assert ReasonCode.UNRESOLVED_DATASET in decision.reason_codes


def test_missing_column_fails_closed() -> None:
    plan = analyze_sql("SELECT c.unclassified_new_field FROM customers c")
    resolution = _resolver().resolve(plan)

    assert ReasonCode.UNRESOLVED_COLUMN in resolution.failures
    assert resolution.projected_context[0].category == SensitivityCategory.UNCLASSIFIED


def test_select_star_fails_closed_until_schema_expansion_exists() -> None:
    plan = analyze_sql("SELECT * FROM customers")
    resolution = _resolver().resolve(plan)

    assert ReasonCode.UNRESOLVED_COLUMN in resolution.failures
