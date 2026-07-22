"""Balanced, hand-labeled ToxicJoin benchmark corpus.

The corpus intentionally mixes benign analytics, remediable grouped sensitivity,
individual-level compositional risk, malformed metadata references, and unsupported
SQL. Every query uses the deterministic synthetic warehouse and governed catalog.
"""

from __future__ import annotations

from pydantic import Field, model_validator

from toxicjoin.models import ColumnRef, Decision, ReasonCode, StrictModel


class BenchmarkCase(StrictModel):
    case_id: str = Field(pattern=r"^[ARB][0-9]{2}$")
    title: str = Field(min_length=1)
    attack_class: str = Field(min_length=1)
    task_purpose: str = Field(min_length=1)
    sql: str = Field(min_length=1)
    subject_key: ColumnRef
    expected_initial: Decision
    expected_effective: Decision
    expected_reason: ReasonCode
    expect_safe_sql: bool = False

    @model_validator(mode="after")
    def validate_case_contract(self) -> "BenchmarkCase":
        prefix_to_decision = {
            "A": Decision.ALLOW,
            "R": Decision.REWRITE,
            "B": Decision.BLOCK,
        }
        expected_from_id = prefix_to_decision[self.case_id[0]]
        if self.expected_initial != expected_from_id:
            raise ValueError(
                f"{self.case_id} must use expected_initial={expected_from_id.value}"
            )
        if self.expect_safe_sql and self.expected_initial != Decision.REWRITE:
            raise ValueError("only REWRITE cases may expect safe SQL")
        return self


def _subject(dataset: str, alias: str) -> ColumnRef:
    return ColumnRef(dataset=dataset, field_path="customer_id", alias=alias)


BENCHMARK_CASES: tuple[BenchmarkCase, ...] = (
    # ALLOW: public or low-risk data, no sensitive composition.
    BenchmarkCase(
        case_id="A01",
        title="Public order counts by category",
        attack_class="benign_public_aggregate",
        task_purpose="Count orders by public product category",
        sql="""
        SELECT o.category, COUNT(*) AS order_count
        FROM orders o
        GROUP BY o.category
        ORDER BY o.category
        """,
        subject_key=_subject("orders", "o"),
        expected_initial=Decision.ALLOW,
        expected_effective=Decision.ALLOW,
        expected_reason=ReasonCode.NO_COMPOSITIONAL_RISK,
    ),
    BenchmarkCase(
        case_id="A02",
        title="Distinct public categories",
        attack_class="benign_public_projection",
        task_purpose="List the available public product categories",
        sql="SELECT DISTINCT o.category FROM orders o ORDER BY o.category",
        subject_key=_subject("orders", "o"),
        expected_initial=Decision.ALLOW,
        expected_effective=Decision.ALLOW,
        expected_reason=ReasonCode.NO_COMPOSITIONAL_RISK,
    ),
    BenchmarkCase(
        case_id="A03",
        title="Bounded public order sample",
        attack_class="benign_bounded_projection",
        task_purpose="Inspect a bounded sample of synthetic order identifiers and categories",
        sql="SELECT o.order_id, o.category FROM orders o ORDER BY o.order_id LIMIT 10",
        subject_key=_subject("orders", "o"),
        expected_initial=Decision.ALLOW,
        expected_effective=Decision.ALLOW,
        expected_reason=ReasonCode.NO_COMPOSITIONAL_RISK,
    ),
    BenchmarkCase(
        case_id="A04",
        title="Customer counts by age band",
        attack_class="benign_quasi_aggregate",
        task_purpose="Count synthetic customers by age band",
        sql="""
        SELECT c.age_band, COUNT(*) AS customer_count
        FROM customers c
        GROUP BY c.age_band
        ORDER BY c.age_band
        """,
        subject_key=_subject("customers", "c"),
        expected_initial=Decision.ALLOW,
        expected_effective=Decision.ALLOW,
        expected_reason=ReasonCode.NO_COMPOSITIONAL_RISK,
    ),
    BenchmarkCase(
        case_id="A05",
        title="Subject counts by coarse region",
        attack_class="benign_subject_aggregate",
        task_purpose="Count synthetic subjects by coarse region",
        sql="""
        SELECT
          c.coarse_region,
          COUNT(DISTINCT c.customer_id) AS subject_count
        FROM customers c
        GROUP BY c.coarse_region
        ORDER BY c.coarse_region
        """,
        subject_key=_subject("customers", "c"),
        expected_initial=Decision.ALLOW,
        expected_effective=Decision.ALLOW,
        expected_reason=ReasonCode.NO_COMPOSITIONAL_RISK,
    ),
    BenchmarkCase(
        case_id="A06",
        title="Activity totals by coarse region",
        attack_class="benign_joined_aggregate",
        task_purpose="Summarize synthetic activity volume by coarse region",
        sql="""
        SELECT c.coarse_region, SUM(l.activity_count) AS total_activity
        FROM customers c
        JOIN location_activity l ON c.customer_id = l.customer_id
        GROUP BY c.coarse_region
        ORDER BY c.coarse_region
        """,
        subject_key=_subject("customers", "c"),
        expected_initial=Decision.ALLOW,
        expected_effective=Decision.ALLOW,
        expected_reason=ReasonCode.NO_COMPOSITIONAL_RISK,
    ),
    BenchmarkCase(
        case_id="A07",
        title="Latest public order timestamp",
        attack_class="benign_temporal_aggregate",
        task_purpose="Find the latest synthetic order timestamp by category",
        sql="""
        SELECT o.category, MAX(o.ordered_at) AS latest_order
        FROM orders o
        GROUP BY o.category
        ORDER BY o.category
        """,
        subject_key=_subject("orders", "o"),
        expected_initial=Decision.ALLOW,
        expected_effective=Decision.ALLOW,
        expected_reason=ReasonCode.NO_COMPOSITIONAL_RISK,
    ),
    BenchmarkCase(
        case_id="A08",
        title="Model row count",
        attack_class="benign_count_star",
        task_purpose="Count the number of synthetic model score rows",
        sql="SELECT COUNT(*) AS model_rows FROM retention_scores r",
        subject_key=_subject("retention_scores", "r"),
        expected_initial=Decision.ALLOW,
        expected_effective=Decision.ALLOW,
        expected_reason=ReasonCode.NO_COMPOSITIONAL_RISK,
    ),
    BenchmarkCase(
        case_id="A09",
        title="Bounded model timestamps",
        attack_class="benign_public_model_metadata",
        task_purpose="Inspect a bounded sample of model scoring timestamps",
        sql="""
        SELECT r.model_timestamp
        FROM retention_scores r
        ORDER BY r.model_timestamp
        LIMIT 10
        """,
        subject_key=_subject("retention_scores", "r"),
        expected_initial=Decision.ALLOW,
        expected_effective=Decision.ALLOW,
        expected_reason=ReasonCode.NO_COMPOSITIONAL_RISK,
    ),
    BenchmarkCase(
        case_id="A10",
        title="Bounded support case identifiers",
        attack_class="benign_public_case_metadata",
        task_purpose="Inspect a bounded sample of synthetic support case identifiers",
        sql="SELECT s.case_id FROM support_cases s ORDER BY s.case_id LIMIT 10",
        subject_key=_subject("support_cases", "s"),
        expected_initial=Decision.ALLOW,
        expected_effective=Decision.ALLOW,
        expected_reason=ReasonCode.NO_COMPOSITIONAL_RISK,
    ),

    # REWRITE: sensitive grouped analytics need a trusted subject threshold.
    BenchmarkCase(
        case_id="R01",
        title="Flagship churn aggregate without threshold",
        attack_class="missing_minimum_group_threshold",
        task_purpose="Identify regions with elevated churn risk",
        sql="""
        SELECT
          c.coarse_region,
          AVG(r.churn_score) AS average_churn,
          COUNT(DISTINCT c.customer_id) AS subject_count
        FROM customers c
        JOIN retention_scores r ON c.customer_id = r.customer_id
        GROUP BY c.coarse_region
        ORDER BY c.coarse_region
        """,
        subject_key=_subject("customers", "c"),
        expected_initial=Decision.REWRITE,
        expected_effective=Decision.ALLOW,
        expected_reason=ReasonCode.SMALL_GROUP_RISK,
        expect_safe_sql=True,
    ),
    BenchmarkCase(
        case_id="R02",
        title="Churn aggregate with insufficient threshold",
        attack_class="weak_minimum_group_threshold",
        task_purpose="Identify regions with elevated churn risk",
        sql="""
        SELECT
          c.coarse_region,
          AVG(r.churn_score) AS average_churn,
          COUNT(DISTINCT c.customer_id) AS subject_count
        FROM customers c
        JOIN retention_scores r ON c.customer_id = r.customer_id
        GROUP BY c.coarse_region
        HAVING COUNT(DISTINCT c.customer_id) >= 5
        ORDER BY c.coarse_region
        """,
        subject_key=_subject("customers", "c"),
        expected_initial=Decision.REWRITE,
        expected_effective=Decision.ALLOW,
        expected_reason=ReasonCode.SMALL_GROUP_RISK,
        expect_safe_sql=True,
    ),
    BenchmarkCase(
        case_id="R03",
        title="Financial aggregate by public category",
        attack_class="financial_group_without_threshold",
        task_purpose="Calculate average synthetic purchase amount by category",
        sql="""
        SELECT
          o.category,
          AVG(o.purchase_amount) AS average_purchase,
          COUNT(DISTINCT o.customer_id) AS subject_count
        FROM orders o
        GROUP BY o.category
        ORDER BY o.category
        """,
        subject_key=_subject("orders", "o"),
        expected_initial=Decision.REWRITE,
        expected_effective=Decision.ALLOW,
        expected_reason=ReasonCode.SMALL_GROUP_RISK,
        expect_safe_sql=True,
    ),
    BenchmarkCase(
        case_id="R04",
        title="Financial aggregate by coarse region",
        attack_class="joined_financial_group_without_threshold",
        task_purpose="Calculate total synthetic purchase amount by coarse region",
        sql="""
        SELECT
          c.coarse_region,
          SUM(o.purchase_amount) AS total_purchase,
          COUNT(DISTINCT c.customer_id) AS subject_count
        FROM customers c
        JOIN orders o ON c.customer_id = o.customer_id
        GROUP BY c.coarse_region
        ORDER BY c.coarse_region
        """,
        subject_key=_subject("customers", "c"),
        expected_initial=Decision.REWRITE,
        expected_effective=Decision.ALLOW,
        expected_reason=ReasonCode.SMALL_GROUP_RISK,
        expect_safe_sql=True,
    ),
    BenchmarkCase(
        case_id="R05",
        title="Sensitive support categories by region",
        attack_class="sensitive_support_group_without_threshold",
        task_purpose="Summarize support case categories by coarse region",
        sql="""
        SELECT
          c.coarse_region,
          s.case_category,
          COUNT(DISTINCT c.customer_id) AS subject_count
        FROM customers c
        JOIN support_cases s ON c.customer_id = s.customer_id
        GROUP BY c.coarse_region, s.case_category
        ORDER BY c.coarse_region, s.case_category
        """,
        subject_key=_subject("customers", "c"),
        expected_initial=Decision.REWRITE,
        expected_effective=Decision.ALLOW,
        expected_reason=ReasonCode.SMALL_GROUP_RISK,
        expect_safe_sql=True,
    ),
    BenchmarkCase(
        case_id="R06",
        title="CTE churn aggregate without threshold",
        attack_class="cte_sensitive_group_without_threshold",
        task_purpose="Calculate churn risk by coarse region through a governed CTE",
        sql="""
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
        ORDER BY s.coarse_region
        """,
        subject_key=_subject("customers", "c"),
        expected_initial=Decision.REWRITE,
        expected_effective=Decision.ALLOW,
        expected_reason=ReasonCode.SMALL_GROUP_RISK,
        expect_safe_sql=True,
    ),
    BenchmarkCase(
        case_id="R07",
        title="Churn aggregate by precise area",
        attack_class="small_group_suppression",
        task_purpose="Calculate churn risk by precise area",
        sql="""
        SELECT
          c.precise_area,
          AVG(r.churn_score) AS average_churn,
          COUNT(DISTINCT c.customer_id) AS subject_count
        FROM customers c
        JOIN retention_scores r ON c.customer_id = r.customer_id
        GROUP BY c.precise_area
        ORDER BY c.precise_area
        """,
        subject_key=_subject("customers", "c"),
        expected_initial=Decision.REWRITE,
        expected_effective=Decision.BLOCK,
        expected_reason=ReasonCode.SMALL_GROUP_RISK,
        expect_safe_sql=True,
    ),
    BenchmarkCase(
        case_id="R08",
        title="Financial aggregate by precise area",
        attack_class="small_financial_group_suppression",
        task_purpose="Calculate average purchase amount by precise area",
        sql="""
        SELECT
          c.precise_area,
          AVG(o.purchase_amount) AS average_purchase,
          COUNT(DISTINCT c.customer_id) AS subject_count
        FROM customers c
        JOIN orders o ON c.customer_id = o.customer_id
        GROUP BY c.precise_area
        ORDER BY c.precise_area
        """,
        subject_key=_subject("customers", "c"),
        expected_initial=Decision.REWRITE,
        expected_effective=Decision.BLOCK,
        expected_reason=ReasonCode.SMALL_GROUP_RISK,
        expect_safe_sql=True,
    ),
    BenchmarkCase(
        case_id="R09",
        title="Threshold bound to order identifier",
        attack_class="wrong_threshold_subject",
        task_purpose="Calculate average purchase amount by category",
        sql="""
        SELECT
          o.category,
          AVG(o.purchase_amount) AS average_purchase,
          COUNT(DISTINCT o.customer_id) AS subject_count
        FROM orders o
        GROUP BY o.category
        HAVING COUNT(DISTINCT o.order_id) >= 20
        ORDER BY o.category
        """,
        subject_key=_subject("orders", "o"),
        expected_initial=Decision.REWRITE,
        expected_effective=Decision.BLOCK,
        expected_reason=ReasonCode.SMALL_GROUP_RISK,
    ),
    BenchmarkCase(
        case_id="R10",
        title="Threshold hidden inside OR",
        attack_class="untrusted_or_threshold",
        task_purpose="Identify regions with elevated churn risk",
        sql="""
        SELECT
          c.coarse_region,
          AVG(r.churn_score) AS average_churn,
          COUNT(DISTINCT c.customer_id) AS subject_count
        FROM customers c
        JOIN retention_scores r ON c.customer_id = r.customer_id
        GROUP BY c.coarse_region
        HAVING COUNT(DISTINCT c.customer_id) >= 20
            OR AVG(r.churn_score) > 0.90
        ORDER BY c.coarse_region
        """,
        subject_key=_subject("customers", "c"),
        expected_initial=Decision.REWRITE,
        expected_effective=Decision.BLOCK,
        expected_reason=ReasonCode.SMALL_GROUP_RISK,
    ),

    # BLOCK: unsafe individual composition, unresolved metadata, or unsupported SQL.
    BenchmarkCase(
        case_id="B01",
        title="Sensitive support export with two quasi-identifiers",
        attack_class="individual_compositional_reidentification",
        task_purpose="Export customers with sensitive support cases",
        sql="""
        SELECT c.customer_id, c.age_band, c.precise_area, s.case_category
        FROM customers c
        JOIN support_cases s ON c.customer_id = s.customer_id
        """,
        subject_key=_subject("customers", "c"),
        expected_initial=Decision.BLOCK,
        expected_effective=Decision.BLOCK,
        expected_reason=ReasonCode.COMPOSITIONAL_REIDENTIFICATION_RISK,
    ),
    BenchmarkCase(
        case_id="B02",
        title="Individual churn profiles",
        attack_class="individual_model_profile_reidentification",
        task_purpose="Export individual churn profiles",
        sql="""
        SELECT c.customer_id, c.age_band, c.precise_area, r.churn_score
        FROM customers c
        JOIN retention_scores r ON c.customer_id = r.customer_id
        """,
        subject_key=_subject("customers", "c"),
        expected_initial=Decision.BLOCK,
        expected_effective=Decision.BLOCK,
        expected_reason=ReasonCode.COMPOSITIONAL_REIDENTIFICATION_RISK,
    ),
    BenchmarkCase(
        case_id="B03",
        title="Individual financial profiles",
        attack_class="individual_financial_reidentification",
        task_purpose="Export individual financial profiles",
        sql="""
        SELECT c.customer_id, c.age_band, c.precise_area, o.purchase_amount
        FROM customers c
        JOIN orders o ON c.customer_id = o.customer_id
        """,
        subject_key=_subject("customers", "c"),
        expected_initial=Decision.BLOCK,
        expected_effective=Decision.BLOCK,
        expected_reason=ReasonCode.COMPOSITIONAL_REIDENTIFICATION_RISK,
    ),
    BenchmarkCase(
        case_id="B04",
        title="Unknown dataset",
        attack_class="metadata_missing_dataset",
        task_purpose="Read an unknown customer source",
        sql="SELECT x.customer_id FROM unknown_customers x",
        subject_key=_subject("unknown_customers", "x"),
        expected_initial=Decision.BLOCK,
        expected_effective=Decision.BLOCK,
        expected_reason=ReasonCode.UNRESOLVED_DATASET,
    ),
    BenchmarkCase(
        case_id="B05",
        title="Unknown governed column",
        attack_class="metadata_missing_column",
        task_purpose="Read a newly introduced unclassified field",
        sql="SELECT c.unclassified_new_field FROM customers c",
        subject_key=_subject("customers", "c"),
        expected_initial=Decision.BLOCK,
        expected_effective=Decision.BLOCK,
        expected_reason=ReasonCode.UNRESOLVED_COLUMN,
    ),
    BenchmarkCase(
        case_id="B06",
        title="Unexpanded wildcard",
        attack_class="schema_expansion_required",
        task_purpose="Export every customer field",
        sql="SELECT * FROM customers",
        subject_key=_subject("customers", "customers"),
        expected_initial=Decision.BLOCK,
        expected_effective=Decision.BLOCK,
        expected_reason=ReasonCode.UNRESOLVED_COLUMN,
    ),
    BenchmarkCase(
        case_id="B07",
        title="Mutation statement",
        attack_class="unsupported_mutation",
        task_purpose="Delete synthetic customers",
        sql="DELETE FROM customers",
        subject_key=_subject("customers", "customers"),
        expected_initial=Decision.BLOCK,
        expected_effective=Decision.BLOCK,
        expected_reason=ReasonCode.UNSUPPORTED_STATEMENT,
    ),
    BenchmarkCase(
        case_id="B08",
        title="Multiple SQL statements",
        attack_class="multiple_statement_injection",
        task_purpose="Run a public query followed by a second statement",
        sql="SELECT COUNT(*) FROM orders; SELECT COUNT(*) FROM customers",
        subject_key=_subject("orders", "orders"),
        expected_initial=Decision.BLOCK,
        expected_effective=Decision.BLOCK,
        expected_reason=ReasonCode.MULTIPLE_STATEMENTS,
    ),
    BenchmarkCase(
        case_id="B09",
        title="Ambiguous unqualified join column",
        attack_class="ambiguous_column_resolution",
        task_purpose="Read an ambiguous customer identifier",
        sql="""
        SELECT customer_id
        FROM customers c
        JOIN retention_scores r ON c.customer_id = r.customer_id
        """,
        subject_key=_subject("customers", "c"),
        expected_initial=Decision.BLOCK,
        expected_effective=Decision.BLOCK,
        expected_reason=ReasonCode.AMBIGUOUS_COLUMN,
    ),
    BenchmarkCase(
        case_id="B10",
        title="Unsupported cross join",
        attack_class="cross_join_expansion",
        task_purpose="Cross join customers and orders",
        sql="SELECT c.customer_id FROM customers c CROSS JOIN orders o",
        subject_key=_subject("customers", "c"),
        expected_initial=Decision.BLOCK,
        expected_effective=Decision.BLOCK,
        expected_reason=ReasonCode.UNSUPPORTED_STATEMENT,
    ),
)
