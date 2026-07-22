from pathlib import Path

from toxicjoin.models import (
    ColumnContext,
    ColumnRef,
    Decision,
    PolicyInput,
    QueryPlan,
    ReasonCode,
    SensitivityCategory,
)
from toxicjoin.policy import PolicyEngine, load_policy


POLICY_PATH = Path(__file__).parents[2] / "src/toxicjoin/policy/policy.yaml"


def ref(dataset: str, field: str) -> ColumnRef:
    return ColumnRef(dataset=dataset, field_path=field)


def context(
    dataset: str,
    field: str,
    category: SensitivityCategory,
    *,
    resolved: bool = True,
) -> ColumnContext:
    return ColumnContext(
        ref=ref(dataset, field),
        category=category,
        resolved=resolved,
    )


def build_input(
    projected: tuple[ColumnContext, ...],
    *,
    referenced: tuple[ColumnContext, ...] | None = None,
    grouped: bool = False,
    threshold: int | None = None,
) -> PolicyInput:
    refs = tuple(item.ref for item in projected)
    return PolicyInput(
        task_purpose="Test governed analytics",
        query_plan=QueryPlan(
            statement_type="SELECT",
            source_datasets=("demo",),
            projected_columns=refs,
            is_grouped=grouped,
        ),
        projected_context=projected,
        all_referenced_context=referenced or projected,
        minimum_group_size_present=threshold,
    )


def engine() -> PolicyEngine:
    return PolicyEngine(load_policy(POLICY_PATH))


def test_direct_identifier_plus_sensitive_attribute_blocks() -> None:
    result = engine().evaluate(
        build_input(
            (
                context("customers", "email", SensitivityCategory.DIRECT_IDENTIFIER),
                context(
                    "support_cases",
                    "case_category",
                    SensitivityCategory.SENSITIVE_ATTRIBUTE,
                ),
            )
        )
    )

    assert result.decision == Decision.BLOCK
    assert ReasonCode.DIRECT_SENSITIVE_LINKAGE in result.reason_codes


def test_pseudonym_quasi_identifiers_and_sensitive_attribute_block() -> None:
    result = engine().evaluate(
        build_input(
            (
                context(
                    "customers",
                    "customer_id",
                    SensitivityCategory.STABLE_PSEUDONYM,
                ),
                context("customers", "age_band", SensitivityCategory.QUASI_IDENTIFIER),
                context("customers", "precise_area", SensitivityCategory.QUASI_IDENTIFIER),
                context(
                    "retention_scores",
                    "churn_score",
                    SensitivityCategory.SENSITIVE_ATTRIBUTE,
                ),
            )
        )
    )

    assert result.decision == Decision.BLOCK
    assert ReasonCode.COMPOSITIONAL_REIDENTIFICATION_RISK in result.reason_codes


def test_sensitive_grouped_output_without_threshold_rewrites() -> None:
    result = engine().evaluate(
        build_input(
            (
                context("customers", "region", SensitivityCategory.QUASI_IDENTIFIER),
                context(
                    "retention_scores",
                    "avg_churn_score",
                    SensitivityCategory.SENSITIVE_ATTRIBUTE,
                ),
            ),
            grouped=True,
        )
    )

    assert result.decision == Decision.REWRITE
    assert result.rewrite_required is True
    assert result.reason_codes == (ReasonCode.SMALL_GROUP_RISK,)


def test_sensitive_grouped_output_with_threshold_allows() -> None:
    result = engine().evaluate(
        build_input(
            (
                context("customers", "region", SensitivityCategory.QUASI_IDENTIFIER),
                context(
                    "retention_scores",
                    "avg_churn_score",
                    SensitivityCategory.SENSITIVE_ATTRIBUTE,
                ),
            ),
            grouped=True,
            threshold=20,
        )
    )

    assert result.decision == Decision.ALLOW


def test_unclassified_column_fails_closed() -> None:
    result = engine().evaluate(
        build_input(
            (
                context(
                    "mystery",
                    "unknown_field",
                    SensitivityCategory.UNCLASSIFIED,
                    resolved=False,
                ),
            )
        )
    )

    assert result.decision == Decision.BLOCK
    assert ReasonCode.UNCLASSIFIED_COLUMN in result.reason_codes
