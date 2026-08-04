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


def ref(dataset: str, field: str, *, alias: str | None = None) -> ColumnRef:
    return ColumnRef(dataset=dataset, field_path=field, alias=alias)


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
    threshold_subject: ColumnRef | None = None,
    expected_subject: ColumnRef | None = None,
    subject_category: SensitivityCategory = SensitivityCategory.STABLE_PSEUDONYM,
) -> PolicyInput:
    refs = tuple(item.ref for item in projected)
    if grouped and expected_subject is None:
        expected_subject = ref("customers", "customer_id")
    if threshold is not None and threshold_subject is None:
        threshold_subject = expected_subject

    # A query that counts a subject necessarily references it, and the policy engine now
    # reads the subject's governed category from the resolved context. Model that here so
    # threshold tests exercise the threshold rather than an unresolved subject.
    resolved_referenced = referenced if referenced is not None else projected
    if expected_subject is not None and not any(
        item.ref.key == expected_subject.key for item in resolved_referenced
    ):
        resolved_referenced = resolved_referenced + (
            context(
                expected_subject.dataset,
                expected_subject.field_path,
                subject_category,
            ),
        )

    return PolicyInput(
        task_purpose="Test governed analytics",
        query_plan=QueryPlan(
            statement_type="SELECT",
            source_datasets=("demo",),
            projected_columns=refs,
            minimum_group_size_present=threshold,
            minimum_group_size_subject=threshold_subject,
            is_grouped=grouped,
        ),
        projected_context=projected,
        all_referenced_context=resolved_referenced,
        subject_key=expected_subject,
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


def test_sensitive_grouped_output_with_trusted_threshold_allows() -> None:
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
    assert result.evidence["trusted_minimum_group_size"] == 20


def test_threshold_on_wrong_subject_rewrites() -> None:
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
            threshold_subject=ref("orders", "order_id"),
            expected_subject=ref("customers", "customer_id"),
        )
    )

    assert result.decision == Decision.REWRITE
    assert result.evidence["threshold_subject_matches"] is False


def test_non_identifier_subject_key_blocks_instead_of_trusting_threshold() -> None:
    """A public column cannot witness k-anonymity even when the threshold syntax is valid."""

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
            expected_subject=ref("orders", "order_id"),
            subject_category=SensitivityCategory.PUBLIC_OR_LOW_RISK,
        )
    )

    assert result.decision == Decision.BLOCK
    assert result.reason_codes == (ReasonCode.UNTRUSTED_SUBJECT_KEY,)
    assert result.evidence["subject_is_governed_identifier"] is False


def test_unresolved_subject_key_is_never_a_trusted_witness() -> None:
    """A subject absent from resolved governance cannot be trusted by default."""

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
            referenced=(
                context("customers", "region", SensitivityCategory.QUASI_IDENTIFIER),
                context(
                    "retention_scores",
                    "avg_churn_score",
                    SensitivityCategory.SENSITIVE_ATTRIBUTE,
                ),
                context(
                    "customers",
                    "customer_id",
                    SensitivityCategory.UNCLASSIFIED,
                    resolved=False,
                ),
            ),
            grouped=True,
            threshold=20,
        )
    )

    assert result.decision == Decision.BLOCK


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
