"""Deterministic compositional-risk policy engine."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from toxicjoin.models import (
    SUBJECT_IDENTIFIER_CATEGORIES,
    ColumnContext,
    ColumnRef,
    Decision,
    PolicyDecision,
    PolicyInput,
    ProjectionExposureKind,
    ReasonCode,
    SensitivityCategory,
)


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    version: str = Field(min_length=1)
    minimum_group_size: int = Field(ge=2)
    quasi_identifier_threshold: int = Field(ge=1)
    fail_closed: bool = True
    categories: tuple[SensitivityCategory, ...]


def default_policy_path() -> Path:
    """Return the canonical policy bundled with the ToxicJoin package."""

    return Path(__file__).with_name("policy.yaml")


def load_policy(path: str | Path | None = None) -> PolicyConfig:
    """Load and strictly validate a policy YAML file.

    Omitting ``path`` loads the package-owned canonical policy. This prevents
    callers and tests from depending on an unrelated repository-relative path.
    """

    policy_path = default_policy_path() if path is None else Path(path)
    try:
        raw = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"unable to read policy file: {policy_path}") from exc
    except yaml.YAMLError as exc:
        raise ValueError(f"invalid policy YAML: {policy_path}") from exc

    if not isinstance(raw, dict):
        raise ValueError("policy YAML root must be an object")
    return PolicyConfig.model_validate(raw)


class PolicyEngine:
    """Evaluate policy in a fixed priority order: BLOCK > REWRITE > ALLOW."""

    def __init__(self, config: PolicyConfig) -> None:
        self.config = config

    def evaluate(self, policy_input: PolicyInput) -> PolicyDecision:
        block_reasons = list(policy_input.upstream_failures)
        categories = [column.category for column in policy_input.projected_context]
        referenced_categories = [
            column.category for column in policy_input.all_referenced_context
        ]
        effective_projected_categories = _effective_categories(
            policy_input.projected_context
        )
        effective_referenced_categories = _effective_categories(
            policy_input.all_referenced_context
        )

        unresolved = [
            column.ref.key
            for column in policy_input.all_referenced_context
            if not column.resolved
            or column.category == SensitivityCategory.UNCLASSIFIED
            or any(
                source.category == SensitivityCategory.UNCLASSIFIED
                for source in column.lineage_sources
            )
        ]
        if unresolved and self.config.fail_closed:
            block_reasons.append(ReasonCode.UNCLASSIFIED_COLUMN)

        semantic_context, semantic_mode = _semantic_projected_context(policy_input)
        semantic_categories = [column.category for column in semantic_context]
        effective_semantic_categories = _effective_categories(semantic_context)
        semantic_quasi_count = _category_count(
            semantic_context,
            SensitivityCategory.QUASI_IDENTIFIER,
        )

        if (
            semantic_mode
            and self.config.fail_closed
            and any(
                exposure.kind == ProjectionExposureKind.NESTED_SCOPE
                for exposure in policy_input.query_plan.projected_exposures
            )
        ):
            block_reasons.append(ReasonCode.UNRESOLVED_COLUMN)

        if _has_protected_conditional_aggregate(policy_input):
            block_reasons.append(ReasonCode.COMPOSITIONAL_REIDENTIFICATION_RISK)

        risk_categories = (
            effective_semantic_categories
            if semantic_mode
            else effective_projected_categories
        )
        has_direct = SensitivityCategory.DIRECT_IDENTIFIER in risk_categories
        has_pseudonym = SensitivityCategory.STABLE_PSEUDONYM in risk_categories
        has_sensitive = SensitivityCategory.SENSITIVE_ATTRIBUTE in risk_categories
        quasi_count = (
            semantic_quasi_count
            if semantic_mode
            else _category_count(
                policy_input.projected_context,
                SensitivityCategory.QUASI_IDENTIFIER,
            )
        )

        if has_direct and has_sensitive:
            block_reasons.append(ReasonCode.DIRECT_SENSITIVE_LINKAGE)

        if not policy_input.query_plan.is_grouped and has_pseudonym and has_sensitive:
            if semantic_mode or quasi_count >= self.config.quasi_identifier_threshold:
                block_reasons.append(ReasonCode.COMPOSITIONAL_REIDENTIFICATION_RISK)

        if block_reasons:
            return PolicyDecision(
                decision=Decision.BLOCK,
                reason_codes=_deduplicate(block_reasons),
                policy_version=self.config.version,
                evidence=_decision_evidence(
                    policy_input=policy_input,
                    categories=categories,
                    semantic_categories=semantic_categories,
                    effective_projected_categories=effective_projected_categories,
                    effective_semantic_categories=effective_semantic_categories,
                    referenced_categories=referenced_categories,
                    effective_referenced_categories=effective_referenced_categories,
                    semantic_mode=semantic_mode,
                    unresolved=unresolved,
                    quasi_count=quasi_count,
                ),
            )

        sensitive_anywhere = (
            SensitivityCategory.SENSITIVE_ATTRIBUTE
            in effective_referenced_categories
        )
        threshold = policy_input.minimum_group_size_present
        expected_subject = policy_input.subject_key
        detected_subject = policy_input.query_plan.minimum_group_size_subject
        subject_category = _subject_governed_category(policy_input)
        # The caller declares subject_key, so it is untrusted input. A distinct-count over a
        # public field (order id, event id) satisfies the threshold syntax while leaving the
        # protected cohort arbitrarily small, so only a governed identifier may act as the
        # k-anonymity witness.
        subject_is_governed_identifier = subject_category in SUBJECT_IDENTIFIER_CATEGORIES
        threshold_subject_matches = (
            expected_subject is not None
            and detected_subject is not None
            and expected_subject.key == detected_subject.key
            and subject_is_governed_identifier
        )
        trusted_threshold = threshold if threshold_subject_matches else None

        if policy_input.query_plan.is_grouped and sensitive_anywhere:
            threshold_evidence = _threshold_evidence(
                threshold=threshold,
                expected_subject=expected_subject,
                detected_subject=detected_subject,
                subject_category=subject_category,
                subject_is_governed_identifier=subject_is_governed_identifier,
                threshold_subject_matches=threshold_subject_matches,
            )
            if not subject_is_governed_identifier:
                # No rewrite can repair this: the caller named a subject that governance does
                # not classify as an identifier, so counting it proves nothing about the
                # protected cohort. Report the declaration itself as the fault.
                return PolicyDecision(
                    decision=Decision.BLOCK,
                    reason_codes=(ReasonCode.UNTRUSTED_SUBJECT_KEY,),
                    policy_version=self.config.version,
                    evidence={
                        "required_minimum_group_size": self.config.minimum_group_size,
                        "required_subject_categories": sorted(
                            category.value for category in SUBJECT_IDENTIFIER_CATEGORIES
                        ),
                        **threshold_evidence,
                        "lineage_sources": _lineage_evidence(
                            policy_input.all_referenced_context
                        ),
                    },
                )
            if (
                trusted_threshold is None
                or trusted_threshold < self.config.minimum_group_size
            ):
                return PolicyDecision(
                    decision=Decision.REWRITE,
                    reason_codes=(ReasonCode.SMALL_GROUP_RISK,),
                    policy_version=self.config.version,
                    evidence={
                        "required_minimum_group_size": self.config.minimum_group_size,
                        **threshold_evidence,
                        "projected_exposures": [
                            exposure.model_dump(mode="json")
                            for exposure in policy_input.query_plan.projected_exposures
                        ],
                        "lineage_sources": _lineage_evidence(
                            policy_input.all_referenced_context
                        ),
                        "effective_referenced_categories": [
                            category.value
                            for category in effective_referenced_categories
                        ],
                    },
                    rewrite_required=True,
                )

        return PolicyDecision(
            decision=Decision.ALLOW,
            reason_codes=(ReasonCode.NO_COMPOSITIONAL_RISK,),
            policy_version=self.config.version,
            evidence={
                "projected_categories": [category.value for category in categories],
                "semantic_projected_categories": [
                    category.value for category in semantic_categories
                ],
                "effective_projected_categories": [
                    category.value for category in effective_projected_categories
                ],
                "effective_semantic_projected_categories": [
                    category.value for category in effective_semantic_categories
                ],
                "semantic_exposure_mode": semantic_mode,
                "projected_exposures": [
                    exposure.model_dump(mode="json")
                    for exposure in policy_input.query_plan.projected_exposures
                ],
                "referenced_categories": [
                    category.value for category in referenced_categories
                ],
                "effective_referenced_categories": [
                    category.value for category in effective_referenced_categories
                ],
                "lineage_sources": _lineage_evidence(
                    policy_input.all_referenced_context
                ),
                "trusted_minimum_group_size": trusted_threshold,
                "trusted_threshold_subject": (
                    detected_subject.key if threshold_subject_matches else None
                ),
                **_threshold_evidence(
                    threshold=threshold,
                    expected_subject=expected_subject,
                    detected_subject=detected_subject,
                    subject_category=subject_category,
                    subject_is_governed_identifier=subject_is_governed_identifier,
                    threshold_subject_matches=threshold_subject_matches,
                ),
            },
        )


def _subject_governed_category(
    policy_input: PolicyInput,
) -> SensitivityCategory | None:
    """Return the governed category of the declared subject key, if it is resolved.

    The subject is looked up in the same resolved context the rest of the decision uses, so
    a caller cannot name a field that governance never classified. An unreferenced or
    unresolved subject returns ``None`` and therefore never yields a trusted threshold.
    """

    subject = policy_input.subject_key
    if subject is None:
        return None
    for column in policy_input.all_referenced_context:
        if column.ref.key == subject.key:
            return column.category if column.resolved else None
    return None


def _threshold_evidence(
    *,
    threshold: int | None,
    expected_subject: ColumnRef | None,
    detected_subject: ColumnRef | None,
    subject_category: SensitivityCategory | None,
    subject_is_governed_identifier: bool,
    threshold_subject_matches: bool,
) -> dict[str, object]:
    return {
        "detected_minimum_group_size": threshold,
        "expected_subject_key": (
            expected_subject.key if expected_subject is not None else None
        ),
        "detected_threshold_subject": (
            detected_subject.key if detected_subject is not None else None
        ),
        "subject_governed_category": (
            subject_category.value if subject_category is not None else None
        ),
        "subject_is_governed_identifier": subject_is_governed_identifier,
        "threshold_subject_matches": threshold_subject_matches,
    }


def _decision_evidence(
    *,
    policy_input: PolicyInput,
    categories: list[SensitivityCategory],
    semantic_categories: list[SensitivityCategory],
    effective_projected_categories: list[SensitivityCategory],
    effective_semantic_categories: list[SensitivityCategory],
    referenced_categories: list[SensitivityCategory],
    effective_referenced_categories: list[SensitivityCategory],
    semantic_mode: bool,
    unresolved: list[str],
    quasi_count: int,
) -> dict[str, object]:
    return {
        "projected_categories": [category.value for category in categories],
        "semantic_projected_categories": [
            category.value for category in semantic_categories
        ],
        "effective_projected_categories": [
            category.value for category in effective_projected_categories
        ],
        "effective_semantic_projected_categories": [
            category.value for category in effective_semantic_categories
        ],
        "semantic_exposure_mode": semantic_mode,
        "projected_exposures": [
            exposure.model_dump(mode="json")
            for exposure in policy_input.query_plan.projected_exposures
        ],
        "referenced_categories": [category.value for category in referenced_categories],
        "effective_referenced_categories": [
            category.value for category in effective_referenced_categories
        ],
        "lineage_sources": _lineage_evidence(policy_input.all_referenced_context),
        "unresolved_columns": unresolved,
        "quasi_identifier_count": quasi_count,
    }


def _semantic_projected_context(
    policy_input: PolicyInput,
) -> tuple[tuple[ColumnContext, ...], bool]:
    exposures = policy_input.query_plan.projected_exposures
    if not exposures:
        return policy_input.projected_context, False

    exposed_value_kinds = {
        ProjectionExposureKind.RAW_VALUE,
        ProjectionExposureKind.TRANSFORMED_RAW_VALUE,
        ProjectionExposureKind.GROUP_KEY,
        ProjectionExposureKind.AGGREGATE_OPERAND,
        ProjectionExposureKind.CONDITIONAL_AGGREGATE,
        ProjectionExposureKind.NESTED_SCOPE,
    }
    exposed_keys = {
        ref.key
        for exposure in exposures
        if exposure.kind in exposed_value_kinds
        for ref in exposure.source_columns
    }
    by_key = {column.ref.key: column for column in policy_input.projected_context}
    return (
        tuple(by_key[key] for key in sorted(exposed_keys) if key in by_key),
        True,
    )


def _has_protected_conditional_aggregate(policy_input: PolicyInput) -> bool:
    """Reject predicate-defined aggregate subcohorts over governed protected data.

    The outer group-size threshold cannot prove a CASE/FILTER-defined subpopulation
    contains the required number of distinct subjects. Until ToxicJoin can prove that
    inner threshold independently, protected conditional aggregates fail closed.
    """

    protected = {
        SensitivityCategory.DIRECT_IDENTIFIER,
        SensitivityCategory.STABLE_PSEUDONYM,
        SensitivityCategory.QUASI_IDENTIFIER,
        SensitivityCategory.SENSITIVE_ATTRIBUTE,
        SensitivityCategory.UNCLASSIFIED,
    }
    by_key = {column.ref.key: column for column in policy_input.projected_context}
    for exposure in policy_input.query_plan.projected_exposures:
        if exposure.kind != ProjectionExposureKind.CONDITIONAL_AGGREGATE:
            continue
        for ref in exposure.source_columns:
            context = by_key.get(ref.key)
            if context is None or not context.resolved:
                return True
            if context.category in protected:
                return True
            if any(source.category in protected for source in context.lineage_sources):
                return True
    return False


def _effective_category_entries(
    columns: tuple[ColumnContext, ...],
) -> tuple[tuple[str, SensitivityCategory], ...]:
    entries: dict[tuple[str, SensitivityCategory], None] = {}
    for column in columns:
        entries[(column.ref.key, column.category)] = None
        for source in column.lineage_sources:
            entries[(source.ref.key, source.category)] = None
    return tuple(entries)


def _effective_categories(
    columns: tuple[ColumnContext, ...],
) -> list[SensitivityCategory]:
    return [category for _, category in _effective_category_entries(columns)]


def _category_count(
    columns: tuple[ColumnContext, ...],
    category: SensitivityCategory,
) -> int:
    return sum(
        effective_category == category
        for _, effective_category in _effective_category_entries(columns)
    )


def _lineage_evidence(
    columns: tuple[ColumnContext, ...],
) -> dict[str, list[dict[str, object]]]:
    return {
        column.ref.key: [source.model_dump(mode="json") for source in column.lineage_sources]
        for column in columns
        if column.lineage_sources
    }


def _deduplicate(values: list[ReasonCode]) -> tuple[ReasonCode, ...]:
    return tuple(dict.fromkeys(values))
