"""Deterministic compositional-risk policy engine."""

from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

from toxicjoin.models import (
    Decision,
    PolicyDecision,
    PolicyInput,
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


def load_policy(path: str | Path) -> PolicyConfig:
    """Load and strictly validate a policy YAML file."""

    policy_path = Path(path)
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

        unresolved = [
            column.ref.key
            for column in policy_input.all_referenced_context
            if not column.resolved
            or column.category == SensitivityCategory.UNCLASSIFIED
        ]
        if unresolved and self.config.fail_closed:
            block_reasons.append(ReasonCode.UNCLASSIFIED_COLUMN)

        has_direct = SensitivityCategory.DIRECT_IDENTIFIER in categories
        has_pseudonym = SensitivityCategory.STABLE_PSEUDONYM in categories
        has_sensitive = SensitivityCategory.SENSITIVE_ATTRIBUTE in categories
        quasi_count = sum(
            category == SensitivityCategory.QUASI_IDENTIFIER
            for category in categories
        )

        if has_direct and has_sensitive:
            block_reasons.append(ReasonCode.DIRECT_SENSITIVE_LINKAGE)

        if (
            has_pseudonym
            and has_sensitive
            and quasi_count >= self.config.quasi_identifier_threshold
            and not policy_input.query_plan.is_grouped
        ):
            block_reasons.append(ReasonCode.COMPOSITIONAL_REIDENTIFICATION_RISK)

        if block_reasons:
            return PolicyDecision(
                decision=Decision.BLOCK,
                reason_codes=_deduplicate(block_reasons),
                policy_version=self.config.version,
                evidence={
                    "projected_categories": [category.value for category in categories],
                    "referenced_categories": [
                        category.value for category in referenced_categories
                    ],
                    "unresolved_columns": unresolved,
                    "quasi_identifier_count": quasi_count,
                },
            )

        sensitive_anywhere = (
            SensitivityCategory.SENSITIVE_ATTRIBUTE in referenced_categories
        )
        threshold = policy_input.minimum_group_size_present
        expected_subject = policy_input.subject_key
        detected_subject = policy_input.query_plan.minimum_group_size_subject
        threshold_subject_matches = (
            expected_subject is not None
            and detected_subject is not None
            and expected_subject.key == detected_subject.key
        )
        trusted_threshold = threshold if threshold_subject_matches else None

        if policy_input.query_plan.is_grouped and sensitive_anywhere:
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
                        "detected_minimum_group_size": threshold,
                        "expected_subject_key": (
                            expected_subject.key if expected_subject is not None else None
                        ),
                        "detected_threshold_subject": (
                            detected_subject.key if detected_subject is not None else None
                        ),
                        "threshold_subject_matches": threshold_subject_matches,
                    },
                    rewrite_required=True,
                )

        return PolicyDecision(
            decision=Decision.ALLOW,
            reason_codes=(ReasonCode.NO_COMPOSITIONAL_RISK,),
            policy_version=self.config.version,
            evidence={
                "projected_categories": [category.value for category in categories],
                "referenced_categories": [
                    category.value for category in referenced_categories
                ],
                "trusted_minimum_group_size": trusted_threshold,
                "trusted_threshold_subject": (
                    detected_subject.key if threshold_subject_matches else None
                ),
            },
        )


def _deduplicate(values: list[ReasonCode]) -> tuple[ReasonCode, ...]:
    return tuple(dict.fromkeys(values))
