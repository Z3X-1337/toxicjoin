"""Isolated P1 policy experiment: patient-level pseudonym + sensitive disclosure.

P1 intentionally changes one rule only. It delegates to the shipped PolicyEngine and
intercepts only non-grouped cases that would otherwise reach ALLOW while projecting a
stable pseudonym and at least one sensitive attribute. No parser, rewriter, resolver,
or executor behavior is changed by this experiment.
"""

from __future__ import annotations

from toxicjoin.models import Decision, PolicyDecision, PolicyInput, ReasonCode
from toxicjoin.policy import PolicyEngine


class P1PolicyEngine(PolicyEngine):
    """Policy-only ablation for the preregistered external patient-level threat rule."""

    def evaluate(self, policy_input: PolicyInput) -> PolicyDecision:
        shipped = super().evaluate(policy_input)

        if shipped.decision != Decision.ALLOW:
            return shipped
        if policy_input.query_plan.is_grouped:
            return shipped

        projected = tuple(policy_input.projected_context)
        has_stable_pseudonym = any(
            field.category.value == "STABLE_PSEUDONYM" for field in projected
        )
        has_sensitive = any(
            field.category.value == "SENSITIVE_ATTRIBUTE" for field in projected
        )
        if not (has_stable_pseudonym and has_sensitive):
            return shipped

        return PolicyDecision(
            decision=Decision.BLOCK,
            reason_codes=(ReasonCode.COMPOSITIONAL_REIDENTIFICATION_RISK,),
            summary=(
                "P1 experimental rule: non-grouped output projects a stable subject "
                "pseudonym together with sensitive data"
            ),
            policy_version=f"{self.config.version}+research-p1",
            rewrite_required=False,
        )
