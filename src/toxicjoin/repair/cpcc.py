"""Deterministic exhaustive core for the Counterfactual Privacy Cut Compiler (CPCC)."""

from __future__ import annotations

from itertools import combinations
from typing import Protocol

from pydantic import ValidationError

from toxicjoin.prospective.ppmc import PpmcStatus
from toxicjoin.repair.models import (
    CpccCandidate,
    CpccCandidateValidation,
    CpccRemediationSpace,
    CpccResult,
    CpccStatus,
    CpccValidationOutcome,
    CpccValidationStage,
    RemediationAction,
    RemediationCost,
    RemediationOperator,
    TrustedQiTransformation,
    TrustedSensitiveAggregate,
    compute_cpcc_candidate_sha256,
    compute_cpcc_candidate_validation_sha256,
    compute_cpcc_result_sha256,
    compute_remediation_action_sha256,
    compute_remediation_space_sha256,
    remediation_operator_cost,
)


class CpccError(RuntimeError):
    """Raised when the trusted CPCC model itself is malformed."""


class CpccCandidateValidator(Protocol):
    """Security-authoritative full-chain validator for one generated repair candidate."""

    def __call__(self, candidate: CpccCandidate) -> CpccCandidateValidation: ...


def build_remediation_action(
    operator: RemediationOperator,
    *,
    field_key: str | None = None,
    qi_transformation: TrustedQiTransformation | None = None,
    aggregate_operator: TrustedSensitiveAggregate | None = None,
    minimum_group_size: int | None = None,
) -> RemediationAction:
    cost = remediation_operator_cost(operator)
    provisional = RemediationAction.model_construct(
        operator=operator,
        field_key=field_key,
        qi_transformation=qi_transformation,
        aggregate_operator=aggregate_operator,
        minimum_group_size=minimum_group_size,
        cost=cost,
        action_sha256="0" * 64,
    )
    return RemediationAction(
        operator=operator,
        field_key=field_key,
        qi_transformation=qi_transformation,
        aggregate_operator=aggregate_operator,
        minimum_group_size=minimum_group_size,
        cost=cost,
        action_sha256=compute_remediation_action_sha256(provisional),
    )


def build_remediation_space(
    actions: tuple[RemediationAction, ...],
) -> CpccRemediationSpace:
    ordered = tuple(sorted(actions, key=lambda action: action.action_sha256))
    provisional = CpccRemediationSpace.model_construct(
        actions=ordered,
        max_actions_per_candidate=2,
        space_sha256="0" * 64,
    )
    return CpccRemediationSpace(
        actions=ordered,
        max_actions_per_candidate=2,
        space_sha256=compute_remediation_space_sha256(provisional),
    )


def enumerate_cpcc_candidates(space: CpccRemediationSpace) -> tuple[CpccCandidate, ...]:
    """Enumerate every one- and two-action candidate; invalid combinations are not hidden.

    Applicability/compatibility is a GENERATE-stage validation concern. Keeping all pairs in
    the committed finite space makes the optimization claim auditable: no candidate is silently
    pruned by an uncommitted heuristic.
    """

    validated_space = CpccRemediationSpace.model_validate(space.model_dump(mode="json"))
    action_groups = [
        *( (action,) for action in validated_space.actions ),
        *combinations(validated_space.actions, 2),
    ]
    candidates = tuple(
        _build_candidate(validated_space.space_sha256, tuple(group))
        for group in action_groups
    )
    return tuple(sorted(candidates, key=lambda candidate: candidate.ordering_key))


def build_cpcc_candidate_validation(
    *,
    candidate_sha256: str,
    outcome: CpccValidationOutcome,
    failure_stage: CpccValidationStage | None = None,
    generated_sql_sha256: str | None = None,
    reparsed_plan_sha256: str | None = None,
    reground_governance_sha256: str | None = None,
    evidence_root_sha256: str | None = None,
    local_policy_decision_sha256: str | None = None,
    local_policy_allowed: bool = False,
    disclosure_state_sha256: str | None = None,
    ppmc_result_sha256: str | None = None,
    ppmc_status: PpmcStatus | None = None,
) -> CpccCandidateValidation:
    payload = {
        "candidate_sha256": candidate_sha256,
        "outcome": outcome,
        "failure_stage": failure_stage,
        "generated_sql_sha256": generated_sql_sha256,
        "reparsed_plan_sha256": reparsed_plan_sha256,
        "reground_governance_sha256": reground_governance_sha256,
        "evidence_root_sha256": evidence_root_sha256,
        "local_policy_decision_sha256": local_policy_decision_sha256,
        "local_policy_allowed": local_policy_allowed,
        "disclosure_state_sha256": disclosure_state_sha256,
        "ppmc_result_sha256": ppmc_result_sha256,
        "ppmc_status": ppmc_status,
    }
    provisional = CpccCandidateValidation.model_construct(
        **payload,
        validation_sha256="0" * 64,
    )
    return CpccCandidateValidation(
        **payload,
        validation_sha256=compute_cpcc_candidate_validation_sha256(provisional),
    )


def run_cpcc(
    *,
    remediation_space: CpccRemediationSpace,
    validator: CpccCandidateValidator,
) -> CpccResult:
    """Exhaustively validate the entire committed finite space before selecting a repair."""

    try:
        space = CpccRemediationSpace.model_validate(remediation_space.model_dump(mode="json"))
        candidates = enumerate_cpcc_candidates(space)
    except ValidationError as exc:
        raise CpccError("CPCC remediation space failed canonical validation") from exc

    validations: list[CpccCandidateValidation] = []
    eligible: list[CpccCandidate] = []
    for candidate in candidates:
        try:
            raw_validation = validator(candidate)
            validation = CpccCandidateValidation.model_validate(
                raw_validation.model_dump(mode="json")
            )
        except Exception:
            return _build_result(
                status=CpccStatus.FAIL_CLOSED,
                remediation_space=space,
                validations=tuple(validations),
                eligible=tuple(eligible),
                selected=None,
                failed_candidate_sha256=candidate.candidate_sha256,
            )
        if validation.candidate_sha256 != candidate.candidate_sha256:
            return _build_result(
                status=CpccStatus.FAIL_CLOSED,
                remediation_space=space,
                validations=tuple(validations),
                eligible=tuple(eligible),
                selected=None,
                failed_candidate_sha256=candidate.candidate_sha256,
            )
        validations.append(validation)
        if validation.outcome == CpccValidationOutcome.ELIGIBLE_SAFE:
            eligible.append(candidate)

    selected = min(eligible, key=lambda candidate: candidate.ordering_key) if eligible else None
    return _build_result(
        status=CpccStatus.REPAIR_FOUND if selected is not None else CpccStatus.NO_ELIGIBLE_REPAIR,
        remediation_space=space,
        validations=tuple(validations),
        eligible=tuple(eligible),
        selected=selected,
        failed_candidate_sha256=None,
    )


def _build_candidate(
    remediation_space_sha256: str,
    actions: tuple[RemediationAction, ...],
) -> CpccCandidate:
    ordered = tuple(sorted(actions, key=lambda action: action.action_sha256))
    cost = RemediationCost(
        goal_loss=sum(action.cost.goal_loss for action in ordered),
        information_loss=sum(action.cost.information_loss for action in ordered),
        structural_change=sum(action.cost.structural_change for action in ordered),
    )
    provisional = CpccCandidate.model_construct(
        remediation_space_sha256=remediation_space_sha256,
        actions=ordered,
        cost=cost,
        candidate_sha256="0" * 64,
    )
    return CpccCandidate(
        remediation_space_sha256=remediation_space_sha256,
        actions=ordered,
        cost=cost,
        candidate_sha256=compute_cpcc_candidate_sha256(provisional),
    )


def _build_result(
    *,
    status: CpccStatus,
    remediation_space: CpccRemediationSpace,
    validations: tuple[CpccCandidateValidation, ...],
    eligible: tuple[CpccCandidate, ...],
    selected: CpccCandidate | None,
    failed_candidate_sha256: str | None,
) -> CpccResult:
    payload = {
        "status": status,
        "remediation_space_sha256": remediation_space.space_sha256,
        "candidates_considered": len(validations),
        "validation_sha256s": tuple(item.validation_sha256 for item in validations),
        "eligible_candidate_sha256s": tuple(
            sorted(candidate.candidate_sha256 for candidate in eligible)
        ),
        "selected_candidate": selected,
        "failed_candidate_sha256": failed_candidate_sha256,
    }
    provisional = CpccResult.model_construct(**payload, result_sha256="0" * 64)
    return CpccResult(**payload, result_sha256=compute_cpcc_result_sha256(provisional))
