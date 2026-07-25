from __future__ import annotations

import pytest
from pydantic import ValidationError

from toxicjoin.prospective.ppmc import PpmcStatus
from toxicjoin.repair import (
    CpccCandidateValidation,
    CpccResult,
    CpccStatus,
    CpccValidationOutcome,
    CpccValidationStage,
    RemediationAction,
    RemediationOperator,
    TrustedQiTransformation,
    TrustedSensitiveAggregate,
    build_cpcc_candidate_validation,
    build_remediation_action,
    build_remediation_space,
    enumerate_cpcc_candidates,
    run_cpcc,
)

H1 = "1" * 64
H2 = "2" * 64
H3 = "3" * 64
H4 = "4" * 64
H5 = "5" * 64
H6 = "6" * 64
H7 = "7" * 64


def _safe_validation(candidate_sha256: str) -> CpccCandidateValidation:
    return build_cpcc_candidate_validation(
        candidate_sha256=candidate_sha256,
        outcome=CpccValidationOutcome.ELIGIBLE_SAFE,
        generated_sql_sha256=H1,
        reparsed_plan_sha256=H2,
        reground_governance_sha256=H3,
        evidence_root_sha256=H4,
        local_policy_decision_sha256=H5,
        local_policy_allowed=True,
        disclosure_state_sha256=H6,
        ppmc_result_sha256=H7,
        ppmc_status=PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND,
    )


def _reject(
    candidate_sha256: str,
    stage: CpccValidationStage = CpccValidationStage.GENERATE,
) -> CpccCandidateValidation:
    return build_cpcc_candidate_validation(
        candidate_sha256=candidate_sha256,
        outcome=CpccValidationOutcome.INELIGIBLE,
        failure_stage=stage,
    )


def _uncertain(candidate_sha256: str) -> CpccCandidateValidation:
    return build_cpcc_candidate_validation(
        candidate_sha256=candidate_sha256,
        outcome=CpccValidationOutcome.FAIL_CLOSED,
        failure_stage=CpccValidationStage.REBUILD_EVIDENCE,
        generated_sql_sha256=H1,
        reparsed_plan_sha256=H2,
        reground_governance_sha256=H3,
    )


def test_remediation_action_cost_is_frozen_and_tamper_evident() -> None:
    action = build_remediation_action(
        RemediationOperator.COARSEN_QI,
        field_key="urn:dataset#age",
        qi_transformation=TrustedQiTransformation.DATE_TO_YEAR,
    )
    assert action.cost.ordering_key == (1, 2, 1)

    payload = action.model_dump(mode="json")
    payload["cost"]["goal_loss"] = 0
    with pytest.raises(ValidationError, match="frozen operator cost"):
        RemediationAction.model_validate(payload)


def test_operator_specific_parameters_fail_closed() -> None:
    with pytest.raises(ValidationError, match="requires a trusted transformation"):
        build_remediation_action(
            RemediationOperator.COARSEN_QI,
            field_key="urn:dataset#birth_date",
        )
    with pytest.raises(ValidationError, match="requires a trusted aggregate"):
        build_remediation_action(
            RemediationOperator.AGGREGATE_SENSITIVE,
            field_key="urn:dataset#diagnosis",
        )
    with pytest.raises(ValidationError, match="threshold binding"):
        build_remediation_action(RemediationOperator.ADD_MINIMUM_GROUP_THRESHOLD)


def test_remediation_space_and_candidate_enumeration_are_deterministic() -> None:
    actions = (
        build_remediation_action(
            RemediationOperator.REMOVE_PROJECTION,
            field_key="urn:dataset#region",
        ),
        build_remediation_action(
            RemediationOperator.ADD_MINIMUM_GROUP_THRESHOLD,
            minimum_group_size=20,
        ),
        build_remediation_action(
            RemediationOperator.AGGREGATE_SENSITIVE,
            field_key="urn:dataset#diagnosis",
            aggregate_operator=TrustedSensitiveAggregate.COUNT,
        ),
        build_remediation_action(RemediationOperator.REMOVE_STABLE_IDENTIFIER),
    )
    first = build_remediation_space(actions)
    second = build_remediation_space(tuple(reversed(actions)))

    assert first == second
    candidates = enumerate_cpcc_candidates(first)
    assert len(candidates) == 10
    assert candidates == tuple(
        sorted(candidates, key=lambda item: item.ordering_key)
    )
    action_sets = {
        tuple(action.action_sha256 for action in item.actions)
        for item in candidates
    }
    assert len(action_sets) == 10


def test_cpcc_validates_entire_space_before_selecting_minimum_cost() -> None:
    threshold = build_remediation_action(
        RemediationOperator.ADD_MINIMUM_GROUP_THRESHOLD,
        minimum_group_size=20,
    )
    coarsen = build_remediation_action(
        RemediationOperator.COARSEN_QI,
        field_key="urn:dataset#event_date",
        qi_transformation=TrustedQiTransformation.DATE_TO_MONTH,
    )
    remove = build_remediation_action(
        RemediationOperator.REMOVE_SENSITIVE_PROJECTION,
    )
    space = build_remediation_space((remove, coarsen, threshold))
    candidates = enumerate_cpcc_candidates(space)
    seen: list[str] = []

    def validator(candidate):
        seen.append(candidate.candidate_sha256)
        operators = {action.operator for action in candidate.actions}
        if operators == {RemediationOperator.COARSEN_QI}:
            return _safe_validation(candidate.candidate_sha256)
        if operators == {RemediationOperator.REMOVE_SENSITIVE_PROJECTION}:
            return _safe_validation(candidate.candidate_sha256)
        return _reject(candidate.candidate_sha256)

    result = run_cpcc(remediation_space=space, validator=validator)

    assert seen == [candidate.candidate_sha256 for candidate in candidates]
    assert result.status == CpccStatus.REPAIR_FOUND
    assert result.candidates_considered == len(candidates)
    assert result.selected_candidate is not None
    assert tuple(action.operator for action in result.selected_candidate.actions) == (
        RemediationOperator.COARSEN_QI,
    )
    assert len(result.eligible_candidate_sha256s) == 2


def test_cpcc_tie_breaks_equal_cost_with_canonical_candidate_hash() -> None:
    first_action = build_remediation_action(
        RemediationOperator.REMOVE_PROJECTION,
        field_key="urn:dataset#a",
    )
    second_action = build_remediation_action(
        RemediationOperator.REMOVE_PROJECTION,
        field_key="urn:dataset#b",
    )
    space = build_remediation_space((first_action, second_action))
    singles = [
        item for item in enumerate_cpcc_candidates(space) if len(item.actions) == 1
    ]

    def validator(candidate):
        if len(candidate.actions) == 1:
            return _safe_validation(candidate.candidate_sha256)
        return _reject(candidate.candidate_sha256)

    result = run_cpcc(remediation_space=space, validator=validator)
    expected = min(singles, key=lambda item: item.ordering_key)

    assert result.selected_candidate == expected


def test_cpcc_no_repair_requires_every_candidate_explicitly_ineligible() -> None:
    space = build_remediation_space(
        (
            build_remediation_action(RemediationOperator.REMOVE_STABLE_IDENTIFIER),
            build_remediation_action(RemediationOperator.REMOVE_SENSITIVE_PROJECTION),
        )
    )
    candidates = enumerate_cpcc_candidates(space)
    calls = 0

    def validator(candidate):
        nonlocal calls
        calls += 1
        return _reject(candidate.candidate_sha256)

    result = run_cpcc(remediation_space=space, validator=validator)

    assert calls == len(candidates)
    assert result.status == CpccStatus.NO_ELIGIBLE_REPAIR
    assert result.selected_candidate is None
    assert result.eligible_candidate_sha256s == ()


def test_cpcc_fails_closed_if_candidate_validation_is_uncertain() -> None:
    cheap = build_remediation_action(
        RemediationOperator.ADD_MINIMUM_GROUP_THRESHOLD,
        minimum_group_size=20,
    )
    expensive = build_remediation_action(
        RemediationOperator.REMOVE_SENSITIVE_PROJECTION,
    )
    space = build_remediation_space((cheap, expensive))
    candidates = enumerate_cpcc_candidates(space)

    def validator(candidate):
        if candidate == candidates[0]:
            return _uncertain(candidate.candidate_sha256)
        return _safe_validation(candidate.candidate_sha256)

    result = run_cpcc(remediation_space=space, validator=validator)

    assert result.status == CpccStatus.FAIL_CLOSED
    assert result.failed_candidate_sha256 == candidates[0].candidate_sha256
    assert result.selected_candidate is None
    assert result.candidates_considered == 1


def test_cpcc_fails_closed_if_validator_raises_or_binds_wrong_candidate() -> None:
    space = build_remediation_space(
        (build_remediation_action(RemediationOperator.REMOVE_STABLE_IDENTIFIER),)
    )
    candidate = enumerate_cpcc_candidates(space)[0]

    def exploding_validator(_candidate):
        raise RuntimeError("simulated full-chain validator failure")

    failure = run_cpcc(remediation_space=space, validator=exploding_validator)
    assert failure.status == CpccStatus.FAIL_CLOSED
    assert failure.failed_candidate_sha256 == candidate.candidate_sha256
    assert failure.candidates_considered == 0

    def mismatched_validator(_candidate):
        return _reject("a" * 64)

    mismatch = run_cpcc(remediation_space=space, validator=mismatched_validator)
    assert mismatch.status == CpccStatus.FAIL_CLOSED
    assert mismatch.failed_candidate_sha256 == candidate.candidate_sha256


def test_eligible_validation_requires_all_mandatory_chain_commitments() -> None:
    with pytest.raises(ValidationError, match="complete validation chain"):
        build_cpcc_candidate_validation(
            candidate_sha256=H1,
            outcome=CpccValidationOutcome.ELIGIBLE_SAFE,
            local_policy_allowed=True,
            ppmc_status=PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND,
        )

    with pytest.raises(ValidationError, match="PolicyEngine ALLOW"):
        build_cpcc_candidate_validation(
            candidate_sha256=H1,
            outcome=CpccValidationOutcome.ELIGIBLE_SAFE,
            generated_sql_sha256=H1,
            reparsed_plan_sha256=H2,
            reground_governance_sha256=H3,
            evidence_root_sha256=H4,
            local_policy_decision_sha256=H5,
            local_policy_allowed=False,
            disclosure_state_sha256=H6,
            ppmc_result_sha256=H7,
            ppmc_status=PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND,
        )


def test_ppmc_ineligible_is_distinct_from_ppmc_fail_closed() -> None:
    unsafe = build_cpcc_candidate_validation(
        candidate_sha256=H1,
        outcome=CpccValidationOutcome.INELIGIBLE,
        failure_stage=CpccValidationStage.PPMC,
        generated_sql_sha256=H1,
        reparsed_plan_sha256=H2,
        reground_governance_sha256=H3,
        evidence_root_sha256=H4,
        local_policy_decision_sha256=H5,
        local_policy_allowed=True,
        disclosure_state_sha256=H6,
        ppmc_result_sha256=H7,
        ppmc_status=PpmcStatus.PROSPECTIVE_UNSAFE,
    )
    assert unsafe.outcome == CpccValidationOutcome.INELIGIBLE

    uncertain = build_cpcc_candidate_validation(
        candidate_sha256=H1,
        outcome=CpccValidationOutcome.FAIL_CLOSED,
        failure_stage=CpccValidationStage.PPMC,
        generated_sql_sha256=H1,
        reparsed_plan_sha256=H2,
        reground_governance_sha256=H3,
        evidence_root_sha256=H4,
        local_policy_decision_sha256=H5,
        local_policy_allowed=True,
        disclosure_state_sha256=H6,
        ppmc_result_sha256=H7,
        ppmc_status=PpmcStatus.FAIL_CLOSED,
    )
    assert uncertain.outcome == CpccValidationOutcome.FAIL_CLOSED


def test_cpcc_result_integrity_tampering_is_rejected() -> None:
    space = build_remediation_space(
        (build_remediation_action(RemediationOperator.REMOVE_STABLE_IDENTIFIER),)
    )
    result = run_cpcc(
        remediation_space=space,
        validator=lambda candidate: _safe_validation(candidate.candidate_sha256),
    )
    payload = result.model_dump(mode="json")
    payload["result_sha256"] = "0" * 64

    with pytest.raises(ValidationError, match="CPCC result hash mismatch"):
        CpccResult.model_validate(payload)


def test_cpcc_space_is_bounded_to_32_actions_and_528_candidates() -> None:
    actions = tuple(
        build_remediation_action(
            RemediationOperator.REMOVE_PROJECTION,
            field_key=f"urn:dataset#field_{index:02d}",
        )
        for index in range(32)
    )
    space = build_remediation_space(actions)
    assert len(enumerate_cpcc_candidates(space)) == 528

    with pytest.raises(ValidationError):
        build_remediation_space(
            actions
            + (
                build_remediation_action(
                    RemediationOperator.REMOVE_PROJECTION,
                    field_key="urn:dataset#field_32",
                ),
            )
        )
