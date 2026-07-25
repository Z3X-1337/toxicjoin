"""Canonical finite-remediation models for the Counterfactual Privacy Cut Compiler."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, model_validator

from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.models import StrictModel
from toxicjoin.prospective.ppmc import PpmcStatus

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_CPCC_MODEL_VERSION = "0.1.0"
_MAX_REMEDIATION_ACTIONS = 32
_MAX_ENUMERATED_CANDIDATES = 528  # C(32,1) + C(32,2)
Sha256 = Annotated[str, Field(pattern=_HASH_PATTERN)]


class RemediationOperator(StrEnum):
    REMOVE_STABLE_IDENTIFIER = "REMOVE_STABLE_IDENTIFIER"
    REMOVE_SENSITIVE_PROJECTION = "REMOVE_SENSITIVE_PROJECTION"
    REMOVE_PROJECTION = "REMOVE_PROJECTION"
    COARSEN_QI = "COARSEN_QI"
    AGGREGATE_SENSITIVE = "AGGREGATE_SENSITIVE"
    ADD_MINIMUM_GROUP_THRESHOLD = "ADD_MINIMUM_GROUP_THRESHOLD"
    INCREASE_MINIMUM_GROUP_THRESHOLD = "INCREASE_MINIMUM_GROUP_THRESHOLD"


class TrustedQiTransformation(StrEnum):
    DATE_TO_MONTH = "DATE_TO_MONTH"
    DATE_TO_YEAR = "DATE_TO_YEAR"


class TrustedSensitiveAggregate(StrEnum):
    COUNT = "COUNT"
    COUNT_DISTINCT = "COUNT_DISTINCT"


class CpccValidationStage(StrEnum):
    GENERATE = "GENERATE"
    REPARSE = "REPARSE"
    REGROUND = "REGROUND"
    REBUILD_EVIDENCE = "REBUILD_EVIDENCE"
    LOCAL_POLICY = "LOCAL_POLICY"
    REBUILD_DISCLOSURE_STATE = "REBUILD_DISCLOSURE_STATE"
    PPMC = "PPMC"


class CpccValidationOutcome(StrEnum):
    ELIGIBLE_SAFE = "ELIGIBLE_SAFE"
    INELIGIBLE = "INELIGIBLE"
    FAIL_CLOSED = "FAIL_CLOSED"


class CpccStatus(StrEnum):
    REPAIR_FOUND = "REPAIR_FOUND"
    NO_ELIGIBLE_REPAIR = "NO_ELIGIBLE_REPAIR"
    FAIL_CLOSED = "FAIL_CLOSED"


class RemediationCost(StrictModel):
    """Declared ordinal cost; it is not a learned or universal utility function."""

    goal_loss: int = Field(ge=0, le=100)
    information_loss: int = Field(ge=0, le=100)
    structural_change: int = Field(ge=0, le=100)

    @property
    def ordering_key(self) -> tuple[int, int, int]:
        return (self.goal_loss, self.information_loss, self.structural_change)


class RemediationAction(StrictModel):
    """One security-owned remediation action from the finite P0 operator grammar."""

    schema_version: Literal["1.0"] = "1.0"
    model_version: Literal["0.1.0"] = _CPCC_MODEL_VERSION
    operator: RemediationOperator
    field_key: str | None = Field(default=None, min_length=1, max_length=4096)
    qi_transformation: TrustedQiTransformation | None = None
    aggregate_operator: TrustedSensitiveAggregate | None = None
    minimum_group_size: int | None = Field(default=None, ge=2, le=1_000_000)
    cost: RemediationCost
    action_sha256: Sha256

    @model_validator(mode="after")
    def validate_action(self) -> "RemediationAction":
        field_required = self.operator in {
            RemediationOperator.REMOVE_PROJECTION,
            RemediationOperator.COARSEN_QI,
            RemediationOperator.AGGREGATE_SENSITIVE,
        }
        if field_required != (self.field_key is not None):
            raise ValueError("CPCC remediation field binding does not match operator")

        if self.operator == RemediationOperator.COARSEN_QI:
            if self.qi_transformation is None:
                raise ValueError("COARSEN_QI requires a trusted transformation")
        elif self.qi_transformation is not None:
            raise ValueError("only COARSEN_QI may carry qi_transformation")

        if self.operator == RemediationOperator.AGGREGATE_SENSITIVE:
            if self.aggregate_operator is None:
                raise ValueError("AGGREGATE_SENSITIVE requires a trusted aggregate")
        elif self.aggregate_operator is not None:
            raise ValueError("only AGGREGATE_SENSITIVE may carry aggregate_operator")

        threshold_operator = self.operator in {
            RemediationOperator.ADD_MINIMUM_GROUP_THRESHOLD,
            RemediationOperator.INCREASE_MINIMUM_GROUP_THRESHOLD,
        }
        if threshold_operator != (self.minimum_group_size is not None):
            raise ValueError("CPCC threshold binding does not match operator")

        if self.cost != remediation_operator_cost(self.operator):
            raise ValueError("CPCC remediation cost does not match frozen operator cost")
        if self.action_sha256 != compute_remediation_action_sha256(self):
            raise ValueError("CPCC remediation action hash mismatch")
        return self


class CpccRemediationSpace(StrictModel):
    """Finite committed P0 remediation space. Candidates contain one or two actions."""

    schema_version: Literal["1.0"] = "1.0"
    model_version: Literal["0.1.0"] = _CPCC_MODEL_VERSION
    actions: tuple[RemediationAction, ...] = Field(
        min_length=1,
        max_length=_MAX_REMEDIATION_ACTIONS,
    )
    max_actions_per_candidate: Literal[2] = 2
    space_sha256: Sha256

    @model_validator(mode="after")
    def validate_space(self) -> "CpccRemediationSpace":
        hashes = tuple(action.action_sha256 for action in self.actions)
        if hashes != tuple(sorted(set(hashes))):
            raise ValueError("CPCC remediation actions must be sorted and unique")
        candidate_count = len(self.actions) + (
            len(self.actions) * (len(self.actions) - 1) // 2
        )
        if candidate_count > _MAX_ENUMERATED_CANDIDATES:
            raise ValueError("CPCC remediation-space candidate budget exceeded")
        if self.space_sha256 != compute_remediation_space_sha256(self):
            raise ValueError("CPCC remediation-space hash mismatch")
        return self


class CpccCandidate(StrictModel):
    """One canonical intervention considered by exhaustive CPCC search."""

    schema_version: Literal["1.0"] = "1.0"
    model_version: Literal["0.1.0"] = _CPCC_MODEL_VERSION
    remediation_space_sha256: Sha256
    actions: tuple[RemediationAction, ...] = Field(min_length=1, max_length=2)
    cost: RemediationCost
    candidate_sha256: Sha256

    @model_validator(mode="after")
    def validate_candidate(self) -> "CpccCandidate":
        hashes = tuple(action.action_sha256 for action in self.actions)
        if hashes != tuple(sorted(set(hashes))):
            raise ValueError("CPCC candidate actions must be sorted and unique")
        expected_cost = RemediationCost(
            goal_loss=sum(action.cost.goal_loss for action in self.actions),
            information_loss=sum(action.cost.information_loss for action in self.actions),
            structural_change=sum(action.cost.structural_change for action in self.actions),
        )
        if self.cost != expected_cost:
            raise ValueError("CPCC candidate cost does not match action costs")
        if self.candidate_sha256 != compute_cpcc_candidate_sha256(self):
            raise ValueError("CPCC candidate hash mismatch")
        return self

    @property
    def ordering_key(self) -> tuple[int, int, int, str]:
        return (*self.cost.ordering_key, self.candidate_sha256)


class CpccCandidateValidation(StrictModel):
    """Commitment to the mandatory full candidate-validation chain."""

    schema_version: Literal["1.0"] = "1.0"
    model_version: Literal["0.1.0"] = _CPCC_MODEL_VERSION
    candidate_sha256: Sha256
    outcome: CpccValidationOutcome
    failure_stage: CpccValidationStage | None = None
    generated_sql_sha256: Sha256 | None = None
    reparsed_plan_sha256: Sha256 | None = None
    reground_governance_sha256: Sha256 | None = None
    evidence_root_sha256: Sha256 | None = None
    local_policy_decision_sha256: Sha256 | None = None
    local_policy_allowed: bool = False
    disclosure_state_sha256: Sha256 | None = None
    ppmc_result_sha256: Sha256 | None = None
    ppmc_status: PpmcStatus | None = None
    validation_sha256: Sha256

    @model_validator(mode="after")
    def validate_chain(self) -> "CpccCandidateValidation":
        required = (
            self.generated_sql_sha256,
            self.reparsed_plan_sha256,
            self.reground_governance_sha256,
            self.evidence_root_sha256,
            self.local_policy_decision_sha256,
            self.disclosure_state_sha256,
            self.ppmc_result_sha256,
            self.ppmc_status,
        )
        if self.outcome == CpccValidationOutcome.ELIGIBLE_SAFE:
            if self.failure_stage is not None or any(value is None for value in required):
                raise ValueError(
                    "eligible CPCC candidate requires the complete validation chain"
                )
            if not self.local_policy_allowed:
                raise ValueError("eligible CPCC candidate requires local PolicyEngine ALLOW")
            if self.ppmc_status != PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND:
                raise ValueError(
                    "eligible CPCC candidate requires bounded PPMC no-counterexample result"
                )
        elif self.outcome == CpccValidationOutcome.INELIGIBLE:
            if self.failure_stage is None:
                raise ValueError("ineligible CPCC candidate requires a failure stage")
            if self.failure_stage == CpccValidationStage.PPMC:
                if not self.local_policy_allowed:
                    raise ValueError(
                        "PPMC-ineligible CPCC candidate requires prior local ALLOW"
                    )
                if self.ppmc_status != PpmcStatus.PROSPECTIVE_UNSAFE:
                    raise ValueError(
                        "PPMC-ineligible candidate requires PROSPECTIVE_UNSAFE"
                    )
            elif self.local_policy_allowed:
                raise ValueError(
                    "locally allowed ineligible candidate may fail only at PPMC"
                )
        else:
            if self.failure_stage is None:
                raise ValueError("fail-closed CPCC validation requires a failure stage")
            if self.ppmc_status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND:
                raise ValueError("safe PPMC result cannot be marked fail closed")

        if self.validation_sha256 != compute_cpcc_candidate_validation_sha256(self):
            raise ValueError("CPCC candidate-validation hash mismatch")
        return self


class CpccResult(StrictModel):
    """Deterministic exhaustive selection result over one committed remediation space."""

    schema_version: Literal["1.0"] = "1.0"
    model_version: Literal["0.1.0"] = _CPCC_MODEL_VERSION
    status: CpccStatus
    remediation_space_sha256: Sha256
    candidates_considered: int = Field(ge=0, le=_MAX_ENUMERATED_CANDIDATES)
    validation_sha256s: tuple[Sha256, ...] = Field(
        default=(),
        max_length=_MAX_ENUMERATED_CANDIDATES,
    )
    eligible_candidate_sha256s: tuple[Sha256, ...] = Field(
        default=(),
        max_length=_MAX_ENUMERATED_CANDIDATES,
    )
    selected_candidate: CpccCandidate | None = None
    failed_candidate_sha256: Sha256 | None = None
    result_sha256: Sha256

    @model_validator(mode="after")
    def validate_result(self) -> "CpccResult":
        if len(self.validation_sha256s) != self.candidates_considered:
            raise ValueError("CPCC validation count does not match considered candidates")
        canonical_eligible = tuple(sorted(set(self.eligible_candidate_sha256s)))
        if self.eligible_candidate_sha256s != canonical_eligible:
            raise ValueError("CPCC eligible candidate hashes must be sorted and unique")

        if self.status == CpccStatus.REPAIR_FOUND:
            if self.selected_candidate is None or self.failed_candidate_sha256 is not None:
                raise ValueError("CPCC repair result requires one selected candidate")
            if (
                self.selected_candidate.remediation_space_sha256
                != self.remediation_space_sha256
            ):
                raise ValueError("CPCC selected candidate belongs to another space")
            if self.selected_candidate.candidate_sha256 not in self.eligible_candidate_sha256s:
                raise ValueError("CPCC selected candidate is not eligible")
        elif self.status == CpccStatus.NO_ELIGIBLE_REPAIR:
            if self.selected_candidate is not None or self.failed_candidate_sha256 is not None:
                raise ValueError(
                    "no-repair CPCC result cannot contain selected/failed candidate"
                )
            if self.eligible_candidate_sha256s:
                raise ValueError("no-repair CPCC result cannot contain eligible candidates")
        else:
            if self.selected_candidate is not None or self.failed_candidate_sha256 is None:
                raise ValueError("fail-closed CPCC result requires failed candidate only")

        if self.result_sha256 != compute_cpcc_result_sha256(self):
            raise ValueError("CPCC result hash mismatch")
        return self


def remediation_operator_cost(operator: RemediationOperator) -> RemediationCost:
    """Frozen P0 ordinal cost table; scoped to this declared model only."""

    values = {
        RemediationOperator.ADD_MINIMUM_GROUP_THRESHOLD: (0, 1, 1),
        RemediationOperator.INCREASE_MINIMUM_GROUP_THRESHOLD: (0, 1, 1),
        RemediationOperator.COARSEN_QI: (1, 2, 1),
        RemediationOperator.AGGREGATE_SENSITIVE: (2, 3, 2),
        RemediationOperator.REMOVE_STABLE_IDENTIFIER: (3, 4, 1),
        RemediationOperator.REMOVE_PROJECTION: (4, 4, 1),
        RemediationOperator.REMOVE_SENSITIVE_PROJECTION: (5, 5, 1),
    }
    return RemediationCost(
        goal_loss=values[operator][0],
        information_loss=values[operator][1],
        structural_change=values[operator][2],
    )


def compute_remediation_action_sha256(action: RemediationAction) -> str:
    return canonical_json_sha256(
        action.model_dump(mode="json", exclude={"action_sha256"})
    )


def compute_remediation_space_sha256(space: CpccRemediationSpace) -> str:
    return canonical_json_sha256(space.model_dump(mode="json", exclude={"space_sha256"}))


def compute_cpcc_candidate_sha256(candidate: CpccCandidate) -> str:
    return canonical_json_sha256(
        candidate.model_dump(mode="json", exclude={"candidate_sha256"})
    )


def compute_cpcc_candidate_validation_sha256(
    validation: CpccCandidateValidation,
) -> str:
    return canonical_json_sha256(
        validation.model_dump(mode="json", exclude={"validation_sha256"})
    )


def compute_cpcc_result_sha256(result: CpccResult) -> str:
    return canonical_json_sha256(
        result.model_dump(mode="json", exclude={"result_sha256"})
    )
