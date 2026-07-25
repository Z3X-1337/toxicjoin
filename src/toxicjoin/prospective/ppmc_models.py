"""Canonical models and integrity commitments for bounded PPMC."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal, Protocol

from pydantic import Field, model_validator

from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.models import StrictModel
from toxicjoin.prospective.forbidden import ForbiddenPredicateId
from toxicjoin.prospective.grammar import FutureAction
from toxicjoin.prospective.trace import CounterexampleTrace
from toxicjoin.prospective.twin import DisclosureState

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_CHECKER_VERSION = "0.1.0"
_DEFAULT_BOUND = 3
_HARD_MAX_BOUND = 5
_DEFAULT_MAX_STATES = 10_000
_HARD_MAX_STATES = 50_000


class PpmcError(RuntimeError):
    """Raised when trusted PPMC inputs violate the declared model contract."""


class PpmcStatus(StrEnum):
    PROSPECTIVE_UNSAFE = "PROSPECTIVE_UNSAFE"
    NO_COUNTEREXAMPLE_WITHIN_BOUND = "NO_COUNTEREXAMPLE_WITHIN_BOUND"
    FAIL_CLOSED = "FAIL_CLOSED"


class PpmcFailureReason(StrEnum):
    INDETERMINATE_SECURITY_PREDICATE = "INDETERMINATE_SECURITY_PREDICATE"
    STATE_BUDGET_EXHAUSTED = "STATE_BUDGET_EXHAUSTED"
    LOCAL_ORACLE_FAILURE = "LOCAL_ORACLE_FAILURE"
    TRANSITION_FAILURE = "TRANSITION_FAILURE"
    PREDICATE_EVALUATION_FAILURE = "PREDICATE_EVALUATION_FAILURE"


class PpmcSearchConfig(StrictModel):
    """Versioned bounded-search limits committed into every PPMC result."""

    schema_version: Literal["1.0"] = "1.0"
    checker_version: Literal["0.1.0"] = _CHECKER_VERSION
    bound: int = Field(default=_DEFAULT_BOUND, ge=0, le=_HARD_MAX_BOUND)
    max_states: int = Field(default=_DEFAULT_MAX_STATES, ge=1, le=_HARD_MAX_STATES)
    config_sha256: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_config(self) -> "PpmcSearchConfig":
        if self.config_sha256 != compute_ppmc_config_sha256(self):
            raise ValueError("PPMC search config hash mismatch")
        return self


class LocalOracleDecision(StrictModel):
    """Canonical decision emitted by the trusted local-admissibility adapter.

    The hash is an integrity commitment, not authentication. Runtime integration must
    ensure the callback itself is the trusted adapter to the existing local privacy kernel.
    """

    schema_version: Literal["1.0"] = "1.0"
    oracle_version: str = Field(min_length=1, max_length=128)
    state_sha256: str = Field(pattern=_HASH_PATTERN)
    action_sha256: str = Field(pattern=_HASH_PATTERN)
    admissible: bool
    reason_codes: tuple[str, ...] = Field(default=(), max_length=16)
    decision_sha256: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_decision(self) -> "LocalOracleDecision":
        if self.reason_codes != tuple(sorted(set(self.reason_codes))):
            raise ValueError("local oracle reason codes must be sorted and unique")
        if any(not value or len(value) > 128 for value in self.reason_codes):
            raise ValueError("local oracle reason codes must be bounded non-empty strings")
        if self.decision_sha256 != compute_local_oracle_decision_sha256(self):
            raise ValueError("local oracle decision hash mismatch")
        return self


class LocalAdmissibilityOracle(Protocol):
    """Trusted in-process boundary used by PPMC to query local admissibility."""

    def __call__(self, state: DisclosureState, action: FutureAction) -> LocalOracleDecision: ...


class PpmcSearchResult(StrictModel):
    """Canonical outcome of one deterministic bounded PPMC run."""

    schema_version: Literal["1.0"] = "1.0"
    checker_version: Literal["0.1.0"] = _CHECKER_VERSION
    status: PpmcStatus
    failure_reason: PpmcFailureReason | None = None
    initial_state_sha256: str = Field(pattern=_HASH_PATTERN)
    grammar_sha256: str = Field(pattern=_HASH_PATTERN)
    config_sha256: str = Field(pattern=_HASH_PATTERN)
    bound: int = Field(ge=0, le=_HARD_MAX_BOUND)
    max_states: int = Field(ge=1, le=_HARD_MAX_STATES)
    forbidden_policy_sha256: str = Field(pattern=_HASH_PATTERN)
    governance_binding_sha256: str | None = Field(default=None, pattern=_HASH_PATTERN)
    search_nodes_discovered: int = Field(ge=1)
    nodes_expanded: int = Field(ge=0)
    actions_considered: int = Field(ge=0)
    transition_rejections: int = Field(ge=0)
    oracle_rejections: int = Field(ge=0)
    oracle_admissions: int = Field(ge=0)
    indeterminate_predicates: tuple[ForbiddenPredicateId, ...] = ()
    terminal_forbidden_evaluation_sha256: str | None = Field(default=None, pattern=_HASH_PATTERN)
    counterexample: CounterexampleTrace | None = None
    search_transcript_sha256: str = Field(pattern=_HASH_PATTERN)
    result_sha256: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_result(self) -> "PpmcSearchResult":
        canonical_indeterminate = tuple(
            predicate
            for predicate in ForbiddenPredicateId
            if predicate in set(self.indeterminate_predicates)
        )
        if self.indeterminate_predicates != canonical_indeterminate:
            raise ValueError("PPMC indeterminate predicates must be canonical and unique")
        if self.counterexample is not None and self.counterexample.bound != self.bound:
            raise ValueError("PPMC counterexample bound does not match search result")
        if self.search_nodes_discovered > self.max_states:
            raise ValueError("PPMC discovered search nodes exceed the configured budget")
        if self.nodes_expanded > self.search_nodes_discovered:
            raise ValueError("PPMC expanded-node count exceeds discovered search nodes")
        if self.oracle_admissions + self.oracle_rejections > self.actions_considered:
            raise ValueError("PPMC oracle counters exceed considered actions")
        if self.transition_rejections > self.actions_considered:
            raise ValueError("PPMC transition rejection count exceeds considered actions")

        if self.status == PpmcStatus.PROSPECTIVE_UNSAFE:
            if self.failure_reason is not None or self.counterexample is None:
                raise ValueError("unsafe PPMC result requires exactly one counterexample")
            if self.indeterminate_predicates:
                raise ValueError("unsafe PPMC result must not summarize indeterminate predicates")
            if self.terminal_forbidden_evaluation_sha256 is None:
                raise ValueError("unsafe PPMC result requires terminal forbidden evaluation")
            if (
                self.counterexample.initial_state_sha256 != self.initial_state_sha256
                or self.counterexample.grammar_sha256 != self.grammar_sha256
                or self.counterexample.terminal_forbidden_evaluation_sha256
                != self.terminal_forbidden_evaluation_sha256
            ):
                raise ValueError("PPMC counterexample commitments do not match the search result")
        elif self.status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND:
            if (
                self.failure_reason is not None
                or self.counterexample is not None
                or self.indeterminate_predicates
                or self.terminal_forbidden_evaluation_sha256 is not None
            ):
                raise ValueError("no-counterexample PPMC result cannot contain failure artifacts")
        else:
            if self.failure_reason is None or self.counterexample is not None:
                raise ValueError("fail-closed PPMC result requires a failure reason and no trace")
            if self.failure_reason == PpmcFailureReason.INDETERMINATE_SECURITY_PREDICATE:
                if not self.indeterminate_predicates:
                    raise ValueError("indeterminate PPMC failure requires predicate identifiers")
                if self.terminal_forbidden_evaluation_sha256 is None:
                    raise ValueError("indeterminate PPMC failure requires terminal evaluation")
            else:
                if self.indeterminate_predicates:
                    raise ValueError("non-indeterminate PPMC failure cannot carry predicates")
                if self.terminal_forbidden_evaluation_sha256 is not None:
                    raise ValueError("non-indeterminate PPMC failure cannot carry terminal evaluation")

        if self.result_sha256 != compute_ppmc_result_sha256(self):
            raise ValueError("PPMC result hash mismatch")
        return self


def build_ppmc_search_config(
    *,
    bound: int = _DEFAULT_BOUND,
    max_states: int = _DEFAULT_MAX_STATES,
) -> PpmcSearchConfig:
    provisional = PpmcSearchConfig.model_construct(
        bound=bound,
        max_states=max_states,
        config_sha256="0" * 64,
    )
    return PpmcSearchConfig(
        bound=bound,
        max_states=max_states,
        config_sha256=compute_ppmc_config_sha256(provisional),
    )


def build_local_oracle_decision(
    *,
    oracle_version: str,
    state_sha256: str,
    action_sha256: str,
    admissible: bool,
    reason_codes: tuple[str, ...] = (),
) -> LocalOracleDecision:
    canonical_reasons = tuple(sorted(set(reason_codes)))
    provisional = LocalOracleDecision.model_construct(
        oracle_version=oracle_version,
        state_sha256=state_sha256,
        action_sha256=action_sha256,
        admissible=admissible,
        reason_codes=canonical_reasons,
        decision_sha256="0" * 64,
    )
    return LocalOracleDecision(
        oracle_version=oracle_version,
        state_sha256=state_sha256,
        action_sha256=action_sha256,
        admissible=admissible,
        reason_codes=canonical_reasons,
        decision_sha256=compute_local_oracle_decision_sha256(provisional),
    )


def compute_ppmc_config_sha256(config: PpmcSearchConfig) -> str:
    return canonical_json_sha256(config.model_dump(mode="json", exclude={"config_sha256"}))


def compute_local_oracle_decision_sha256(decision: LocalOracleDecision) -> str:
    return canonical_json_sha256(decision.model_dump(mode="json", exclude={"decision_sha256"}))


def compute_ppmc_result_sha256(result: PpmcSearchResult) -> str:
    return canonical_json_sha256(result.model_dump(mode="json", exclude={"result_sha256"}))
