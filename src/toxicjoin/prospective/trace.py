"""Canonical replayable counterexample trace commitments for bounded PPMC.

These models do not search and do not claim shortestness. The later deterministic BFS
constructs them after replaying exact grammar actions and local-oracle commitments.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator

from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.models import StrictModel
from toxicjoin.prospective.forbidden import ForbiddenPredicateId

_HASH_PATTERN = r"^[0-9a-f]{64}$"
Sha256 = Annotated[str, Field(pattern=_HASH_PATTERN)]


class CounterexampleStep(StrictModel):
    """One exact deterministic state transition in a counterexample path."""

    schema_version: Literal["1.0"] = "1.0"
    step_index: int = Field(ge=0, le=4)
    pre_state_sha256: str = Field(pattern=_HASH_PATTERN)
    action_sha256: str = Field(pattern=_HASH_PATTERN)
    local_oracle_commitment_sha256: str = Field(pattern=_HASH_PATTERN)
    post_state_sha256: str = Field(pattern=_HASH_PATTERN)
    step_sha256: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_step(self) -> "CounterexampleStep":
        if self.step_sha256 != compute_counterexample_step_sha256(self):
            raise ValueError("counterexample step hash mismatch")
        return self


class CounterexampleTrace(StrictModel):
    """Replayable bounded witness ending in at least one matched forbidden predicate."""

    schema_version: Literal["1.0"] = "1.0"
    bound: int = Field(ge=0, le=5)
    initial_state_sha256: str = Field(pattern=_HASH_PATTERN)
    grammar_sha256: str = Field(pattern=_HASH_PATTERN)
    steps: tuple[CounterexampleStep, ...] = Field(default=(), max_length=5)
    terminal_state_sha256: str = Field(pattern=_HASH_PATTERN)
    terminal_forbidden_evaluation_sha256: str = Field(pattern=_HASH_PATTERN)
    terminal_matched_predicates: tuple[ForbiddenPredicateId, ...] = Field(
        min_length=1,
        max_length=6,
    )
    trace_sha256: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_trace(self) -> "CounterexampleTrace":
        if len(self.steps) > self.bound:
            raise ValueError("counterexample trace exceeds declared bound")
        expected_indices = tuple(range(len(self.steps)))
        actual_indices = tuple(step.step_index for step in self.steps)
        if actual_indices != expected_indices:
            raise ValueError("counterexample steps must use contiguous zero-based indices")
        if self.steps:
            if self.steps[0].pre_state_sha256 != self.initial_state_sha256:
                raise ValueError("counterexample first step does not start at initial state")
            for previous, current in zip(self.steps, self.steps[1:], strict=False):
                if previous.post_state_sha256 != current.pre_state_sha256:
                    raise ValueError("counterexample state chain is broken")
            if self.steps[-1].post_state_sha256 != self.terminal_state_sha256:
                raise ValueError("counterexample terminal state does not match final step")
        elif self.terminal_state_sha256 != self.initial_state_sha256:
            raise ValueError("zero-step counterexample must terminate at initial state")

        canonical_predicates = tuple(
            predicate
            for predicate in ForbiddenPredicateId
            if predicate in set(self.terminal_matched_predicates)
        )
        if self.terminal_matched_predicates != canonical_predicates:
            raise ValueError("counterexample matched predicates must be canonical and unique")
        if self.trace_sha256 != compute_counterexample_trace_sha256(self):
            raise ValueError("counterexample trace hash mismatch")
        return self


def build_counterexample_step(
    *,
    step_index: int,
    pre_state_sha256: str,
    action_sha256: str,
    local_oracle_commitment_sha256: str,
    post_state_sha256: str,
) -> CounterexampleStep:
    provisional = CounterexampleStep.model_construct(
        step_index=step_index,
        pre_state_sha256=pre_state_sha256,
        action_sha256=action_sha256,
        local_oracle_commitment_sha256=local_oracle_commitment_sha256,
        post_state_sha256=post_state_sha256,
        step_sha256="0" * 64,
    )
    return CounterexampleStep(
        step_index=step_index,
        pre_state_sha256=pre_state_sha256,
        action_sha256=action_sha256,
        local_oracle_commitment_sha256=local_oracle_commitment_sha256,
        post_state_sha256=post_state_sha256,
        step_sha256=compute_counterexample_step_sha256(provisional),
    )


def build_counterexample_trace(
    *,
    bound: int,
    initial_state_sha256: str,
    grammar_sha256: str,
    steps: tuple[CounterexampleStep, ...],
    terminal_state_sha256: str,
    terminal_forbidden_evaluation_sha256: str,
    terminal_matched_predicates: tuple[ForbiddenPredicateId, ...],
) -> CounterexampleTrace:
    canonical_predicates = tuple(
        predicate
        for predicate in ForbiddenPredicateId
        if predicate in set(terminal_matched_predicates)
    )
    provisional = CounterexampleTrace.model_construct(
        bound=bound,
        initial_state_sha256=initial_state_sha256,
        grammar_sha256=grammar_sha256,
        steps=steps,
        terminal_state_sha256=terminal_state_sha256,
        terminal_forbidden_evaluation_sha256=terminal_forbidden_evaluation_sha256,
        terminal_matched_predicates=canonical_predicates,
        trace_sha256="0" * 64,
    )
    return CounterexampleTrace(
        bound=bound,
        initial_state_sha256=initial_state_sha256,
        grammar_sha256=grammar_sha256,
        steps=steps,
        terminal_state_sha256=terminal_state_sha256,
        terminal_forbidden_evaluation_sha256=terminal_forbidden_evaluation_sha256,
        terminal_matched_predicates=canonical_predicates,
        trace_sha256=compute_counterexample_trace_sha256(provisional),
    )


def compute_counterexample_step_sha256(step: CounterexampleStep) -> str:
    return canonical_json_sha256(step.model_dump(mode="json", exclude={"step_sha256"}))


def compute_counterexample_trace_sha256(trace: CounterexampleTrace) -> str:
    return canonical_json_sha256(trace.model_dump(mode="json", exclude={"trace_sha256"}))
