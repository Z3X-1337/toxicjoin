from __future__ import annotations

from pydantic import ValidationError
import pytest

from toxicjoin.prospective.forbidden import ForbiddenPredicateId
from toxicjoin.prospective.trace import (
    CounterexampleStep,
    CounterexampleTrace,
    build_counterexample_step,
    build_counterexample_trace,
)


INITIAL = "1" * 64
STATE_1 = "2" * 64
STATE_2 = "3" * 64
GRAMMAR = "4" * 64
ACTION_1 = "5" * 64
ACTION_2 = "6" * 64
ORACLE_1 = "7" * 64
ORACLE_2 = "8" * 64
FORBIDDEN = "9" * 64


def test_counterexample_trace_chains_exact_states_and_actions() -> None:
    step0 = build_counterexample_step(
        step_index=0,
        pre_state_sha256=INITIAL,
        action_sha256=ACTION_1,
        local_oracle_commitment_sha256=ORACLE_1,
        post_state_sha256=STATE_1,
    )
    step1 = build_counterexample_step(
        step_index=1,
        pre_state_sha256=STATE_1,
        action_sha256=ACTION_2,
        local_oracle_commitment_sha256=ORACLE_2,
        post_state_sha256=STATE_2,
    )

    trace = build_counterexample_trace(
        bound=3,
        initial_state_sha256=INITIAL,
        grammar_sha256=GRAMMAR,
        steps=(step0, step1),
        terminal_state_sha256=STATE_2,
        terminal_forbidden_evaluation_sha256=FORBIDDEN,
        terminal_matched_predicates=(
            ForbiddenPredicateId.F4_CROSS_RELEASE_COMPOSITION,
            ForbiddenPredicateId.F2_STABLE_LINKABLE_SENSITIVE,
        ),
    )

    assert len(trace.steps) == 2
    assert trace.terminal_matched_predicates == (
        ForbiddenPredicateId.F2_STABLE_LINKABLE_SENSITIVE,
        ForbiddenPredicateId.F4_CROSS_RELEASE_COMPOSITION,
    )


def test_zero_step_counterexample_is_valid_for_forbidden_initial_state() -> None:
    trace = build_counterexample_trace(
        bound=0,
        initial_state_sha256=INITIAL,
        grammar_sha256=GRAMMAR,
        steps=(),
        terminal_state_sha256=INITIAL,
        terminal_forbidden_evaluation_sha256=FORBIDDEN,
        terminal_matched_predicates=(ForbiddenPredicateId.F6_UNTRUSTED_GOVERNANCE_AUTHORIZATION,),
    )

    assert trace.steps == ()
    assert trace.terminal_state_sha256 == INITIAL


def test_trace_rejects_broken_state_chain() -> None:
    step0 = build_counterexample_step(
        step_index=0,
        pre_state_sha256=INITIAL,
        action_sha256=ACTION_1,
        local_oracle_commitment_sha256=ORACLE_1,
        post_state_sha256=STATE_1,
    )
    step1 = build_counterexample_step(
        step_index=1,
        pre_state_sha256=STATE_2,
        action_sha256=ACTION_2,
        local_oracle_commitment_sha256=ORACLE_2,
        post_state_sha256=STATE_2,
    )

    with pytest.raises(ValidationError, match="state chain is broken"):
        build_counterexample_trace(
            bound=2,
            initial_state_sha256=INITIAL,
            grammar_sha256=GRAMMAR,
            steps=(step0, step1),
            terminal_state_sha256=STATE_2,
            terminal_forbidden_evaluation_sha256=FORBIDDEN,
            terminal_matched_predicates=(ForbiddenPredicateId.F4_CROSS_RELEASE_COMPOSITION,),
        )


def test_trace_rejects_noncontiguous_step_indices() -> None:
    step = build_counterexample_step(
        step_index=1,
        pre_state_sha256=INITIAL,
        action_sha256=ACTION_1,
        local_oracle_commitment_sha256=ORACLE_1,
        post_state_sha256=STATE_1,
    )

    with pytest.raises(ValidationError, match="contiguous zero-based"):
        build_counterexample_trace(
            bound=2,
            initial_state_sha256=INITIAL,
            grammar_sha256=GRAMMAR,
            steps=(step,),
            terminal_state_sha256=STATE_1,
            terminal_forbidden_evaluation_sha256=FORBIDDEN,
            terminal_matched_predicates=(ForbiddenPredicateId.F4_CROSS_RELEASE_COMPOSITION,),
        )


def test_trace_rejects_length_beyond_bound() -> None:
    step0 = build_counterexample_step(
        step_index=0,
        pre_state_sha256=INITIAL,
        action_sha256=ACTION_1,
        local_oracle_commitment_sha256=ORACLE_1,
        post_state_sha256=STATE_1,
    )

    with pytest.raises(ValidationError, match="exceeds declared bound"):
        build_counterexample_trace(
            bound=0,
            initial_state_sha256=INITIAL,
            grammar_sha256=GRAMMAR,
            steps=(step0,),
            terminal_state_sha256=STATE_1,
            terminal_forbidden_evaluation_sha256=FORBIDDEN,
            terminal_matched_predicates=(ForbiddenPredicateId.F1_DIRECT_SENSITIVE_LINKAGE,),
        )


def test_trace_and_step_hash_tampering_are_rejected() -> None:
    step = build_counterexample_step(
        step_index=0,
        pre_state_sha256=INITIAL,
        action_sha256=ACTION_1,
        local_oracle_commitment_sha256=ORACLE_1,
        post_state_sha256=STATE_1,
    )
    step_payload = step.model_dump(mode="json")
    step_payload["step_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="step hash mismatch"):
        CounterexampleStep.model_validate(step_payload)

    trace = build_counterexample_trace(
        bound=1,
        initial_state_sha256=INITIAL,
        grammar_sha256=GRAMMAR,
        steps=(step,),
        terminal_state_sha256=STATE_1,
        terminal_forbidden_evaluation_sha256=FORBIDDEN,
        terminal_matched_predicates=(ForbiddenPredicateId.F1_DIRECT_SENSITIVE_LINKAGE,),
    )
    trace_payload = trace.model_dump(mode="json")
    trace_payload["trace_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="trace hash mismatch"):
        CounterexampleTrace.model_validate(trace_payload)
