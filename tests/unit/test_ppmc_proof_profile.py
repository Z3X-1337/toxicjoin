from __future__ import annotations

import pytest

from toxicjoin.proofs.ppmc_profile import (
    PREEXECUTION_PPMC_BOUND,
    PREEXECUTION_PPMC_MAX_STATES,
    PREEXECUTION_PPMC_PROFILE,
    build_preexecution_ppmc_search_config,
    is_approved_preexecution_ppmc_profile,
)
from toxicjoin.prospective.ppmc import build_ppmc_search_config


@pytest.mark.parametrize("bound", (0, 1, 2))
def test_preexecution_profile_rejects_weak_bounds(bound: int) -> None:
    config = build_ppmc_search_config(bound=bound, max_states=100)

    assert not is_approved_preexecution_ppmc_profile(
        profile=PREEXECUTION_PPMC_PROFILE,
        bound=bound,
        max_states=100,
        config_sha256=config.config_sha256,
    )


def test_preexecution_profile_accepts_exact_security_owned_bound() -> None:
    config = build_ppmc_search_config(bound=PREEXECUTION_PPMC_BOUND, max_states=100)

    assert is_approved_preexecution_ppmc_profile(
        profile=PREEXECUTION_PPMC_PROFILE,
        bound=PREEXECUTION_PPMC_BOUND,
        max_states=100,
        config_sha256=config.config_sha256,
    )


@pytest.mark.parametrize("bound", (4, 5))
def test_preexecution_profile_rejects_deeper_generic_bounds(bound: int) -> None:
    config = build_ppmc_search_config(bound=bound, max_states=100)

    assert not is_approved_preexecution_ppmc_profile(
        profile=PREEXECUTION_PPMC_PROFILE,
        bound=bound,
        max_states=100,
        config_sha256=config.config_sha256,
    )


def test_preexecution_profile_rejects_state_budget_above_execution_ceiling() -> None:
    config = build_ppmc_search_config(
        bound=PREEXECUTION_PPMC_BOUND,
        max_states=PREEXECUTION_PPMC_MAX_STATES + 1,
    )

    assert not is_approved_preexecution_ppmc_profile(
        profile=PREEXECUTION_PPMC_PROFILE,
        bound=config.bound,
        max_states=config.max_states,
        config_sha256=config.config_sha256,
    )


def test_preexecution_profile_rejects_legacy_v1_identifier() -> None:
    config = build_ppmc_search_config(
        bound=PREEXECUTION_PPMC_BOUND,
        max_states=PREEXECUTION_PPMC_MAX_STATES,
    )

    assert PREEXECUTION_PPMC_PROFILE == "p0-preexec-v2"
    assert not is_approved_preexecution_ppmc_profile(
        profile="p0-preexec-v1",
        bound=config.bound,
        max_states=config.max_states,
        config_sha256=config.config_sha256,
    )


def test_preexecution_profile_rejects_config_rebinding() -> None:
    assert not is_approved_preexecution_ppmc_profile(
        profile=PREEXECUTION_PPMC_PROFILE,
        bound=PREEXECUTION_PPMC_BOUND,
        max_states=100,
        config_sha256="f" * 64,
    )


def test_preexecution_profile_does_not_invent_state_budget_floor() -> None:
    config = build_ppmc_search_config(bound=PREEXECUTION_PPMC_BOUND, max_states=1)

    assert is_approved_preexecution_ppmc_profile(
        profile=PREEXECUTION_PPMC_PROFILE,
        bound=config.bound,
        max_states=config.max_states,
        config_sha256=config.config_sha256,
    )


def test_security_owned_builder_emits_exact_execution_ceiling() -> None:
    config = build_preexecution_ppmc_search_config()

    assert config.bound == PREEXECUTION_PPMC_BOUND == 3
    assert config.max_states == PREEXECUTION_PPMC_MAX_STATES == 256
