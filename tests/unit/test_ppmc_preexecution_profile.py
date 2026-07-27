from __future__ import annotations

from toxicjoin.proofs.ppmc_profile import (
    PREEXECUTION_PPMC_BOUND,
    PREEXECUTION_PPMC_MAX_STATES,
    PREEXECUTION_PPMC_PROFILE,
    build_preexecution_ppmc_search_config,
    is_approved_preexecution_ppmc_profile,
)
from toxicjoin.prospective.ppmc import build_ppmc_search_config


def _approved(*, bound: int, max_states: int) -> bool:
    config = build_ppmc_search_config(bound=bound, max_states=max_states)
    return is_approved_preexecution_ppmc_profile(
        profile=PREEXECUTION_PPMC_PROFILE,
        bound=bound,
        max_states=max_states,
        config_sha256=config.config_sha256,
    )


def test_preexecution_profile_builder_is_fixed_and_approved() -> None:
    config = build_preexecution_ppmc_search_config()

    assert config.bound == PREEXECUTION_PPMC_BOUND == 3
    assert config.max_states == PREEXECUTION_PPMC_MAX_STATES == 256
    assert _approved(bound=config.bound, max_states=config.max_states) is True


def test_preexecution_profile_rejects_deeper_generic_search() -> None:
    generic = build_ppmc_search_config(bound=5, max_states=PREEXECUTION_PPMC_MAX_STATES)

    assert generic.bound == 5
    assert is_approved_preexecution_ppmc_profile(
        profile=PREEXECUTION_PPMC_PROFILE,
        bound=generic.bound,
        max_states=generic.max_states,
        config_sha256=generic.config_sha256,
    ) is False


def test_preexecution_profile_rejects_generic_state_budget_above_execution_ceiling() -> None:
    generic = build_ppmc_search_config(bound=3, max_states=50_000)

    assert generic.max_states == 50_000
    assert is_approved_preexecution_ppmc_profile(
        profile=PREEXECUTION_PPMC_PROFILE,
        bound=generic.bound,
        max_states=generic.max_states,
        config_sha256=generic.config_sha256,
    ) is False


def test_smaller_state_budget_remains_proof_eligible_when_search_completed() -> None:
    # A smaller budget cannot silently certify an incomplete search: the PPMC engine
    # returns STATE_BUDGET_EXHAUSTED / FAIL_CLOSED when the reachable set exceeds it.
    assert _approved(bound=3, max_states=128) is True


def test_profile_rejects_valid_values_with_wrong_config_commitment() -> None:
    assert is_approved_preexecution_ppmc_profile(
        profile=PREEXECUTION_PPMC_PROFILE,
        bound=PREEXECUTION_PPMC_BOUND,
        max_states=PREEXECUTION_PPMC_MAX_STATES,
        config_sha256="0" * 64,
    ) is False
