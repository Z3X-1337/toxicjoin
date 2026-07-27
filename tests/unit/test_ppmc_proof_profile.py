from __future__ import annotations

import pytest

from toxicjoin.proofs.ppmc_profile import (
    PREEXECUTION_PPMC_PROFILE,
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


@pytest.mark.parametrize("bound", (3, 4, 5))
def test_preexecution_profile_accepts_canonical_stronger_bounds(bound: int) -> None:
    config = build_ppmc_search_config(bound=bound, max_states=100)

    assert is_approved_preexecution_ppmc_profile(
        profile=PREEXECUTION_PPMC_PROFILE,
        bound=bound,
        max_states=100,
        config_sha256=config.config_sha256,
    )


def test_preexecution_profile_rejects_config_rebinding() -> None:
    assert not is_approved_preexecution_ppmc_profile(
        profile=PREEXECUTION_PPMC_PROFILE,
        bound=3,
        max_states=100,
        config_sha256="f" * 64,
    )


def test_preexecution_profile_does_not_invent_state_budget_floor() -> None:
    config = build_ppmc_search_config(bound=3, max_states=1)

    assert is_approved_preexecution_ppmc_profile(
        profile=PREEXECUTION_PPMC_PROFILE,
        bound=3,
        max_states=1,
        config_sha256=config.config_sha256,
    )
