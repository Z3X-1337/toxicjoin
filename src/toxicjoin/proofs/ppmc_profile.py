"""Security-owned PPMC profile required for pre-execution proof eligibility."""

from __future__ import annotations

import hmac

from toxicjoin.prospective.ppmc import build_ppmc_search_config

PREEXECUTION_PPMC_PROFILE = "p0-preexec-v1"
PREEXECUTION_PPMC_MIN_BOUND = 3


def is_approved_preexecution_ppmc_profile(
    *,
    profile: str,
    bound: int,
    max_states: int,
    config_sha256: str,
) -> bool:
    """Return whether the committed PPMC configuration is proof-eligible.

    The profile deliberately constrains only security-relevant proof semantics. A search bound
    below three is not eligible for pre-execution proof. Larger legal bounds are accepted because
    they are monotonic-strengthening under the same finite grammar. ``max_states`` is not assigned
    an arbitrary minimum: exhaustion already makes PPMC fail closed. Its exact value is instead
    rebound into the canonical PPMC configuration commitment.
    """

    if profile != PREEXECUTION_PPMC_PROFILE or bound < PREEXECUTION_PPMC_MIN_BOUND:
        return False
    try:
        expected = build_ppmc_search_config(bound=bound, max_states=max_states)
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(expected.config_sha256, config_sha256)
