"""Security-owned PPMC resource profile required for pre-execution proof eligibility."""

from __future__ import annotations

import hmac

from toxicjoin.prospective.ppmc import PpmcSearchConfig, build_ppmc_search_config

PREEXECUTION_PPMC_PROFILE = "p0-preexec-v1"
PREEXECUTION_PPMC_BOUND = 3
PREEXECUTION_PPMC_MAX_STATES = 256


def build_preexecution_ppmc_search_config() -> PpmcSearchConfig:
    """Return the fixed search profile owned by the proof-producing runtime.

    Generic/offline PPMC remains separately configurable.  Execution-eligible Agent
    handoff deliberately owns this deterministic budget so callers cannot trade
    resource consumption against the security model before proof issuance.
    """

    return build_ppmc_search_config(
        bound=PREEXECUTION_PPMC_BOUND,
        max_states=PREEXECUTION_PPMC_MAX_STATES,
    )


def is_approved_preexecution_ppmc_profile(
    *,
    profile: str,
    bound: int,
    max_states: int,
    config_sha256: str,
) -> bool:
    """Return whether a committed PPMC configuration is execution-proof eligible.

    Bound three is the exact P0 pre-execution semantic horizon.  Deeper generic
    searches remain available for analysis but are not allowed to enlarge synchronous
    execution-path work.  A smaller state budget remains semantically safe because
    exhaustion is explicit FAIL_CLOSED; the profile only imposes the upper resource
    ceiling.  The authenticated Agent path itself always emits the fixed maximum.
    """

    if profile != PREEXECUTION_PPMC_PROFILE or bound != PREEXECUTION_PPMC_BOUND:
        return False
    if max_states < 1 or max_states > PREEXECUTION_PPMC_MAX_STATES:
        return False
    try:
        expected = build_ppmc_search_config(bound=bound, max_states=max_states)
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(expected.config_sha256, config_sha256)
