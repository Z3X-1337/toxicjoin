from __future__ import annotations

from datetime import datetime, timezone
import inspect

import pytest

from toxicjoin.agent.ppmc_authority import (
    AgentPpmcAuthorityError,
    DataHubAgentPpmcAuthority,
)


def test_agent_ppmc_authority_does_not_accept_caller_supplied_f6_authority() -> None:
    parameters = inspect.signature(DataHubAgentPpmcAuthority.check).parameters

    assert "evaluation" in parameters
    assert "governance_trust" in parameters
    assert "initial_state" in parameters
    assert "f6_clearance" not in parameters
    assert "governance_binding" not in parameters
    assert "f6_binding" not in parameters
    assert "trusted" not in parameters


def test_f6_and_ppmc_share_one_monotonic_clock_guard() -> None:
    samples = iter(
        (
            datetime(2026, 7, 27, 5, 0, 10, tzinfo=timezone.utc),
            datetime(2026, 7, 27, 5, 0, 20, tzinfo=timezone.utc),
            datetime(2026, 7, 27, 5, 0, 15, tzinfo=timezone.utc),
        )
    )
    authority = DataHubAgentPpmcAuthority(clock=lambda: next(samples))

    assert authority._f6_authority._sample_clock() == datetime(
        2026, 7, 27, 5, 0, 10, tzinfo=timezone.utc
    )
    assert authority._f6_authority._sample_clock() == datetime(
        2026, 7, 27, 5, 0, 20, tzinfo=timezone.utc
    )
    with pytest.raises(AgentPpmcAuthorityError, match="AGENT_PPMC_TIME_ROLLBACK"):
        authority._sample_clock()
