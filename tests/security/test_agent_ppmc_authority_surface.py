from __future__ import annotations

import inspect

from toxicjoin.agent.ppmc_authority import DataHubAgentPpmcAuthority


def test_agent_ppmc_authority_does_not_accept_caller_supplied_f6_authority() -> None:
    parameters = inspect.signature(DataHubAgentPpmcAuthority.check).parameters

    assert "evaluation" in parameters
    assert "governance_trust" in parameters
    assert "initial_state" in parameters
    assert "f6_clearance" not in parameters
    assert "governance_binding" not in parameters
    assert "f6_binding" not in parameters
    assert "trusted" not in parameters
