from __future__ import annotations

import inspect

from toxicjoin.agent import DataHubAgentPreExecutionProofAuthority


def test_agent_proof_authority_does_not_accept_caller_auth_identity() -> None:
    """Authenticated request identity must come from the security-owned request context."""

    parameters = inspect.signature(DataHubAgentPreExecutionProofAuthority.build).parameters

    assert "identity" not in parameters
