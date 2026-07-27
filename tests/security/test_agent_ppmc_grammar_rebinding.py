from __future__ import annotations

from datetime import timedelta

import pytest

from tests.security.test_agent_ppmc_clearance_bridge import (
    NOW,
    _artifacts,
    _unexpected_oracle,
)
from toxicjoin.agent.ppmc_authority import (
    AgentPpmcAuthorityError,
    DataHubAgentPpmcAuthority,
)
from toxicjoin.prospective.grammar import (
    FutureActionGrammarContext,
    compute_future_action_context_sha256,
    instantiate_future_action_grammar,
)


def _rebind_context(grammar, *, field: str, value: str):
    provisional = grammar.context.model_copy(
        update={field: value, "context_sha256": "0" * 64}
    )
    rebound = provisional.model_copy(
        update={"context_sha256": compute_future_action_context_sha256(provisional)}
    )
    canonical_context = FutureActionGrammarContext.model_validate(
        rebound.model_dump(mode="json")
    )
    return instantiate_future_action_grammar(canonical_context)


@pytest.mark.parametrize(
    ("field", "error_code"),
    (
        ("scope_sha256", "AGENT_PPMC_GRAMMAR_SCOPE_MISMATCH"),
        ("purpose_commitment_sha256", "AGENT_PPMC_GRAMMAR_PURPOSE_MISMATCH"),
        ("governance_commitment_sha256", "AGENT_PPMC_GRAMMAR_GOVERNANCE_MISMATCH"),
        ("evidence_root_sha256", "AGENT_PPMC_GRAMMAR_EVIDENCE_MISMATCH"),
        ("base_warehouse_snapshot_sha256", "AGENT_PPMC_GRAMMAR_SNAPSHOT_MISMATCH"),
    ),
)
def test_self_consistent_grammar_context_rebinding_fails_closed_at_bound_zero(
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    error_code: str,
) -> None:
    (
        evaluation,
        governance_trust,
        state,
        grammar,
        forbidden_policy,
        config,
        _,
        _,
    ) = _artifacts(monkeypatch)
    forged_grammar = _rebind_context(grammar, field=field, value="a" * 64)

    with pytest.raises(AgentPpmcAuthorityError, match=error_code):
        DataHubAgentPpmcAuthority(clock=lambda: NOW + timedelta(seconds=4)).check(
            evaluation=evaluation,
            governance_trust=governance_trust,
            initial_state=state,
            grammar=forged_grammar,
            forbidden_policy=forbidden_policy,
            local_oracle=_unexpected_oracle,
            config=config,
        )
