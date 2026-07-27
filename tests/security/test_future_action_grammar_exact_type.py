from __future__ import annotations

from pathlib import Path
import runpy

import pytest

from toxicjoin.policy import load_policy
from toxicjoin.prospective.forbidden import build_forbidden_predicate_policy
from toxicjoin.prospective.grammar import FutureActionGrammar
from toxicjoin.prospective.ppmc import (
    PpmcError,
    PpmcStatus,
    build_local_oracle_decision,
    build_ppmc_search_config,
    check_prospective_privacy,
)

_HELPERS = runpy.run_path(
    str(Path(__file__).with_name("test_agent_preexecution_proof_authority.py"))
)
_upstream = _HELPERS["_upstream"]


def _admit_all(state, action):  # noqa: ANN001, ANN201
    return build_local_oracle_decision(
        oracle_version="phase-11-exact-type-test",
        state_sha256=state.state_sha256,
        action_sha256=action.action_sha256,
        admissible=True,
    )


def test_ppmc_rejects_polymorphic_grammar_before_virtual_serialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, _, ppmc_evaluation, state, legitimate = _upstream(monkeypatch)
    assert legitimate.actions

    class MaliciousGrammar(FutureActionGrammar):
        def model_dump(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
            return legitimate.model_dump(*args, **kwargs)

    malicious = MaliciousGrammar.model_construct(
        **{
            **legitimate.__dict__,
            "actions": (),
        }
    )

    assert malicious.actions == ()
    assert malicious.grammar_sha256 == legitimate.grammar_sha256
    assert malicious.model_dump(mode="json") == legitimate.model_dump(mode="json")

    package_policy = load_policy()
    try:
        result = check_prospective_privacy(
            initial_state=state,
            grammar=malicious,
            forbidden_policy=build_forbidden_predicate_policy(
                minimum_group_size=package_policy.minimum_group_size
            ),
            governance_binding=ppmc_evaluation.f6_clearance.f6_binding,
            local_oracle=_admit_all,
            config=build_ppmc_search_config(bound=1, max_states=128),
        )
    except PpmcError as error:
        assert "trusted input failed canonical revalidation" in str(error)
        return

    assert result.status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND
    assert result.actions_considered == 0
    pytest.fail(
        "PPMC accepted a polymorphic grammar and certified an empty search universe"
    )
