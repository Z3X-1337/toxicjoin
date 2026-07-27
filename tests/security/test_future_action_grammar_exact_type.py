from __future__ import annotations

from pathlib import Path
import runpy

import pytest

from toxicjoin.disclosure.models import DisclosureSemanticRelease
from toxicjoin.policy import load_policy
from toxicjoin.prospective.forbidden import build_forbidden_predicate_policy
from toxicjoin.prospective.grammar import (
    FutureAction,
    FutureActionGrammar,
    FutureActionGrammarContext,
)
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


def _run_ppmc(*, state, grammar, ppmc_evaluation):  # noqa: ANN001, ANN201
    package_policy = load_policy()
    return check_prospective_privacy(
        initial_state=state,
        grammar=grammar,
        forbidden_policy=build_forbidden_predicate_policy(
            minimum_group_size=package_policy.minimum_group_size
        ),
        governance_binding=ppmc_evaluation.f6_clearance.f6_binding,
        local_oracle=_admit_all,
        config=build_ppmc_search_config(bound=1, max_states=128),
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

    try:
        result = _run_ppmc(
            state=state,
            grammar=malicious,
            ppmc_evaluation=ppmc_evaluation,
        )
    except PpmcError as error:
        assert "trusted input failed canonical revalidation" in str(error)
        return

    assert result.status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND
    assert result.actions_considered == 0
    pytest.fail(
        "PPMC accepted a polymorphic grammar and certified an empty search universe"
    )


def test_ppmc_rejects_nested_context_subclass_before_virtual_serialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, _, ppmc_evaluation, state, legitimate = _upstream(monkeypatch)

    class MaliciousContext(FutureActionGrammarContext):
        def model_dump(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
            raise AssertionError("context virtual serialization must not run")

    malicious_context = MaliciousContext.model_construct(**legitimate.context.__dict__)
    malicious = FutureActionGrammar.model_construct(
        **{**legitimate.__dict__, "context": malicious_context}
    )

    with pytest.raises(PpmcError, match="trusted input failed canonical revalidation"):
        _run_ppmc(state=state, grammar=malicious, ppmc_evaluation=ppmc_evaluation)


def test_ppmc_rejects_nested_action_subclass_before_virtual_serialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, _, ppmc_evaluation, state, legitimate = _upstream(monkeypatch)
    action = legitimate.actions[0]

    class MaliciousAction(FutureAction):
        def model_dump(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
            raise AssertionError("action virtual serialization must not run")

    malicious_action = MaliciousAction.model_construct(**action.__dict__)
    malicious = FutureActionGrammar.model_construct(
        **{
            **legitimate.__dict__,
            "actions": (malicious_action, *legitimate.actions[1:]),
        }
    )

    with pytest.raises(PpmcError, match="trusted input failed canonical revalidation"):
        _run_ppmc(state=state, grammar=malicious, ppmc_evaluation=ppmc_evaluation)


def test_ppmc_rejects_nested_semantic_subclass_before_virtual_serialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, _, ppmc_evaluation, state, legitimate = _upstream(monkeypatch)
    semantic = legitimate.context.base_semantic

    class MaliciousSemantic(DisclosureSemanticRelease):
        def model_dump(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
            raise AssertionError("semantic virtual serialization must not run")

    malicious_semantic = MaliciousSemantic.model_construct(**semantic.__dict__)
    malicious_context = FutureActionGrammarContext.model_construct(
        **{
            **legitimate.context.__dict__,
            "base_semantic": malicious_semantic,
        }
    )
    malicious = FutureActionGrammar.model_construct(
        **{**legitimate.__dict__, "context": malicious_context}
    )

    with pytest.raises(PpmcError, match="trusted input failed canonical revalidation"):
        _run_ppmc(state=state, grammar=malicious, ppmc_evaluation=ppmc_evaluation)
