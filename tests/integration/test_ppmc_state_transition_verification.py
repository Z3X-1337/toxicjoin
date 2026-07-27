from __future__ import annotations

import pytest

import toxicjoin.benchmark.ppmc_hard_gate as hard_gate
from toxicjoin.disclosure.models import DisclosureScope
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.prospective.forbidden import (
    ForbiddenPredicateId,
    GovernanceTrustBinding,
    build_governance_trust_binding,
)
from toxicjoin.prospective.ppmc import (
    PpmcError,
    PpmcStatus,
    build_ppmc_search_config,
    check_prospective_privacy,
)
from toxicjoin.prospective.twin import DisclosureAtom, DisclosureState


def _capture_hard_gate_inputs(monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    captured: dict[str, object] = {}
    original_check = hard_gate.check_prospective_privacy

    def _capture_check(**kwargs):  # noqa: ANN003, ANN202
        captured.update(kwargs)
        return original_check(**kwargs)

    monkeypatch.setattr(hard_gate, "check_prospective_privacy", _capture_check)
    evidence = hard_gate.build_ppmc_hard_gate_evidence()
    assert evidence.gate_passed is True
    return captured


def test_ppmc_rejects_polymorphic_initial_state_before_transition_semantics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A virtually serialized state must not differ from the state searched by PPMC."""

    captured = _capture_hard_gate_inputs(monkeypatch)
    legitimate = captured["initial_state"]
    grammar = captured["grammar"]
    assert type(legitimate) is DisclosureState

    legitimate_result = check_prospective_privacy(**captured)
    assert legitimate_result.status == PpmcStatus.PROSPECTIVE_UNSAFE
    assert legitimate_result.counterexample is not None
    assert len(legitimate_result.counterexample.steps) == 2

    runtime_only_snapshot = canonical_json_sha256(
        {"snapshot": "phase-12-polymorphic-runtime-only"}
    )
    declared_snapshots = {
        grammar.context.base_warehouse_snapshot_sha256,
        *(edge.from_snapshot_sha256 for edge in grammar.context.snapshot_transitions),
        *(edge.to_snapshot_sha256 for edge in grammar.context.snapshot_transitions),
    }
    assert runtime_only_snapshot not in declared_snapshots

    class MaliciousDisclosureState(DisclosureState):
        def model_dump(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
            return legitimate.model_dump(*args, **kwargs)

    malicious = MaliciousDisclosureState.model_construct(
        **{
            **legitimate.__dict__,
            "warehouse_snapshot_sha256": runtime_only_snapshot,
        }
    )

    assert malicious.state_sha256 == legitimate.state_sha256
    assert malicious.warehouse_snapshot_sha256 == runtime_only_snapshot
    assert malicious.model_dump(mode="json") == legitimate.model_dump(mode="json")

    try:
        result = check_prospective_privacy(
            **{
                **captured,
                "initial_state": malicious,
            }
        )
    except PpmcError as error:
        assert "trusted input failed canonical revalidation" in str(error)
        return

    assert result.status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND
    assert result.transition_rejections == len(grammar.actions)
    assert result.oracle_admissions == 0
    pytest.fail(
        "PPMC accepted a polymorphic DisclosureState and certified safety after "
        "runtime-only state semantics pruned the declared transition graph"
    )


def test_ppmc_still_revalidates_exact_state_constructed_without_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = _capture_hard_gate_inputs(monkeypatch)
    legitimate = captured["initial_state"]
    assert type(legitimate) is DisclosureState

    corrupt = DisclosureState.model_construct(
        **{
            **legitimate.__dict__,
            "warehouse_snapshot_sha256": canonical_json_sha256(
                {"snapshot": "phase-12-exact-constructed-corruption"}
            ),
        }
    )
    assert type(corrupt) is DisclosureState
    assert corrupt.state_sha256 == legitimate.state_sha256

    with pytest.raises(PpmcError, match="trusted input failed canonical revalidation"):
        check_prospective_privacy(
            **{
                **captured,
                "initial_state": corrupt,
            }
        )


def test_ppmc_nested_scope_subclass_cannot_split_revalidation_from_transition_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = _capture_hard_gate_inputs(monkeypatch)
    legitimate = captured["initial_state"]
    grammar = captured["grammar"]
    assert type(legitimate) is DisclosureState
    legitimate_scope = legitimate.scope
    assert type(legitimate_scope) is DisclosureScope

    class MaliciousScope(DisclosureScope):
        def model_dump(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
            return legitimate_scope.model_dump(*args, **kwargs)

    malicious_scope = MaliciousScope.model_construct(
        **{
            **legitimate_scope.__dict__,
            "scope_sha256": canonical_json_sha256(
                {"scope": "phase-12-polymorphic-runtime-only"}
            ),
        }
    )
    malicious_state = DisclosureState.model_construct(
        **{
            **legitimate.__dict__,
            "scope": malicious_scope,
        }
    )

    try:
        result = check_prospective_privacy(
            **{
                **captured,
                "initial_state": malicious_state,
            }
        )
    except PpmcError as error:
        assert "trusted input failed canonical revalidation" in str(error)
        return

    assert result.status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND
    assert result.transition_rejections == len(grammar.actions)
    pytest.fail(
        "PPMC accepted a nested polymorphic DisclosureScope whose runtime scope "
        "differed from the canonically revalidated state"
    )


def test_ppmc_nested_atom_subclass_cannot_split_revalidation_from_transition_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = _capture_hard_gate_inputs(monkeypatch)
    legitimate = captured["initial_state"]
    grammar = captured["grammar"]
    assert type(legitimate) is DisclosureState
    legitimate_atom = legitimate.released_atoms[0]
    assert type(legitimate_atom) is DisclosureAtom

    class MaliciousAtom(DisclosureAtom):
        def model_dump(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
            return legitimate_atom.model_dump(*args, **kwargs)

    runtime_only_atom_sha = canonical_json_sha256(
        {"atom": "phase-12-polymorphic-runtime-only"}
    )
    assert runtime_only_atom_sha not in {
        atom.atom_sha256 for atom in legitimate.released_atoms
    }
    malicious_atom = MaliciousAtom.model_construct(
        **{
            **legitimate_atom.__dict__,
            "atom_sha256": runtime_only_atom_sha,
        }
    )
    malicious_state = DisclosureState.model_construct(
        **{
            **legitimate.__dict__,
            "released_atoms": tuple(
                malicious_atom if atom is legitimate_atom else atom
                for atom in legitimate.released_atoms
            ),
        }
    )

    try:
        result = check_prospective_privacy(
            **{
                **captured,
                "initial_state": malicious_state,
            }
        )
    except PpmcError as error:
        assert "trusted input failed canonical revalidation" in str(error)
        return

    assert result.status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND
    assert result.transition_rejections == len(grammar.actions)
    pytest.fail(
        "PPMC accepted a nested polymorphic DisclosureAtom whose runtime identity "
        "differed from the canonically revalidated state"
    )


def test_ppmc_rejects_polymorphic_governance_binding_before_f6_evaluation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """F6 must evaluate the same governance binding that canonical revalidation validates."""

    captured = _capture_hard_gate_inputs(monkeypatch)
    legitimate_binding = captured["governance_binding"]
    assert type(legitimate_binding) is GovernanceTrustBinding

    untrusted = build_governance_trust_binding(
        governance_commitment_sha256=legitimate_binding.governance_commitment_sha256,
        trusted=False,
        trust_evidence_sha256=legitimate_binding.trust_evidence_sha256,
    )
    bound_zero = build_ppmc_search_config(bound=0, max_states=100)

    untrusted_result = check_prospective_privacy(
        **{
            **captured,
            "governance_binding": untrusted,
            "config": bound_zero,
        }
    )
    assert untrusted_result.status == PpmcStatus.PROSPECTIVE_UNSAFE
    assert untrusted_result.counterexample is not None
    assert untrusted_result.counterexample.steps == ()
    assert (
        ForbiddenPredicateId.F6_UNTRUSTED_GOVERNANCE_AUTHORIZATION
        in untrusted_result.counterexample.terminal_matched_predicates
    )

    class MaliciousGovernanceBinding(GovernanceTrustBinding):
        def model_dump(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
            return untrusted.model_dump(*args, **kwargs)

    malicious = MaliciousGovernanceBinding.model_construct(
        **{
            **untrusted.__dict__,
            "trusted": True,
        }
    )
    assert malicious.binding_sha256 == untrusted.binding_sha256
    assert malicious.trusted is True
    assert malicious.model_dump(mode="json") == untrusted.model_dump(mode="json")

    try:
        result = check_prospective_privacy(
            **{
                **captured,
                "governance_binding": malicious,
                "config": bound_zero,
            }
        )
    except PpmcError as error:
        assert "trusted input failed canonical revalidation" in str(error)
        return

    assert result.status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND
    pytest.fail(
        "PPMC accepted a polymorphic GovernanceTrustBinding and cleared F6 using "
        "runtime trust semantics that differed from canonical revalidation"
    )


def test_ppmc_still_revalidates_exact_governance_binding_constructed_without_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = _capture_hard_gate_inputs(monkeypatch)
    legitimate_binding = captured["governance_binding"]
    assert type(legitimate_binding) is GovernanceTrustBinding
    assert legitimate_binding.trusted is True

    corrupt = GovernanceTrustBinding.model_construct(
        **{
            **legitimate_binding.__dict__,
            "trusted": False,
        }
    )
    assert type(corrupt) is GovernanceTrustBinding
    assert corrupt.binding_sha256 == legitimate_binding.binding_sha256

    with pytest.raises(PpmcError, match="trusted input failed canonical revalidation"):
        check_prospective_privacy(
            **{
                **captured,
                "governance_binding": corrupt,
                "config": build_ppmc_search_config(bound=0, max_states=100),
            }
        )
