from __future__ import annotations

import pytest

import toxicjoin.benchmark.ppmc_hard_gate as hard_gate
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.prospective.ppmc import PpmcError, PpmcStatus, check_prospective_privacy
from toxicjoin.prospective.twin import DisclosureState


def test_ppmc_rejects_polymorphic_initial_state_before_transition_semantics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A virtually serialized state must not differ from the state searched by PPMC."""

    captured: dict[str, object] = {}
    original_check = hard_gate.check_prospective_privacy

    def _capture_check(**kwargs):  # noqa: ANN003, ANN202
        captured.update(kwargs)
        return original_check(**kwargs)

    monkeypatch.setattr(hard_gate, "check_prospective_privacy", _capture_check)
    evidence = hard_gate.build_ppmc_hard_gate_evidence()
    assert evidence.gate_passed is True

    legitimate = captured["initial_state"]
    grammar = captured["grammar"]
    assert type(legitimate) is DisclosureState

    legitimate_result = original_check(**captured)
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
