from toxicjoin.benchmark.ppmc_hard_gate import build_ppmc_hard_gate_evidence
from toxicjoin.models import ReasonCode
from toxicjoin.prospective.forbidden import ForbiddenPredicateId
from toxicjoin.prospective.grammar import FutureActionKind


def test_real_policy_engine_allow_ppmc_counterexample_hard_gate() -> None:
    evidence = build_ppmc_hard_gate_evidence()

    assert evidence.gate_passed is True
    assert evidence.initial_policy_decision == "ALLOW"
    assert evidence.initial_policy_reason_codes == (ReasonCode.NO_COMPOSITIONAL_RISK.value,)
    assert evidence.adapter_initial_reason_codes == evidence.initial_policy_reason_codes
    assert evidence.future_replay_reason_codes == evidence.initial_policy_reason_codes
    assert evidence.counterexample_depth == 2
    assert evidence.counterexample_action_kinds == (
        FutureActionKind.SNAPSHOT_ADVANCE,
        FutureActionKind.REPLAY,
    )
    assert ForbiddenPredicateId.F5_TEMPORAL_DIFFERENCING in evidence.matched_predicates
