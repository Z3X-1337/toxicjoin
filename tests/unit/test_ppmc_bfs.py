from __future__ import annotations

import pytest
from pydantic import ValidationError

import toxicjoin.prospective.ppmc_search as ppmc_search_module
from toxicjoin.disclosure.models import (
    DisclosureComposition,
    DisclosureScope,
    DisclosureSemanticRelease,
    GovernedColumn,
    GovernedSubjectDomain,
    SemanticOutput,
    compute_scope_sha256,
    compute_semantic_sha256,
    compute_subject_namespace_sha256,
)
from toxicjoin.models import ProjectionExposureKind, SensitivityCategory
from toxicjoin.prospective.forbidden import (
    ForbiddenPredicateId,
    build_forbidden_predicate_policy,
    build_governance_trust_binding,
)
from toxicjoin.prospective.grammar import (
    DeclaredSnapshotTransition,
    FutureActionKind,
    apply_future_action,
    build_future_action_grammar_context,
    instantiate_future_action_grammar,
)
from toxicjoin.prospective.ppmc import (
    LocalOracleDecision,
    PpmcFailureReason,
    PpmcSearchResult,
    PpmcStatus,
    build_local_oracle_decision,
    build_ppmc_search_config,
    check_prospective_privacy,
)
from toxicjoin.prospective.twin import (
    DisclosureState,
    build_disclosure_state,
    compute_disclosure_state_sha256,
    compute_inference_rules_sha256,
    direct_atoms_for_release,
    instantiate_disclosure_inference_rules,
    least_fixed_point,
)

DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.ppmc,PROD)"
PURPOSE = "1" * 64
GOVERNANCE = "2" * 64
EVIDENCE = "3" * 64
SNAPSHOT_A = "4" * 64
SNAPSHOT_B = "5" * 64
TRUST_EVIDENCE = "6" * 64
COHORT = "a" * 64


def _column(field: str, category: SensitivityCategory) -> GovernedColumn:
    return GovernedColumn(dataset_urn=DATASET_URN, field_path=field, category=category)


def _output(column: GovernedColumn) -> SemanticOutput:
    return SemanticOutput(kind=ProjectionExposureKind.RAW_VALUE, sources=(column,))


def _semantic(*columns: GovernedColumn) -> DisclosureSemanticRelease:
    outputs = tuple(
        sorted((_output(column) for column in columns), key=lambda item: item.sources[0].key)
    )
    referenced = tuple(sorted(columns, key=lambda column: column.key))
    provisional = DisclosureSemanticRelease.model_construct(
        source_dataset_urns=(DATASET_URN,),
        outputs=outputs,
        referenced_columns=referenced,
        join_columns=(),
        group_keys=(),
        aggregate_functions=(),
        minimum_group_size_present=None,
        semantic_sha256="0" * 64,
    )
    return DisclosureSemanticRelease(
        source_dataset_urns=(DATASET_URN,),
        outputs=outputs,
        referenced_columns=referenced,
        join_columns=(),
        group_keys=(),
        aggregate_functions=(),
        minimum_group_size_present=None,
        semantic_sha256=compute_semantic_sha256(provisional),
    )


def _aggregate_sensitive_semantic(column: GovernedColumn) -> DisclosureSemanticRelease:
    output = SemanticOutput(
        kind=ProjectionExposureKind.AGGREGATE_VALUE,
        sources=(column,),
    )
    provisional = DisclosureSemanticRelease.model_construct(
        source_dataset_urns=(DATASET_URN,),
        outputs=(output,),
        referenced_columns=(column,),
        join_columns=(),
        group_keys=(),
        aggregate_functions=("COUNT",),
        minimum_group_size_present=None,
        semantic_sha256="0" * 64,
    )
    return DisclosureSemanticRelease(
        source_dataset_urns=(DATASET_URN,),
        outputs=(output,),
        referenced_columns=(column,),
        join_columns=(),
        group_keys=(),
        aggregate_functions=("COUNT",),
        minimum_group_size_present=None,
        semantic_sha256=compute_semantic_sha256(provisional),
    )


def _composition(semantic: DisclosureSemanticRelease) -> DisclosureComposition:
    return DisclosureComposition(
        protected_release=True,
        release_family_sha256=semantic.semantic_sha256,
        cohort_hmac_sha256=COHORT,
    )


def _state(semantic: DisclosureSemanticRelease, *, snapshot: str | None = SNAPSHOT_A):
    namespace = compute_subject_namespace_sha256(
        "customer_id",
        SensitivityCategory.STABLE_PSEUDONYM,
    )
    subject = GovernedSubjectDomain(
        field_path="customer_id",
        category=SensitivityCategory.STABLE_PSEUDONYM,
        dataset_urns=(DATASET_URN,),
        governance_domains=("urn:li:domain:privacy",),
        namespace_sha256=namespace,
    )
    scope = DisclosureScope(
        principal_id="principal-ppmc",
        agent_id="agent-ppmc",
        subject=subject,
        scope_sha256=compute_scope_sha256(
            principal_id="principal-ppmc",
            agent_id="agent-ppmc",
            subject_namespace_sha256=namespace,
        ),
    )
    return build_disclosure_state(
        scope=scope,
        audit_history=(),
        candidate_semantic=semantic,
        candidate_composition=_composition(semantic),
        purpose_commitment_sha256=PURPOSE,
        governance_commitment_sha256=GOVERNANCE,
        evidence_root_sha256=EVIDENCE,
        warehouse_snapshot_sha256=snapshot,
    )


def _state_with_extra_release(
    state: DisclosureState,
    semantic: DisclosureSemanticRelease,
) -> DisclosureState:
    extras = direct_atoms_for_release(semantic, _composition(semantic))
    merged = {atom.atom_sha256: atom for atom in state.released_atoms}
    for atom in extras:
        merged[atom.atom_sha256] = atom
    released = tuple(merged[key] for key in sorted(merged))
    rules = instantiate_disclosure_inference_rules(released)
    derived = least_fixed_point(released, rules)
    rules_sha = compute_inference_rules_sha256(rules)
    provisional = DisclosureState.model_construct(
        scope=state.scope,
        purpose_commitment_sha256=state.purpose_commitment_sha256,
        governance_commitment_sha256=state.governance_commitment_sha256,
        evidence_root_sha256=state.evidence_root_sha256,
        warehouse_snapshot_sha256=state.warehouse_snapshot_sha256,
        released_atoms=released,
        derived_atoms=derived,
        inference_rules_sha256=rules_sha,
        state_sha256="0" * 64,
    )
    return DisclosureState(
        scope=state.scope,
        purpose_commitment_sha256=state.purpose_commitment_sha256,
        governance_commitment_sha256=state.governance_commitment_sha256,
        evidence_root_sha256=state.evidence_root_sha256,
        warehouse_snapshot_sha256=state.warehouse_snapshot_sha256,
        released_atoms=released,
        derived_atoms=derived,
        inference_rules_sha256=rules_sha,
        state_sha256=compute_disclosure_state_sha256(provisional),
    )


def _grammar(
    state,
    semantic,
    *,
    relevant: tuple[GovernedColumn, ...] = (),
    transitions: tuple[DeclaredSnapshotTransition, ...] = (),
):
    return instantiate_future_action_grammar(
        build_future_action_grammar_context(
            base_state=state,
            base_semantic=semantic,
            base_composition=_composition(semantic),
            relevant_projection_fields=relevant,
            snapshot_transitions=transitions,
        )
    )


def _policy():
    return build_forbidden_predicate_policy(minimum_group_size=10)


def _binding():
    return build_governance_trust_binding(
        governance_commitment_sha256=GOVERNANCE,
        trusted=True,
        trust_evidence_sha256=TRUST_EVIDENCE,
    )


def _allow_all(state, action):
    return build_local_oracle_decision(
        oracle_version="test-local-policy-1",
        state_sha256=state.state_sha256,
        action_sha256=action.action_sha256,
        admissible=True,
        reason_codes=("ALLOW",),
    )


def test_zero_step_forbidden_state_returns_counterexample_without_oracle() -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    sensitive = _column("diagnosis", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    semantic = _semantic(stable, sensitive)
    state = _state(semantic)
    grammar = _grammar(state, semantic)
    calls = 0

    def oracle(current, action):
        nonlocal calls
        calls += 1
        return _allow_all(current, action)

    result = check_prospective_privacy(
        initial_state=state,
        grammar=grammar,
        forbidden_policy=_policy(),
        governance_binding=_binding(),
        local_oracle=oracle,
    )

    assert result.status == PpmcStatus.PROSPECTIVE_UNSAFE
    assert result.counterexample is not None
    assert result.counterexample.steps == ()
    assert (
        ForbiddenPredicateId.F2_STABLE_LINKABLE_SENSITIVE
        in result.counterexample.terminal_matched_predicates
    )
    assert calls == 0


def test_bfs_returns_minimum_depth_one_step_counterexample() -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    sensitive = _column("diagnosis", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    base = _semantic(stable)
    state = _state(base)
    grammar = _grammar(state, base, relevant=(sensitive,))

    result = check_prospective_privacy(
        initial_state=state,
        grammar=grammar,
        forbidden_policy=_policy(),
        governance_binding=_binding(),
        local_oracle=_allow_all,
        config=build_ppmc_search_config(bound=3, max_states=100),
    )

    assert result.status == PpmcStatus.PROSPECTIVE_UNSAFE
    assert result.counterexample is not None
    assert len(result.counterexample.steps) == 1
    step = result.counterexample.steps[0]
    action = next(item for item in grammar.actions if item.action_sha256 == step.action_sha256)
    assert action.kind == FutureActionKind.ADD_PROJECTION


def test_local_oracle_rejection_removes_action_from_reachable_search() -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    sensitive = _column("diagnosis", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    base = _semantic(stable)
    state = _state(base)
    grammar = _grammar(state, base, relevant=(sensitive,))

    def oracle(current, action):
        allowed = action.kind != FutureActionKind.ADD_PROJECTION
        return build_local_oracle_decision(
            oracle_version="test-local-policy-1",
            state_sha256=current.state_sha256,
            action_sha256=action.action_sha256,
            admissible=allowed,
            reason_codes=("ALLOW",) if allowed else ("BLOCK",),
        )

    result = check_prospective_privacy(
        initial_state=state,
        grammar=grammar,
        forbidden_policy=_policy(),
        governance_binding=_binding(),
        local_oracle=oracle,
        config=build_ppmc_search_config(bound=3, max_states=100),
    )

    assert result.status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND
    assert result.oracle_rejections >= 1


def test_sensitive_release_without_snapshot_fails_closed_as_indeterminate() -> None:
    sensitive = _column("diagnosis", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    base = _semantic(sensitive)
    state = _state(base, snapshot=None)
    grammar = _grammar(state, base)

    result = check_prospective_privacy(
        initial_state=state,
        grammar=grammar,
        forbidden_policy=_policy(),
        governance_binding=_binding(),
        local_oracle=_allow_all,
    )

    assert result.status == PpmcStatus.FAIL_CLOSED
    assert result.failure_reason == PpmcFailureReason.INDETERMINATE_SECURITY_PREDICATE
    assert result.indeterminate_predicates == (ForbiddenPredicateId.F5_TEMPORAL_DIFFERENCING,)


def test_historical_sensitive_release_without_snapshot_provenance_fails_closed() -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    sensitive = _column("diagnosis", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    base = _semantic(stable)
    base_state = _state(base, snapshot=SNAPSHOT_A)
    state = _state_with_extra_release(base_state, _aggregate_sensitive_semantic(sensitive))
    grammar = _grammar(state, base)

    result = check_prospective_privacy(
        initial_state=state,
        grammar=grammar,
        forbidden_policy=_policy(),
        governance_binding=_binding(),
        local_oracle=_allow_all,
    )

    assert result.status == PpmcStatus.FAIL_CLOSED
    assert result.failure_reason == PpmcFailureReason.INDETERMINATE_SECURITY_PREDICATE
    assert result.indeterminate_predicates == (ForbiddenPredicateId.F5_TEMPORAL_DIFFERENCING,)


def test_f5_sensitive_replay_after_snapshot_advance_is_depth_two_counterexample() -> None:
    sensitive = _column("diagnosis", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    base = _semantic(sensitive)
    state = _state(base, snapshot=SNAPSHOT_A)
    grammar = _grammar(
        state,
        base,
        transitions=(
            DeclaredSnapshotTransition(
                from_snapshot_sha256=SNAPSHOT_A,
                to_snapshot_sha256=SNAPSHOT_B,
            ),
        ),
    )

    result = check_prospective_privacy(
        initial_state=state,
        grammar=grammar,
        forbidden_policy=_policy(),
        governance_binding=_binding(),
        local_oracle=_allow_all,
        config=build_ppmc_search_config(bound=3, max_states=100),
    )

    assert result.status == PpmcStatus.PROSPECTIVE_UNSAFE
    assert result.counterexample is not None
    assert len(result.counterexample.steps) == 2
    kinds = [
        next(item.kind for item in grammar.actions if item.action_sha256 == step.action_sha256)
        for step in result.counterexample.steps
    ]
    assert kinds == [FutureActionKind.SNAPSHOT_ADVANCE, FutureActionKind.REPLAY]
    assert (
        ForbiddenPredicateId.F5_TEMPORAL_DIFFERENCING
        in result.counterexample.terminal_matched_predicates
    )
    assert result.transition_rejections >= 1


def test_f5_depth_two_counterexample_is_not_claimed_with_bound_one() -> None:
    sensitive = _column("diagnosis", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    base = _semantic(sensitive)
    state = _state(base, snapshot=SNAPSHOT_A)
    grammar = _grammar(
        state,
        base,
        transitions=(
            DeclaredSnapshotTransition(
                from_snapshot_sha256=SNAPSHOT_A,
                to_snapshot_sha256=SNAPSHOT_B,
            ),
        ),
    )

    result = check_prospective_privacy(
        initial_state=state,
        grammar=grammar,
        forbidden_policy=_policy(),
        governance_binding=_binding(),
        local_oracle=_allow_all,
        config=build_ppmc_search_config(bound=1, max_states=100),
    )

    assert result.status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND
    assert result.counterexample is None


def test_state_budget_exhaustion_fails_closed() -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    public = _column("country", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    base = _semantic(stable)
    state = _state(base)
    grammar = _grammar(state, base, relevant=(public,))

    result = check_prospective_privacy(
        initial_state=state,
        grammar=grammar,
        forbidden_policy=_policy(),
        governance_binding=_binding(),
        local_oracle=_allow_all,
        config=build_ppmc_search_config(bound=3, max_states=1),
    )

    assert result.status == PpmcStatus.FAIL_CLOSED
    assert result.failure_reason == PpmcFailureReason.STATE_BUDGET_EXHAUSTED


def test_replay_same_snapshot_is_temporally_deduplicated() -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    base = _semantic(stable)
    state = _state(base)
    grammar = _grammar(state, base)
    assert tuple(action.kind for action in grammar.actions) == (FutureActionKind.REPLAY,)

    result = check_prospective_privacy(
        initial_state=state,
        grammar=grammar,
        forbidden_policy=_policy(),
        governance_binding=_binding(),
        local_oracle=_allow_all,
        config=build_ppmc_search_config(bound=5, max_states=100),
    )

    assert result.status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND
    assert result.search_nodes_discovered == 1
    assert result.nodes_expanded == 1


def test_oracle_binding_mismatch_fails_closed() -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    base = _semantic(stable)
    state = _state(base)
    grammar = _grammar(state, base)

    def bad_oracle(current, action):
        return build_local_oracle_decision(
            oracle_version="test-local-policy-1",
            state_sha256="f" * 64,
            action_sha256=action.action_sha256,
            admissible=True,
            reason_codes=("ALLOW",),
        )

    result = check_prospective_privacy(
        initial_state=state,
        grammar=grammar,
        forbidden_policy=_policy(),
        governance_binding=_binding(),
        local_oracle=bad_oracle,
    )

    assert result.status == PpmcStatus.FAIL_CLOSED
    assert result.failure_reason == PpmcFailureReason.LOCAL_ORACLE_FAILURE


def test_oracle_exception_fails_closed() -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    base = _semantic(stable)
    state = _state(base)
    grammar = _grammar(state, base)

    def exploding_oracle(current, action):
        raise RuntimeError("simulated local oracle outage")

    result = check_prospective_privacy(
        initial_state=state,
        grammar=grammar,
        forbidden_policy=_policy(),
        governance_binding=_binding(),
        local_oracle=exploding_oracle,
    )

    assert result.status == PpmcStatus.FAIL_CLOSED
    assert result.failure_reason == PpmcFailureReason.LOCAL_ORACLE_FAILURE


def test_predicate_evaluator_failure_is_explicit_fail_closed(monkeypatch) -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    base = _semantic(stable)
    state = _state(base)
    grammar = _grammar(state, base)

    def explode(*args, **kwargs):
        raise RuntimeError("simulated predicate failure")

    monkeypatch.setattr(ppmc_search_module, "evaluate_forbidden_state", explode)
    result = check_prospective_privacy(
        initial_state=state,
        grammar=grammar,
        forbidden_policy=_policy(),
        governance_binding=_binding(),
        local_oracle=_allow_all,
    )

    assert result.status == PpmcStatus.FAIL_CLOSED
    assert result.failure_reason == PpmcFailureReason.PREDICATE_EVALUATION_FAILURE


def test_unexpected_transition_failure_is_explicit_fail_closed(monkeypatch) -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    base = _semantic(stable)
    state = _state(base)
    grammar = _grammar(state, base)

    def explode(*args, **kwargs):
        raise RuntimeError("simulated transition defect")

    monkeypatch.setattr(ppmc_search_module, "apply_future_action", explode)
    result = check_prospective_privacy(
        initial_state=state,
        grammar=grammar,
        forbidden_policy=_policy(),
        governance_binding=_binding(),
        local_oracle=_allow_all,
    )

    assert result.status == PpmcStatus.FAIL_CLOSED
    assert result.failure_reason == PpmcFailureReason.TRANSITION_FAILURE


def test_ppmc_is_deterministic_for_same_model_and_oracle() -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    public = _column("country", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    base = _semantic(stable)
    state = _state(base)
    grammar = _grammar(state, base, relevant=(public,))
    config = build_ppmc_search_config(bound=2, max_states=100)

    first = check_prospective_privacy(
        initial_state=state,
        grammar=grammar,
        forbidden_policy=_policy(),
        governance_binding=_binding(),
        local_oracle=_allow_all,
        config=config,
    )
    second = check_prospective_privacy(
        initial_state=state,
        grammar=grammar,
        forbidden_policy=_policy(),
        governance_binding=_binding(),
        local_oracle=_allow_all,
        config=config,
    )

    assert first == second
    assert first.result_sha256 == second.result_sha256
    assert first.search_transcript_sha256 == second.search_transcript_sha256


def test_ppmc_result_and_oracle_commitment_tampering_are_rejected() -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    base = _semantic(stable)
    state = _state(base)
    grammar = _grammar(state, base)
    result = check_prospective_privacy(
        initial_state=state,
        grammar=grammar,
        forbidden_policy=_policy(),
        governance_binding=_binding(),
        local_oracle=_allow_all,
    )

    payload = result.model_dump(mode="json")
    payload["result_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="PPMC result hash mismatch"):
        PpmcSearchResult.model_validate(payload)

    action = grammar.actions[0]
    decision = _allow_all(state, action)
    bad = decision.model_dump(mode="json")
    bad["decision_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="local oracle decision hash mismatch"):
        LocalOracleDecision.model_validate(bad)


def test_search_config_enforces_frozen_hard_limits() -> None:
    with pytest.raises(ValidationError):
        build_ppmc_search_config(bound=6)
    with pytest.raises(ValidationError):
        build_ppmc_search_config(max_states=50_001)


def test_test_fixture_transition_matches_real_grammar_contract() -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    public = _column("country", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    base = _semantic(stable)
    state = _state(base)
    grammar = _grammar(state, base, relevant=(public,))
    action = next(item for item in grammar.actions if item.kind == FutureActionKind.ADD_PROJECTION)
    next_state = apply_future_action(state, action, grammar)
    assert next_state.state_sha256 != state.state_sha256
