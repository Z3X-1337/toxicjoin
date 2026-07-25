from __future__ import annotations

from pydantic import ValidationError
import pytest

from toxicjoin.disclosure.composition import is_protected_release
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
from toxicjoin.prospective.grammar import (
    DeclaredSnapshotTransition,
    FutureAction,
    FutureActionGrammar,
    FutureActionGrammarError,
    FutureActionKind,
    FutureActionTransitionError,
    apply_future_action,
    build_future_action_grammar_context,
    compute_future_action_grammar_sha256,
    compute_future_action_sha256,
    instantiate_future_action_grammar,
)
from toxicjoin.prospective.twin import DisclosureAtomKind, build_disclosure_state

DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.grammar,PROD)"
PURPOSE = "1" * 64
GOVERNANCE = "2" * 64
EVIDENCE = "3" * 64
SNAPSHOT = "4" * 64


def _column(field: str, category: SensitivityCategory) -> GovernedColumn:
    return GovernedColumn(dataset_urn=DATASET_URN, field_path=field, category=category)


def _output(
    column: GovernedColumn,
    kind: ProjectionExposureKind = ProjectionExposureKind.RAW_VALUE,
) -> SemanticOutput:
    return SemanticOutput(kind=kind, sources=(column,))


def _semantic(
    *,
    outputs: tuple[SemanticOutput, ...],
    referenced: tuple[GovernedColumn, ...],
    groups: tuple[GovernedColumn, ...] = (),
    aggregates: tuple[str, ...] = (),
) -> DisclosureSemanticRelease:
    canonical_outputs = tuple(
        sorted(
            outputs,
            key=lambda output: (
                output.kind.value,
                tuple(source.key for source in output.sources),
            ),
        )
    )
    kwargs = {
        "source_dataset_urns": (DATASET_URN,),
        "outputs": canonical_outputs,
        "referenced_columns": tuple(sorted(referenced, key=lambda column: column.key)),
        "join_columns": (),
        "group_keys": tuple(sorted(groups, key=lambda column: column.key)),
        "aggregate_functions": tuple(sorted(set(aggregates))),
        "minimum_group_size_present": None,
    }
    provisional = DisclosureSemanticRelease.model_construct(
        **kwargs,
        semantic_sha256="0" * 64,
    )
    return DisclosureSemanticRelease(
        **kwargs,
        semantic_sha256=compute_semantic_sha256(provisional),
    )


def _composition(
    semantic: DisclosureSemanticRelease,
    *,
    cohort: str = "a" * 64,
) -> DisclosureComposition:
    return DisclosureComposition(
        protected_release=is_protected_release(semantic),
        release_family_sha256=semantic.semantic_sha256,
        cohort_hmac_sha256=cohort,
    )


def _state(
    semantic: DisclosureSemanticRelease,
    composition: DisclosureComposition,
    *,
    principal: str = "principal-grammar",
    purpose: str = PURPOSE,
    governance: str = GOVERNANCE,
    evidence: str = EVIDENCE,
    snapshot: str | None = SNAPSHOT,
):
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
        principal_id=principal,
        agent_id="agent-grammar",
        subject=subject,
        scope_sha256=compute_scope_sha256(
            principal_id=principal,
            agent_id="agent-grammar",
            subject_namespace_sha256=namespace,
        ),
    )
    return build_disclosure_state(
        scope=scope,
        audit_history=(),
        candidate_semantic=semantic,
        candidate_composition=composition,
        purpose_commitment_sha256=purpose,
        governance_commitment_sha256=governance,
        evidence_root_sha256=evidence,
        warehouse_snapshot_sha256=snapshot,
    )


def _context(
    base: DisclosureSemanticRelease,
    composition: DisclosureComposition,
    **kwargs,
):
    state = kwargs.pop("base_state", None) or _state(base, composition)
    return build_future_action_grammar_context(
        base_state=state,
        base_semantic=base,
        base_composition=composition,
        **kwargs,
    )


def _action(grammar: FutureActionGrammar, kind: FutureActionKind) -> FutureAction:
    matches = [action for action in grammar.actions if action.kind == kind]
    assert len(matches) == 1
    return matches[0]


def _snapshot_action(grammar: FutureActionGrammar, target: str) -> FutureAction:
    matches = [
        action
        for action in grammar.actions
        if action.kind == FutureActionKind.SNAPSHOT_ADVANCE
        and action.snapshot_sha256 == target
    ]
    assert len(matches) == 1
    return matches[0]


def test_context_and_grammar_are_deterministic_across_input_order() -> None:
    public = _column("country", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    q1 = _column("region", SensitivityCategory.QUASI_IDENTIFIER)
    q2 = _column("age_band", SensitivityCategory.QUASI_IDENTIFIER)
    sensitive = _column("medical_flag", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    base = _semantic(outputs=(_output(public),), referenced=(public,))
    composition = _composition(base)
    state = _state(base, composition)
    edge_a = DeclaredSnapshotTransition(
        from_snapshot_sha256=SNAPSHOT,
        to_snapshot_sha256="8" * 64,
    )
    edge_b = DeclaredSnapshotTransition(
        from_snapshot_sha256="8" * 64,
        to_snapshot_sha256="9" * 64,
    )

    first = _context(
        base,
        composition,
        base_state=state,
        relevant_projection_fields=(sensitive, q2, q1),
        group_key_fields=(q2, q1),
        aggregate_allowlist=("sum", "COUNT"),
        cohort_variant_hmacs=("c" * 64, "b" * 64),
        snapshot_transitions=(edge_b, edge_a),
    )
    second = _context(
        base,
        composition,
        base_state=state,
        relevant_projection_fields=(q1, sensitive, q2),
        group_key_fields=(q1, q2),
        aggregate_allowlist=("COUNT", "SUM"),
        cohort_variant_hmacs=("b" * 64, "c" * 64),
        snapshot_transitions=(edge_a, edge_b),
    )

    assert first == second
    assert instantiate_future_action_grammar(first) == instantiate_future_action_grammar(second)


def test_context_rejects_unclassified_base_or_invalid_group_and_aggregate_inputs() -> None:
    unknown = _column("mystery", SensitivityCategory.UNCLASSIFIED)
    unknown_base = _semantic(outputs=(_output(unknown),), referenced=(unknown,))
    unknown_composition = _composition(unknown_base)
    with pytest.raises(ValidationError, match="unclassified"):
        _context(unknown_base, unknown_composition)

    public = _column("country", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    base = _semantic(outputs=(_output(public),), referenced=(public,))
    composition = _composition(base)
    with pytest.raises(ValidationError, match="quasi-identifiers"):
        _context(
            base,
            composition,
            relevant_projection_fields=(public,),
            group_key_fields=(public,),
        )
    with pytest.raises(ValidationError, match="unsupported future aggregate"):
        _context(base, composition, aggregate_allowlist=("MEDIAN",))


def test_snapshot_transition_graph_rejects_unreachable_sources() -> None:
    public = _column("country", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    base = _semantic(outputs=(_output(public),), referenced=(public,))
    composition = _composition(base)
    disconnected = DeclaredSnapshotTransition(
        from_snapshot_sha256="8" * 64,
        to_snapshot_sha256="9" * 64,
    )

    with pytest.raises(ValidationError, match="unreachable source"):
        _context(base, composition, snapshot_transitions=(disconnected,))


def test_grammar_regenerates_expected_action_set_and_rejects_tampering() -> None:
    public = _column("country", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    sensitive = _column("medical_flag", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    base = _semantic(outputs=(_output(public),), referenced=(public,))
    composition = _composition(base)
    context = _context(
        base,
        composition,
        relevant_projection_fields=(sensitive,),
        snapshot_transitions=(
            DeclaredSnapshotTransition(
                from_snapshot_sha256=SNAPSHOT,
                to_snapshot_sha256="9" * 64,
            ),
        ),
    )
    grammar = instantiate_future_action_grammar(context)
    assert len(grammar.actions) >= 3

    shortened = tuple(grammar.actions[:-1])
    unchecked = FutureActionGrammar.model_construct(
        context=grammar.context,
        actions=shortened,
        grammar_sha256="0" * 64,
    )
    payload = grammar.model_dump(mode="json")
    payload["actions"] = [action.model_dump(mode="json") for action in shortened]
    payload["grammar_sha256"] = compute_future_action_grammar_sha256(unchecked)

    with pytest.raises(ValidationError, match="action set does not match"):
        FutureActionGrammar.model_validate(payload)


def test_action_budget_exhaustion_fails_closed() -> None:
    public = _column("country", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    base = _semantic(outputs=(_output(public),), referenced=(public,))
    composition = _composition(base)
    q_fields = tuple(
        _column(f"q{i:02d}", SensitivityCategory.QUASI_IDENTIFIER)
        for i in range(12)
    )
    extra_fields = tuple(
        _column(f"p{i:02d}", SensitivityCategory.PUBLIC_OR_LOW_RISK)
        for i in range(4)
    )
    transitions: list[DeclaredSnapshotTransition] = []
    source = SNAPSHOT
    for index in range(8):
        target = f"{index + 20:064x}"
        transitions.append(
            DeclaredSnapshotTransition(
                from_snapshot_sha256=source,
                to_snapshot_sha256=target,
            )
        )
        source = target
    context = _context(
        base,
        composition,
        relevant_projection_fields=(*q_fields, *extra_fields),
        group_key_fields=q_fields,
        cohort_variant_hmacs=tuple(f"{i + 1:064x}" for i in range(8)),
        snapshot_transitions=tuple(transitions),
    )

    with pytest.raises(FutureActionGrammarError, match="budget exceeded"):
        instantiate_future_action_grammar(context)


def test_add_projection_transition_can_create_linkable_sensitive_coexposure() -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    sensitive = _column("medical_flag", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    base = _semantic(outputs=(_output(stable),), referenced=(stable,))
    composition = _composition(base)
    state = _state(base, composition)
    grammar = instantiate_future_action_grammar(
        _context(
            base,
            composition,
            base_state=state,
            relevant_projection_fields=(sensitive,),
        )
    )

    next_state = apply_future_action(
        state,
        _action(grammar, FutureActionKind.ADD_PROJECTION),
        grammar,
    )

    assert next_state.scope == state.scope
    assert next_state.purpose_commitment_sha256 == PURPOSE
    assert next_state.governance_commitment_sha256 == GOVERNANCE
    assert next_state.evidence_root_sha256 == EVIDENCE
    assert any(
        atom.kind == DisclosureAtomKind.IDENTIFIER_SENSITIVE_COEXPOSURE
        for atom in next_state.derived_atoms
    )


def test_cohort_variant_transition_derives_protected_cohort_variation() -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    base = _semantic(outputs=(_output(stable),), referenced=(stable,))
    composition = _composition(base, cohort="a" * 64)
    state = _state(base, composition)
    grammar = instantiate_future_action_grammar(
        _context(
            base,
            composition,
            base_state=state,
            cohort_variant_hmacs=("b" * 64,),
        )
    )

    next_state = apply_future_action(
        state,
        _action(grammar, FutureActionKind.COHORT_VARIANT),
        grammar,
    )

    assert any(
        atom.kind == DisclosureAtomKind.PROTECTED_COHORT_VARIATION
        for atom in next_state.derived_atoms
    )


def test_snapshot_advance_is_directed_and_changes_only_snapshot_commitment() -> None:
    public = _column("country", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    base = _semantic(outputs=(_output(public),), referenced=(public,))
    composition = _composition(base)
    state = _state(base, composition)
    first_target = "8" * 64
    second_target = "9" * 64
    grammar = instantiate_future_action_grammar(
        _context(
            base,
            composition,
            base_state=state,
            snapshot_transitions=(
                DeclaredSnapshotTransition(
                    from_snapshot_sha256=SNAPSHOT,
                    to_snapshot_sha256=first_target,
                ),
                DeclaredSnapshotTransition(
                    from_snapshot_sha256=first_target,
                    to_snapshot_sha256=second_target,
                ),
            ),
        )
    )

    advanced = apply_future_action(
        state,
        _snapshot_action(grammar, first_target),
        grammar,
    )
    assert advanced.warehouse_snapshot_sha256 == first_target
    assert advanced.released_atoms == state.released_atoms
    assert advanced.derived_atoms == state.derived_atoms
    assert advanced.state_sha256 != state.state_sha256

    twice = apply_future_action(
        advanced,
        _snapshot_action(grammar, second_target),
        grammar,
    )
    assert twice.warehouse_snapshot_sha256 == second_target

    with pytest.raises(FutureActionTransitionError, match="source does not match"):
        apply_future_action(state, _snapshot_action(grammar, second_target), grammar)


def test_replay_is_semantically_idempotent() -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    base = _semantic(outputs=(_output(stable),), referenced=(stable,))
    composition = _composition(base)
    state = _state(base, composition)
    grammar = instantiate_future_action_grammar(
        _context(base, composition, base_state=state)
    )

    replayed = apply_future_action(state, _action(grammar, FutureActionKind.REPLAY), grammar)

    assert replayed == state


def test_state_outside_committed_model_universe_is_rejected() -> None:
    public = _column("country", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    base = _semantic(outputs=(_output(public),), referenced=(public,))
    composition = _composition(base)
    state = _state(base, composition)
    grammar = instantiate_future_action_grammar(
        _context(base, composition, base_state=state)
    )
    foreign = _state(base, composition, purpose="f" * 64)

    with pytest.raises(FutureActionTransitionError, match="purpose"):
        apply_future_action(foreign, _action(grammar, FutureActionKind.REPLAY), grammar)


def test_self_valid_action_outside_grammar_is_rejected() -> None:
    public = _column("country", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    base = _semantic(outputs=(_output(public),), referenced=(public,))
    composition = _composition(base)
    state = _state(base, composition)
    grammar = instantiate_future_action_grammar(
        _context(base, composition, base_state=state)
    )
    provisional = FutureAction.model_construct(
        kind=FutureActionKind.SNAPSHOT_ADVANCE,
        snapshot_from_sha256=SNAPSHOT,
        snapshot_sha256="9" * 64,
        semantic=None,
        composition=None,
        action_sha256="0" * 64,
    )
    outsider = FutureAction(
        kind=FutureActionKind.SNAPSHOT_ADVANCE,
        snapshot_from_sha256=SNAPSHOT,
        snapshot_sha256="9" * 64,
        action_sha256=compute_future_action_sha256(provisional),
    )

    with pytest.raises(FutureActionTransitionError, match="not authorized"):
        apply_future_action(state, outsider, grammar)


def test_add_group_key_preserves_aggregate_output_and_adds_group_output() -> None:
    public = _column("country", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    qid = _column("region", SensitivityCategory.QUASI_IDENTIFIER)
    base = _semantic(
        outputs=(
            _output(public),
            _output(qid, ProjectionExposureKind.AGGREGATE_VALUE),
        ),
        referenced=(public, qid),
        aggregates=("COUNT",),
    )
    composition = _composition(base)
    grammar = instantiate_future_action_grammar(
        _context(
            base,
            composition,
            relevant_projection_fields=(qid,),
            group_key_fields=(qid,),
        )
    )
    add_group = _action(grammar, FutureActionKind.ADD_GROUP_KEY)
    assert add_group.semantic is not None

    kinds = {
        output.kind
        for output in add_group.semantic.outputs
        if len(output.sources) == 1 and output.sources[0].key == qid.key
    }
    assert ProjectionExposureKind.AGGREGATE_VALUE in kinds
    assert ProjectionExposureKind.GROUP_KEY in kinds


def test_drop_group_key_that_would_remove_all_outputs_is_unavailable() -> None:
    qid = _column("region", SensitivityCategory.QUASI_IDENTIFIER)
    base = _semantic(
        outputs=(_output(qid, ProjectionExposureKind.GROUP_KEY),),
        referenced=(qid,),
        groups=(qid,),
    )
    composition = _composition(base)
    grammar = instantiate_future_action_grammar(_context(base, composition))

    assert all(action.kind != FutureActionKind.DROP_GROUP_KEY for action in grammar.actions)
    assert all(action.kind != FutureActionKind.REMOVE_PROJECTION for action in grammar.actions)


def test_filter_only_does_not_suppress_add_raw_projection() -> None:
    public = _column("country", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    sensitive = _column("medical_flag", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    base = _semantic(
        outputs=(
            _output(public),
            _output(sensitive, ProjectionExposureKind.FILTER_ONLY),
        ),
        referenced=(public, sensitive),
    )
    composition = _composition(base)
    grammar = instantiate_future_action_grammar(
        _context(
            base,
            composition,
            relevant_projection_fields=(sensitive,),
        )
    )
    add_projection = _action(grammar, FutureActionKind.ADD_PROJECTION)
    assert add_projection.semantic is not None
    kinds = {
        output.kind
        for output in add_projection.semantic.outputs
        if len(output.sources) == 1 and output.sources[0].key == sensitive.key
    }
    assert ProjectionExposureKind.FILTER_ONLY in kinds
    assert ProjectionExposureKind.RAW_VALUE in kinds


def test_action_hash_tampering_is_rejected() -> None:
    public = _column("country", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    base = _semantic(outputs=(_output(public),), referenced=(public,))
    composition = _composition(base)
    grammar = instantiate_future_action_grammar(_context(base, composition))
    payload = grammar.actions[0].model_dump(mode="json")
    payload["action_sha256"] = "0" * 64

    with pytest.raises(ValidationError, match="action hash mismatch"):
        FutureAction.model_validate(payload)
