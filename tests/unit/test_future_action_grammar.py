from __future__ import annotations

from pydantic import ValidationError
import pytest

from toxicjoin.disclosure.composition import is_protected_release
from toxicjoin.disclosure.models import (
    DisclosureComposition,
    DisclosureSemanticRelease,
    GovernedColumn,
    SemanticOutput,
    compute_semantic_sha256,
)
from toxicjoin.models import ProjectionExposureKind, SensitivityCategory
from toxicjoin.prospective.grammar import (
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
from toxicjoin.prospective.twin import (
    DisclosureAtomKind,
    build_disclosure_state,
)


DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.grammar,PROD)"
PURPOSE = "1" * 64
GOVERNANCE = "2" * 64
EVIDENCE = "3" * 64
SNAPSHOT = "4" * 64


def _column(field: str, category: SensitivityCategory) -> GovernedColumn:
    return GovernedColumn(
        dataset_urn=DATASET_URN,
        field_path=field,
        category=category,
    )


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
):
    from toxicjoin.disclosure.models import (
        DisclosureScope,
        GovernedSubjectDomain,
        compute_scope_sha256,
        compute_subject_namespace_sha256,
    )

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
        principal_id="principal-grammar",
        agent_id="agent-grammar",
        subject=subject,
        scope_sha256=compute_scope_sha256(
            principal_id="principal-grammar",
            agent_id="agent-grammar",
            subject_namespace_sha256=namespace,
        ),
    )
    return build_disclosure_state(
        scope=scope,
        audit_history=(),
        candidate_semantic=semantic,
        candidate_composition=composition,
        purpose_commitment_sha256=PURPOSE,
        governance_commitment_sha256=GOVERNANCE,
        evidence_root_sha256=EVIDENCE,
        warehouse_snapshot_sha256=SNAPSHOT,
    )


def _action(grammar: FutureActionGrammar, kind: FutureActionKind) -> FutureAction:
    matches = [action for action in grammar.actions if action.kind == kind]
    assert len(matches) == 1
    return matches[0]


def test_context_and_grammar_are_deterministic_across_input_order() -> None:
    public = _column("country", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    q1 = _column("region", SensitivityCategory.QUASI_IDENTIFIER)
    q2 = _column("age_band", SensitivityCategory.QUASI_IDENTIFIER)
    sensitive = _column("medical_flag", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    base = _semantic(outputs=(_output(public),), referenced=(public,))
    composition = _composition(base)

    first = build_future_action_grammar_context(
        base_semantic=base,
        base_composition=composition,
        relevant_projection_fields=(sensitive, q2, q1),
        group_key_fields=(q2, q1),
        aggregate_allowlist=("sum", "COUNT"),
        cohort_variant_hmacs=("c" * 64, "b" * 64),
        snapshot_transitions=("9" * 64, "8" * 64),
    )
    second = build_future_action_grammar_context(
        base_semantic=base,
        base_composition=composition,
        relevant_projection_fields=(q1, sensitive, q2),
        group_key_fields=(q1, q2),
        aggregate_allowlist=("COUNT", "SUM"),
        cohort_variant_hmacs=("b" * 64, "c" * 64),
        snapshot_transitions=("8" * 64, "9" * 64),
    )

    assert first == second
    assert instantiate_future_action_grammar(first) == instantiate_future_action_grammar(second)


def test_context_rejects_unclassified_base_or_invalid_group_and_aggregate_inputs() -> None:
    unknown = _column("mystery", SensitivityCategory.UNCLASSIFIED)
    unknown_base = _semantic(outputs=(_output(unknown),), referenced=(unknown,))
    with pytest.raises(ValidationError, match="unclassified"):
        build_future_action_grammar_context(
            base_semantic=unknown_base,
            base_composition=_composition(unknown_base),
        )

    public = _column("country", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    base = _semantic(outputs=(_output(public),), referenced=(public,))
    with pytest.raises(ValidationError, match="quasi-identifiers"):
        build_future_action_grammar_context(
            base_semantic=base,
            base_composition=_composition(base),
            relevant_projection_fields=(public,),
            group_key_fields=(public,),
        )
    with pytest.raises(ValidationError, match="unsupported future aggregate"):
        build_future_action_grammar_context(
            base_semantic=base,
            base_composition=_composition(base),
            aggregate_allowlist=("MEDIAN",),
        )


def test_grammar_regenerates_expected_action_set_and_rejects_tampering() -> None:
    public = _column("country", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    sensitive = _column("medical_flag", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    base = _semantic(outputs=(_output(public),), referenced=(public,))
    context = build_future_action_grammar_context(
        base_semantic=base,
        base_composition=_composition(base),
        relevant_projection_fields=(sensitive,),
        snapshot_transitions=("9" * 64,),
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
    q_fields = tuple(
        _column(f"q{i:02d}", SensitivityCategory.QUASI_IDENTIFIER)
        for i in range(12)
    )
    extra_fields = tuple(
        _column(f"p{i:02d}", SensitivityCategory.PUBLIC_OR_LOW_RISK)
        for i in range(4)
    )
    context = build_future_action_grammar_context(
        base_semantic=base,
        base_composition=_composition(base),
        relevant_projection_fields=(*q_fields, *extra_fields),
        group_key_fields=q_fields,
        cohort_variant_hmacs=tuple(f"{i + 1:064x}" for i in range(8)),
        snapshot_transitions=tuple(f"{i + 20:064x}" for i in range(8)),
    )

    with pytest.raises(FutureActionGrammarError, match="budget exceeded"):
        instantiate_future_action_grammar(context)


def test_add_projection_transition_can_create_linkable_sensitive_coexposure() -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    sensitive = _column("medical_flag", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    base = _semantic(outputs=(_output(stable),), referenced=(stable,))
    composition = _composition(base)
    context = build_future_action_grammar_context(
        base_semantic=base,
        base_composition=composition,
        relevant_projection_fields=(sensitive,),
    )
    grammar = instantiate_future_action_grammar(context)
    state = _state(base, composition)

    next_state = apply_future_action(state, _action(grammar, FutureActionKind.ADD_PROJECTION), grammar)

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
    context = build_future_action_grammar_context(
        base_semantic=base,
        base_composition=composition,
        cohort_variant_hmacs=("b" * 64,),
    )
    grammar = instantiate_future_action_grammar(context)

    next_state = apply_future_action(
        _state(base, composition),
        _action(grammar, FutureActionKind.COHORT_VARIANT),
        grammar,
    )

    assert any(
        atom.kind == DisclosureAtomKind.PROTECTED_COHORT_VARIATION
        for atom in next_state.derived_atoms
    )


def test_snapshot_advance_changes_only_snapshot_commitment_and_state_hash() -> None:
    public = _column("country", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    base = _semantic(outputs=(_output(public),), referenced=(public,))
    composition = _composition(base)
    context = build_future_action_grammar_context(
        base_semantic=base,
        base_composition=composition,
        snapshot_transitions=("9" * 64,),
    )
    grammar = instantiate_future_action_grammar(context)
    state = _state(base, composition)

    next_state = apply_future_action(
        state,
        _action(grammar, FutureActionKind.SNAPSHOT_ADVANCE),
        grammar,
    )

    assert next_state.warehouse_snapshot_sha256 == "9" * 64
    assert next_state.released_atoms == state.released_atoms
    assert next_state.derived_atoms == state.derived_atoms
    assert next_state.state_sha256 != state.state_sha256


def test_replay_is_semantically_idempotent() -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    base = _semantic(outputs=(_output(stable),), referenced=(stable,))
    composition = _composition(base)
    grammar = instantiate_future_action_grammar(
        build_future_action_grammar_context(
            base_semantic=base,
            base_composition=composition,
        )
    )
    state = _state(base, composition)

    replayed = apply_future_action(state, _action(grammar, FutureActionKind.REPLAY), grammar)

    assert replayed == state


def test_self_valid_action_outside_grammar_is_rejected() -> None:
    public = _column("country", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    base = _semantic(outputs=(_output(public),), referenced=(public,))
    composition = _composition(base)
    grammar = instantiate_future_action_grammar(
        build_future_action_grammar_context(
            base_semantic=base,
            base_composition=composition,
        )
    )
    provisional = FutureAction.model_construct(
        kind=FutureActionKind.SNAPSHOT_ADVANCE,
        snapshot_sha256="9" * 64,
        semantic=None,
        composition=None,
        action_sha256="0" * 64,
    )
    outsider = FutureAction(
        kind=FutureActionKind.SNAPSHOT_ADVANCE,
        snapshot_sha256="9" * 64,
        action_sha256=compute_future_action_sha256(provisional),
    )

    with pytest.raises(FutureActionTransitionError, match="not authorized"):
        apply_future_action(_state(base, composition), outsider, grammar)


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
    context = build_future_action_grammar_context(
        base_semantic=base,
        base_composition=_composition(base),
        relevant_projection_fields=(qid,),
        group_key_fields=(qid,),
    )
    grammar = instantiate_future_action_grammar(context)
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
    grammar = instantiate_future_action_grammar(
        build_future_action_grammar_context(
            base_semantic=base,
            base_composition=_composition(base),
        )
    )

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
    grammar = instantiate_future_action_grammar(
        build_future_action_grammar_context(
            base_semantic=base,
            base_composition=_composition(base),
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
    grammar = instantiate_future_action_grammar(
        build_future_action_grammar_context(
            base_semantic=base,
            base_composition=_composition(base),
        )
    )
    payload = grammar.actions[0].model_dump(mode="json")
    payload["action_sha256"] = "0" * 64

    with pytest.raises(ValidationError, match="action hash mismatch"):
        FutureAction.model_validate(payload)
