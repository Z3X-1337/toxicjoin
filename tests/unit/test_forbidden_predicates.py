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
from toxicjoin.prospective.forbidden import (
    ForbiddenPredicateId,
    ForbiddenPredicateStatus,
    ForbiddenReasonCode,
    ForbiddenStateEvaluation,
    build_forbidden_predicate_policy,
    build_governance_trust_binding,
    build_temporal_path_context,
    build_temporal_release_observation,
    evaluate_forbidden_state,
)
from toxicjoin.prospective.grammar import (
    FutureActionKind,
    apply_future_action,
    build_future_action_grammar_context,
    instantiate_future_action_grammar,
)
from toxicjoin.prospective.twin import build_disclosure_state

DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.forbidden,PROD)"
PURPOSE = "1" * 64
GOVERNANCE = "2" * 64
EVIDENCE = "3" * 64
SNAPSHOT_A = "4" * 64
SNAPSHOT_B = "5" * 64
TRUST_EVIDENCE = "6" * 64


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
    minimum_group_size: int | None = None,
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
        "minimum_group_size_present": minimum_group_size,
    }
    provisional = DisclosureSemanticRelease.model_construct(
        **kwargs,
        semantic_sha256="0" * 64,
    )
    return DisclosureSemanticRelease(
        **kwargs,
        semantic_sha256=compute_semantic_sha256(provisional),
    )


def _composition(semantic: DisclosureSemanticRelease) -> DisclosureComposition | None:
    if not is_protected_release(semantic):
        return None
    return DisclosureComposition(
        protected_release=True,
        release_family_sha256=semantic.semantic_sha256,
        cohort_hmac_sha256="a" * 64,
    )


def _state(semantic: DisclosureSemanticRelease):
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
        principal_id="principal-forbidden",
        agent_id="agent-forbidden",
        subject=subject,
        scope_sha256=compute_scope_sha256(
            principal_id="principal-forbidden",
            agent_id="agent-forbidden",
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
        warehouse_snapshot_sha256=SNAPSHOT_A,
    )


def _policy():
    return build_forbidden_predicate_policy(minimum_group_size=10)


def _trusted_binding(commitment: str = GOVERNANCE):
    return build_governance_trust_binding(
        governance_commitment_sha256=commitment,
        trusted=True,
        trust_evidence_sha256=TRUST_EVIDENCE,
    )


def _empty_temporal():
    return build_temporal_path_context(())


def _evaluation(state, *, binding=None, temporal=None):
    return evaluate_forbidden_state(
        state,
        policy=_policy(),
        governance_binding=_trusted_binding() if binding is None else binding,
        temporal_path=_empty_temporal() if temporal is None else temporal,
    )


def _predicate(evaluation, predicate_id):
    return next(item for item in evaluation.predicates if item.predicate_id == predicate_id)


def test_f1_direct_identifier_and_sensitive_linkable_same_release_matches() -> None:
    direct = _column("email", SensitivityCategory.DIRECT_IDENTIFIER)
    sensitive = _column("diagnosis", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    state = _state(
        _semantic(
            outputs=(_output(direct), _output(sensitive)),
            referenced=(direct, sensitive),
        )
    )

    result = _predicate(_evaluation(state), ForbiddenPredicateId.F1_DIRECT_SENSITIVE_LINKAGE)

    assert result.status == ForbiddenPredicateStatus.MATCHED
    assert result.reason_code == ForbiddenReasonCode.DIRECT_AND_SENSITIVE_LINKABLE_SAME_RELEASE
    assert len(result.witness_atom_sha256s) == 2


def test_f2_stable_identifier_and_sensitive_linkable_same_release_matches() -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    sensitive = _column("diagnosis", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    state = _state(
        _semantic(
            outputs=(_output(stable), _output(sensitive)),
            referenced=(stable, sensitive),
        )
    )

    result = _predicate(_evaluation(state), ForbiddenPredicateId.F2_STABLE_LINKABLE_SENSITIVE)

    assert result.status == ForbiddenPredicateStatus.MATCHED
    assert result.reason_code == ForbiddenReasonCode.STABLE_AND_SENSITIVE_LINKABLE_SAME_RELEASE


def test_aggregate_sensitive_output_does_not_match_linkable_f2() -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    sensitive = _column("diagnosis", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    state = _state(
        _semantic(
            outputs=(
                _output(stable),
                _output(sensitive, ProjectionExposureKind.AGGREGATE_VALUE),
            ),
            referenced=(stable, sensitive),
            aggregates=("COUNT",),
        )
    )

    result = _predicate(_evaluation(state), ForbiddenPredicateId.F2_STABLE_LINKABLE_SENSITIVE)

    assert result.status == ForbiddenPredicateStatus.CLEAR


def test_f3_small_group_sensitive_matches_below_threshold() -> None:
    qid = _column("region", SensitivityCategory.QUASI_IDENTIFIER)
    sensitive = _column("diagnosis", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    state = _state(
        _semantic(
            outputs=(
                _output(qid, ProjectionExposureKind.GROUP_KEY),
                _output(sensitive, ProjectionExposureKind.AGGREGATE_VALUE),
            ),
            referenced=(qid, sensitive),
            groups=(qid,),
            aggregates=("COUNT",),
            minimum_group_size=5,
        )
    )

    result = _predicate(_evaluation(state), ForbiddenPredicateId.F3_SMALL_COHORT_SENSITIVE)

    assert result.status == ForbiddenPredicateStatus.MATCHED
    assert result.reason_code == ForbiddenReasonCode.SENSITIVE_GROUP_BELOW_MINIMUM


def test_f3_sensitive_group_without_minimum_fails_closed() -> None:
    qid = _column("region", SensitivityCategory.QUASI_IDENTIFIER)
    sensitive = _column("diagnosis", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    state = _state(
        _semantic(
            outputs=(
                _output(qid, ProjectionExposureKind.GROUP_KEY),
                _output(sensitive, ProjectionExposureKind.AGGREGATE_VALUE),
            ),
            referenced=(qid, sensitive),
            groups=(qid,),
            aggregates=("COUNT",),
            minimum_group_size=None,
        )
    )

    result = _predicate(_evaluation(state), ForbiddenPredicateId.F3_SMALL_COHORT_SENSITIVE)

    assert result.status == ForbiddenPredicateStatus.MATCHED
    assert result.reason_code == ForbiddenReasonCode.SENSITIVE_GROUP_MINIMUM_MISSING


def test_f3_group_at_or_above_threshold_is_clear() -> None:
    qid = _column("region", SensitivityCategory.QUASI_IDENTIFIER)
    sensitive = _column("diagnosis", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    state = _state(
        _semantic(
            outputs=(
                _output(qid, ProjectionExposureKind.GROUP_KEY),
                _output(sensitive, ProjectionExposureKind.AGGREGATE_VALUE),
            ),
            referenced=(qid, sensitive),
            groups=(qid,),
            aggregates=("COUNT",),
            minimum_group_size=10,
        )
    )

    result = _predicate(_evaluation(state), ForbiddenPredicateId.F3_SMALL_COHORT_SENSITIVE)

    assert result.status == ForbiddenPredicateStatus.CLEAR


def test_f4_cross_release_composition_matches_after_future_sensitive_variant() -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    sensitive = _column("diagnosis", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    base = _semantic(outputs=(_output(stable),), referenced=(stable,))
    composition = _composition(base)
    assert composition is not None
    state = _state(base)
    grammar = instantiate_future_action_grammar(
        build_future_action_grammar_context(
            base_state=state,
            base_semantic=base,
            base_composition=composition,
            relevant_projection_fields=(sensitive,),
        )
    )
    action = next(item for item in grammar.actions if item.kind == FutureActionKind.ADD_PROJECTION)
    next_state = apply_future_action(state, action, grammar)

    result = _predicate(
        _evaluation(next_state),
        ForbiddenPredicateId.F4_CROSS_RELEASE_COMPOSITION,
    )

    assert result.status == ForbiddenPredicateStatus.MATCHED
    assert result.reason_code == ForbiddenReasonCode.IDENTIFIER_AND_SENSITIVE_ACROSS_RELEASES
    assert len(result.witness_release_sha256s) == 2


def test_f5_without_temporal_context_is_indeterminate_not_clear() -> None:
    public = _column("country", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    state = _state(_semantic(outputs=(_output(public),), referenced=(public,)))

    evaluation = evaluate_forbidden_state(
        state,
        policy=_policy(),
        governance_binding=_trusted_binding(),
        temporal_path=None,
    )
    result = _predicate(evaluation, ForbiddenPredicateId.F5_TEMPORAL_DIFFERENCING)

    assert result.status == ForbiddenPredicateStatus.INDETERMINATE
    assert result.reason_code == ForbiddenReasonCode.TEMPORAL_PATH_CONTEXT_MISSING
    assert evaluation.forbidden is False
    assert ForbiddenPredicateId.F5_TEMPORAL_DIFFERENCING in evaluation.indeterminate_predicates


def test_f5_sensitive_replay_across_two_snapshots_matches() -> None:
    sensitive = _column("diagnosis", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    semantic = _semantic(outputs=(_output(sensitive),), referenced=(sensitive,))
    state = _state(semantic)
    temporal = build_temporal_path_context(
        (
            build_temporal_release_observation(
                step_index=0,
                release_semantic_sha256=semantic.semantic_sha256,
                warehouse_snapshot_sha256=SNAPSHOT_A,
                sensitive_release=True,
            ),
            build_temporal_release_observation(
                step_index=1,
                release_semantic_sha256=semantic.semantic_sha256,
                warehouse_snapshot_sha256=SNAPSHOT_B,
                sensitive_release=True,
            ),
        )
    )

    result = _predicate(
        _evaluation(state, temporal=temporal),
        ForbiddenPredicateId.F5_TEMPORAL_DIFFERENCING,
    )

    assert result.status == ForbiddenPredicateStatus.MATCHED
    assert result.reason_code == ForbiddenReasonCode.SENSITIVE_REPLAY_ACROSS_SNAPSHOTS


def test_f5_same_snapshot_replay_is_clear() -> None:
    sensitive = _column("diagnosis", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    semantic = _semantic(outputs=(_output(sensitive),), referenced=(sensitive,))
    state = _state(semantic)
    temporal = build_temporal_path_context(
        (
            build_temporal_release_observation(
                step_index=0,
                release_semantic_sha256=semantic.semantic_sha256,
                warehouse_snapshot_sha256=SNAPSHOT_A,
                sensitive_release=True,
            ),
            build_temporal_release_observation(
                step_index=1,
                release_semantic_sha256=semantic.semantic_sha256,
                warehouse_snapshot_sha256=SNAPSHOT_A,
                sensitive_release=True,
            ),
        )
    )

    result = _predicate(
        _evaluation(state, temporal=temporal),
        ForbiddenPredicateId.F5_TEMPORAL_DIFFERENCING,
    )

    assert result.status == ForbiddenPredicateStatus.CLEAR


def test_f6_requires_positive_matching_governance_binding() -> None:
    public = _column("country", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    state = _state(_semantic(outputs=(_output(public),), referenced=(public,)))

    missing = evaluate_forbidden_state(
        state,
        policy=_policy(),
        governance_binding=None,
        temporal_path=_empty_temporal(),
    )
    missing_result = _predicate(
        missing,
        ForbiddenPredicateId.F6_UNTRUSTED_GOVERNANCE_AUTHORIZATION,
    )
    assert missing_result.status == ForbiddenPredicateStatus.MATCHED
    assert missing_result.reason_code == ForbiddenReasonCode.GOVERNANCE_BINDING_MISSING

    mismatch = build_governance_trust_binding(
        governance_commitment_sha256="f" * 64,
        trusted=True,
        trust_evidence_sha256=TRUST_EVIDENCE,
    )
    mismatch_result = _predicate(
        _evaluation(state, binding=mismatch),
        ForbiddenPredicateId.F6_UNTRUSTED_GOVERNANCE_AUTHORIZATION,
    )
    assert mismatch_result.reason_code == ForbiddenReasonCode.GOVERNANCE_COMMITMENT_MISMATCH

    untrusted = build_governance_trust_binding(
        governance_commitment_sha256=GOVERNANCE,
        trusted=False,
        trust_evidence_sha256=TRUST_EVIDENCE,
    )
    untrusted_result = _predicate(
        _evaluation(state, binding=untrusted),
        ForbiddenPredicateId.F6_UNTRUSTED_GOVERNANCE_AUTHORIZATION,
    )
    assert untrusted_result.reason_code == ForbiddenReasonCode.GOVERNANCE_NOT_TRUSTED

    trusted_result = _predicate(
        _evaluation(state, binding=_trusted_binding()),
        ForbiddenPredicateId.F6_UNTRUSTED_GOVERNANCE_AUTHORIZATION,
    )
    assert trusted_result.status == ForbiddenPredicateStatus.CLEAR


def test_state_evaluation_hash_tampering_is_rejected() -> None:
    public = _column("country", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    state = _state(_semantic(outputs=(_output(public),), referenced=(public,)))
    evaluation = _evaluation(state)
    payload = evaluation.model_dump(mode="json")
    payload["evaluation_sha256"] = "0" * 64

    with pytest.raises(ValidationError, match="evaluation hash mismatch"):
        ForbiddenStateEvaluation.model_validate(payload)
