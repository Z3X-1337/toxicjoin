from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from toxicjoin.disclosure.models import (
    DisclosureAuditIdentity,
    DisclosureComposition,
    DisclosureEvent,
    DisclosureRecord,
    DisclosureScope,
    DisclosureSemanticRelease,
    GovernedColumn,
    GovernedSubjectDomain,
    SemanticOutput,
    compute_event_sha256,
    compute_record_sha256,
    compute_scope_sha256,
    compute_semantic_sha256,
    compute_subject_namespace_sha256,
)
from toxicjoin.models import ProjectionExposureKind, SensitivityCategory
from toxicjoin.prospective.twin import (
    DisclosureAtomKind,
    DisclosureHistoryEntry,
    DisclosureHistoryLifecycle,
    DisclosureState,
    DisclosureTwinError,
    build_disclosure_state,
)


BASE_TIME = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)
DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.twin,PROD)"
OTHER_DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.other,PROD)"
PURPOSE = "1" * 64
GOVERNANCE = "2" * 64
EVIDENCE = "3" * 64
WAREHOUSE = "4" * 64


def _scope(*, principal: str = "principal-a") -> DisclosureScope:
    subject_namespace = compute_subject_namespace_sha256(
        "customer_id",
        SensitivityCategory.STABLE_PSEUDONYM,
    )
    subject = GovernedSubjectDomain(
        field_path="customer_id",
        category=SensitivityCategory.STABLE_PSEUDONYM,
        dataset_urns=(DATASET_URN,),
        governance_domains=("urn:li:domain:privacy",),
        namespace_sha256=subject_namespace,
    )
    return DisclosureScope(
        principal_id=principal,
        agent_id="agent-a",
        subject=subject,
        scope_sha256=compute_scope_sha256(
            principal_id=principal,
            agent_id="agent-a",
            subject_namespace_sha256=subject_namespace,
        ),
    )


def _column(field_path: str, category: SensitivityCategory) -> GovernedColumn:
    return GovernedColumn(
        dataset_urn=DATASET_URN,
        field_path=field_path,
        category=category,
    )


def _semantic(
    *,
    outputs: tuple[SemanticOutput, ...] = (),
    referenced: tuple[GovernedColumn, ...] = (),
    joins: tuple[GovernedColumn, ...] = (),
    groups: tuple[GovernedColumn, ...] = (),
    aggregates: tuple[str, ...] = (),
    minimum_group_size: int | None = None,
    datasets: tuple[str, ...] = (DATASET_URN,),
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
        "source_dataset_urns": tuple(sorted(set(datasets))),
        "outputs": canonical_outputs,
        "referenced_columns": tuple(sorted(referenced, key=lambda column: column.key)),
        "join_columns": tuple(sorted(joins, key=lambda column: column.key)),
        "group_keys": tuple(sorted(groups, key=lambda column: column.key)),
        "aggregate_functions": tuple(sorted(set(value.upper() for value in aggregates))),
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


def _output(column: GovernedColumn) -> SemanticOutput:
    return SemanticOutput(
        kind=ProjectionExposureKind.RAW_VALUE,
        sources=(column,),
    )


def _composition(
    semantic: DisclosureSemanticRelease,
    *,
    cohort: str,
    protected: bool = True,
) -> DisclosureComposition:
    return DisclosureComposition(
        protected_release=protected,
        release_family_sha256=semantic.semantic_sha256,
        cohort_hmac_sha256=cohort,
    )


def _event(
    *,
    scope: DisclosureScope,
    receipt_index: int,
    semantic: DisclosureSemanticRelease,
    composition: DisclosureComposition | None = None,
) -> DisclosureEvent:
    return DisclosureEvent(
        scope=scope,
        audit_identity=DisclosureAuditIdentity(credential_id="credential-a"),
        receipt_id=f"tj_{receipt_index:016x}",
        policy_version="0.2.0",
        semantic=semantic,
        composition=composition,
    )


def _record(
    *,
    sequence: int,
    event: DisclosureEvent,
    previous: str | None,
    salt: int = 0,
) -> DisclosureRecord:
    event_sha256 = compute_event_sha256(event)
    kwargs = {
        "schema_version": "1.1" if event.composition is not None else "1.0",
        "record_id": f"dl_{sequence + salt * 1000:032x}",
        "sequence": sequence,
        "created_at": BASE_TIME + timedelta(seconds=sequence + salt * 100),
        "event": event,
        "event_sha256": event_sha256,
        "previous_content_sha256": previous,
    }
    provisional = DisclosureRecord.model_construct(**kwargs, content_sha256="0" * 64)
    return DisclosureRecord(
        **kwargs,
        content_sha256=compute_record_sha256(provisional),
    )


def _history(
    scope: DisclosureScope,
    releases: tuple[
        tuple[DisclosureSemanticRelease, DisclosureComposition | None, DisclosureHistoryLifecycle],
        ...,
    ],
    *,
    salt: int = 0,
) -> tuple[DisclosureHistoryEntry, ...]:
    entries: list[DisclosureHistoryEntry] = []
    previous: str | None = None
    for index, (semantic, composition, lifecycle) in enumerate(releases, start=1):
        record = _record(
            sequence=index,
            event=_event(
                scope=scope,
                receipt_index=index + salt * 100,
                semantic=semantic,
                composition=composition,
            ),
            previous=previous,
            salt=salt,
        )
        entries.append(DisclosureHistoryEntry(record=record, lifecycle=lifecycle))
        previous = record.content_sha256
    return tuple(entries)


def _state(
    *,
    scope: DisclosureScope,
    history: tuple[DisclosureHistoryEntry, ...],
    candidate: DisclosureSemanticRelease,
    candidate_composition: DisclosureComposition | None = None,
    purpose: str = PURPOSE,
    governance: str = GOVERNANCE,
    evidence: str = EVIDENCE,
    warehouse: str | None = WAREHOUSE,
) -> DisclosureState:
    return build_disclosure_state(
        scope=scope,
        audit_history=history,
        candidate_semantic=candidate,
        candidate_composition=candidate_composition,
        purpose_commitment_sha256=purpose,
        governance_commitment_sha256=governance,
        evidence_root_sha256=evidence,
        warehouse_snapshot_sha256=warehouse,
    )


def _derived_kinds(state: DisclosureState) -> set[DisclosureAtomKind]:
    return {atom.kind for atom in state.derived_atoms}


def test_twin_derives_identifier_sensitive_coexposure_across_active_releases() -> None:
    scope = _scope()
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    sensitive = _column("medical_flag", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    stable_release = _semantic(outputs=(_output(stable),), referenced=(stable,))
    sensitive_release = _semantic(outputs=(_output(sensitive),), referenced=(sensitive,))
    public = _column("region", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    candidate = _semantic(outputs=(_output(public),), referenced=(public,))
    history = _history(
        scope,
        (
            (stable_release, None, DisclosureHistoryLifecycle.RELEASED),
            (sensitive_release, None, DisclosureHistoryLifecycle.RELEASED),
        ),
    )

    state = _state(scope=scope, history=history, candidate=candidate)

    assert DisclosureAtomKind.CATEGORY_PRESENCE in _derived_kinds(state)
    assert DisclosureAtomKind.IDENTIFIER_SENSITIVE_COEXPOSURE in _derived_kinds(state)
    coexposure = [
        atom
        for atom in state.derived_atoms
        if atom.kind == DisclosureAtomKind.IDENTIFIER_SENSITIVE_COEXPOSURE
    ]
    assert len(coexposure) == 1
    assert coexposure[0].identifier_category == SensitivityCategory.STABLE_PSEUDONYM


def test_pending_is_conservatively_active_and_aborted_is_excluded() -> None:
    scope = _scope()
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    sensitive = _column("medical_flag", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    public = _column("region", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    stable_release = _semantic(outputs=(_output(stable),), referenced=(stable,))
    sensitive_release = _semantic(outputs=(_output(sensitive),), referenced=(sensitive,))
    candidate = _semantic(outputs=(_output(public),), referenced=(public,))

    pending = _state(
        scope=scope,
        history=_history(
            scope,
            (
                (stable_release, None, DisclosureHistoryLifecycle.RELEASED),
                (sensitive_release, None, DisclosureHistoryLifecycle.PENDING),
            ),
        ),
        candidate=candidate,
    )
    aborted = _state(
        scope=scope,
        history=_history(
            scope,
            (
                (stable_release, None, DisclosureHistoryLifecycle.RELEASED),
                (sensitive_release, None, DisclosureHistoryLifecycle.ABORTED),
            ),
        ),
        candidate=candidate,
    )

    assert DisclosureAtomKind.IDENTIFIER_SENSITIVE_COEXPOSURE in _derived_kinds(pending)
    assert DisclosureAtomKind.IDENTIFIER_SENSITIVE_COEXPOSURE not in _derived_kinds(aborted)


def test_candidate_is_projected_as_hypothetical_post_release_state() -> None:
    scope = _scope()
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    sensitive = _column("medical_flag", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    candidate = _semantic(
        outputs=(_output(stable), _output(sensitive)),
        referenced=(stable, sensitive),
    )

    state = _state(scope=scope, history=(), candidate=candidate)

    assert DisclosureAtomKind.IDENTIFIER_SENSITIVE_COEXPOSURE in _derived_kinds(state)


def test_protected_cohort_variation_is_derived_deterministically() -> None:
    scope = _scope()
    sensitive = _column("medical_flag", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    protected_release = _semantic(
        outputs=(_output(sensitive),),
        referenced=(sensitive,),
        groups=(_column("region", SensitivityCategory.QUASI_IDENTIFIER),),
        aggregates=("COUNT",),
        minimum_group_size=10,
    )
    history = _history(
        scope,
        (
            (
                protected_release,
                _composition(protected_release, cohort="a" * 64),
                DisclosureHistoryLifecycle.RELEASED,
            ),
            (
                protected_release,
                _composition(protected_release, cohort="b" * 64),
                DisclosureHistoryLifecycle.PENDING,
            ),
        ),
    )
    public = _column("region", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    candidate = _semantic(outputs=(_output(public),), referenced=(public,))

    state = _state(scope=scope, history=history, candidate=candidate)

    variations = [
        atom
        for atom in state.derived_atoms
        if atom.kind == DisclosureAtomKind.PROTECTED_COHORT_VARIATION
    ]
    assert len(variations) == 1
    assert variations[0].release_family_sha256 == protected_release.semantic_sha256


def test_state_hash_excludes_record_ids_timestamps_and_input_order() -> None:
    scope = _scope()
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    stable_release = _semantic(outputs=(_output(stable),), referenced=(stable,))
    public = _column("region", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    candidate = _semantic(outputs=(_output(public),), referenced=(public,))
    history_a = _history(
        scope,
        ((stable_release, None, DisclosureHistoryLifecycle.RELEASED),),
        salt=0,
    )
    history_b = _history(
        scope,
        ((stable_release, None, DisclosureHistoryLifecycle.RELEASED),),
        salt=7,
    )

    state_a = _state(scope=scope, history=history_a, candidate=candidate)
    state_b = _state(scope=scope, history=tuple(reversed(history_b)), candidate=candidate)

    assert history_a[0].record.record_id != history_b[0].record.record_id
    assert history_a[0].record.created_at != history_b[0].record.created_at
    assert state_a.state_sha256 == state_b.state_sha256
    assert state_a.released_atoms == state_b.released_atoms
    assert state_a.derived_atoms == state_b.derived_atoms


def test_state_hash_binds_purpose_governance_evidence_and_snapshot_commitments() -> None:
    scope = _scope()
    public = _column("region", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    candidate = _semantic(outputs=(_output(public),), referenced=(public,))
    baseline = _state(scope=scope, history=(), candidate=candidate)

    variants = (
        _state(scope=scope, history=(), candidate=candidate, purpose="5" * 64),
        _state(scope=scope, history=(), candidate=candidate, governance="6" * 64),
        _state(scope=scope, history=(), candidate=candidate, evidence="7" * 64),
        _state(scope=scope, history=(), candidate=candidate, warehouse="8" * 64),
        _state(scope=scope, history=(), candidate=candidate, warehouse=None),
    )

    assert all(variant.state_sha256 != baseline.state_sha256 for variant in variants)


def test_incomplete_hash_chain_and_scope_mismatch_fail_closed() -> None:
    scope = _scope()
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    sensitive = _column("medical_flag", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    first = _semantic(outputs=(_output(stable),), referenced=(stable,))
    second = _semantic(outputs=(_output(sensitive),), referenced=(sensitive,))
    public = _column("region", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    candidate = _semantic(outputs=(_output(public),), referenced=(public,))
    history = _history(
        scope,
        (
            (first, None, DisclosureHistoryLifecycle.RELEASED),
            (second, None, DisclosureHistoryLifecycle.RELEASED),
        ),
    )

    with pytest.raises(DisclosureTwinError, match="hash chain"):
        _state(scope=scope, history=(history[1],), candidate=candidate)

    other_scope = _scope(principal="principal-b")
    with pytest.raises(DisclosureTwinError, match="different privacy scope"):
        _state(scope=other_scope, history=history, candidate=candidate)


def test_duplicate_semantics_are_deduplicated_without_losing_closure() -> None:
    scope = _scope()
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    release = _semantic(outputs=(_output(stable),), referenced=(stable,))
    history = _history(
        scope,
        (
            (release, None, DisclosureHistoryLifecycle.RELEASED),
            (release, None, DisclosureHistoryLifecycle.PENDING),
        ),
    )

    state = _state(scope=scope, history=history, candidate=release)

    release_atoms = [
        atom
        for atom in state.released_atoms
        if atom.kind == DisclosureAtomKind.SEMANTIC_RELEASE
    ]
    assert len(release_atoms) == 1


def test_state_rejects_tampered_hash_or_derived_partition() -> None:
    scope = _scope()
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    sensitive = _column("medical_flag", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    candidate = _semantic(
        outputs=(_output(stable), _output(sensitive)),
        referenced=(stable, sensitive),
    )
    state = _state(scope=scope, history=(), candidate=candidate)

    bad_hash = state.model_dump(mode="json")
    bad_hash["state_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="state hash mismatch"):
        DisclosureState.model_validate(bad_hash)

    missing_derived = state.model_dump(mode="json")
    missing_derived["derived_atoms"] = []
    with pytest.raises(ValidationError, match="deterministic closure"):
        DisclosureState.model_validate(missing_derived)
