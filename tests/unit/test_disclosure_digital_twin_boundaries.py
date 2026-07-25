from __future__ import annotations

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
from toxicjoin.prospective.twin import (
    DisclosureAtomKind,
    DisclosureTwinError,
    direct_atoms_for_release,
    instantiate_disclosure_inference_rules,
    least_fixed_point,
)

DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.twin-boundary,PROD)"


def _column(field_path: str, category: SensitivityCategory) -> GovernedColumn:
    return GovernedColumn(
        dataset_urn=DATASET_URN,
        field_path=field_path,
        category=category,
    )


def _semantic(
    *,
    outputs: tuple[SemanticOutput, ...],
    referenced: tuple[GovernedColumn, ...],
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
    canonical_referenced = tuple(sorted(referenced, key=lambda column: column.key))
    provisional = DisclosureSemanticRelease.model_construct(
        source_dataset_urns=(DATASET_URN,),
        outputs=canonical_outputs,
        referenced_columns=canonical_referenced,
        join_columns=(),
        group_keys=(),
        aggregate_functions=(),
        minimum_group_size_present=None,
        semantic_sha256="0" * 64,
    )
    return DisclosureSemanticRelease(
        source_dataset_urns=(DATASET_URN,),
        outputs=canonical_outputs,
        referenced_columns=canonical_referenced,
        join_columns=(),
        group_keys=(),
        aggregate_functions=(),
        minimum_group_size_present=None,
        semantic_sha256=compute_semantic_sha256(provisional),
    )


def _output(column: GovernedColumn, kind: ProjectionExposureKind) -> SemanticOutput:
    return SemanticOutput(kind=kind, sources=(column,))


def _composition(semantic: DisclosureSemanticRelease) -> DisclosureComposition:
    return DisclosureComposition(
        protected_release=is_protected_release(semantic),
        release_family_sha256=semantic.semantic_sha256,
        cohort_hmac_sha256="a" * 64,
    )


def _derived(semantic: DisclosureSemanticRelease):
    composition = _composition(semantic) if is_protected_release(semantic) else None
    released = direct_atoms_for_release(semantic, composition)
    rules = instantiate_disclosure_inference_rules(released)
    return least_fixed_point(released, rules)


def _categories(atoms) -> set[SensitivityCategory]:
    return {
        atom.category
        for atom in atoms
        if atom.kind == DisclosureAtomKind.CATEGORY_PRESENCE and atom.category is not None
    }


def test_referenced_sensitive_column_is_structural_not_released_knowledge() -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    sensitive = _column("medical_flag", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    semantic = _semantic(
        outputs=(_output(stable, ProjectionExposureKind.RAW_VALUE),),
        referenced=(stable, sensitive),
    )

    derived = _derived(semantic)

    assert SensitivityCategory.STABLE_PSEUDONYM in _categories(derived)
    assert SensitivityCategory.SENSITIVE_ATTRIBUTE not in _categories(derived)
    assert all(
        atom.kind != DisclosureAtomKind.IDENTIFIER_SENSITIVE_COEXPOSURE
        for atom in derived
    )


def test_filter_only_output_does_not_create_sensitive_released_knowledge() -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    sensitive = _column("medical_flag", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    semantic = _semantic(
        outputs=(
            _output(stable, ProjectionExposureKind.RAW_VALUE),
            _output(sensitive, ProjectionExposureKind.FILTER_ONLY),
        ),
        referenced=(stable, sensitive),
    )

    derived = _derived(semantic)

    assert SensitivityCategory.STABLE_PSEUDONYM in _categories(derived)
    assert SensitivityCategory.SENSITIVE_ATTRIBUTE not in _categories(derived)
    assert all(
        atom.kind != DisclosureAtomKind.IDENTIFIER_SENSITIVE_COEXPOSURE
        for atom in derived
    )


def test_aggregate_sensitive_signal_is_known_but_not_raw_linkable_coexposure() -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    sensitive = _column("medical_flag", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    semantic = _semantic(
        outputs=(
            _output(stable, ProjectionExposureKind.RAW_VALUE),
            _output(sensitive, ProjectionExposureKind.AGGREGATE_VALUE),
        ),
        referenced=(stable, sensitive),
    )

    derived = _derived(semantic)

    assert SensitivityCategory.STABLE_PSEUDONYM in _categories(derived)
    assert SensitivityCategory.SENSITIVE_ATTRIBUTE in _categories(derived)
    assert all(
        atom.kind != DisclosureAtomKind.IDENTIFIER_SENSITIVE_COEXPOSURE
        for atom in derived
    )


def test_protected_release_without_composition_fails_closed() -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    semantic = _semantic(
        outputs=(_output(stable, ProjectionExposureKind.RAW_VALUE),),
        referenced=(stable,),
    )
    assert is_protected_release(semantic)

    with pytest.raises(DisclosureTwinError, match="requires composition metadata"):
        direct_atoms_for_release(semantic, None)


def test_protected_classification_mismatch_fails_closed() -> None:
    stable = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    semantic = _semantic(
        outputs=(_output(stable, ProjectionExposureKind.RAW_VALUE),),
        referenced=(stable,),
    )
    forged = DisclosureComposition(
        protected_release=False,
        release_family_sha256=semantic.semantic_sha256,
        cohort_hmac_sha256="b" * 64,
    )

    with pytest.raises(DisclosureTwinError, match="classification mismatch"):
        direct_atoms_for_release(semantic, forged)
