"""Deterministic Disclosure Digital Twin over existing ledger semantics.

The twin is an immutable projection and least-fixed-point closure. It owns no
persistence and never mutates the disclosure ledger. Callers provide one atomic
per-scope audit-history/lifecycle snapshot: ABORTED records are excluded, while
PENDING records are conservatively active to preserve the ledger's no-race
privacy semantics.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, model_validator

from toxicjoin.disclosure.composition import is_protected_release
from toxicjoin.disclosure.models import (
    DisclosureComposition,
    DisclosureRecord,
    DisclosureScope,
    DisclosureSemanticRelease,
)
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.models import ProjectionExposureKind, SensitivityCategory, StrictModel

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_TWIN_MODEL_VERSION = "0.1.0"
_INFERENCE_VERSION = "0.1.0"
_MAX_STATE_ATOMS = 4096
_MAX_INFERENCE_RULES = 8192
AtomSha256 = Annotated[str, Field(pattern=_HASH_PATTERN)]

_IDENTIFIER_CATEGORIES = {
    SensitivityCategory.DIRECT_IDENTIFIER,
    SensitivityCategory.STABLE_PSEUDONYM,
}
_REVEALING_OUTPUT_KINDS = {
    ProjectionExposureKind.RAW_VALUE,
    ProjectionExposureKind.TRANSFORMED_RAW_VALUE,
    ProjectionExposureKind.GROUP_KEY,
    ProjectionExposureKind.AGGREGATE_OPERAND,
    ProjectionExposureKind.AGGREGATE_VALUE,
    ProjectionExposureKind.CONDITIONAL_AGGREGATE,
    ProjectionExposureKind.NESTED_SCOPE,
}
_LINKABLE_OUTPUT_KINDS = {
    ProjectionExposureKind.RAW_VALUE,
    ProjectionExposureKind.TRANSFORMED_RAW_VALUE,
    ProjectionExposureKind.GROUP_KEY,
    ProjectionExposureKind.NESTED_SCOPE,
}


class DisclosureTwinError(RuntimeError):
    """Raised when disclosure history cannot be projected safely."""


class DisclosureHistoryLifecycle(StrEnum):
    PENDING = "PENDING"
    RELEASED = "RELEASED"
    ABORTED = "ABORTED"


class DisclosureHistoryEntry(StrictModel):
    """One validated ledger record plus its lifecycle in one trusted snapshot."""

    record: DisclosureRecord
    lifecycle: DisclosureHistoryLifecycle


class DisclosureAtomKind(StrEnum):
    SEMANTIC_RELEASE = "SEMANTIC_RELEASE"
    SOURCE_DATASET = "SOURCE_DATASET"
    COLUMN_EXPOSURE = "COLUMN_EXPOSURE"
    AGGREGATE_FUNCTION = "AGGREGATE_FUNCTION"
    MINIMUM_GROUP_SIZE = "MINIMUM_GROUP_SIZE"
    COHORT = "COHORT"
    CATEGORY_PRESENCE = "CATEGORY_PRESENCE"
    IDENTIFIER_SENSITIVE_COEXPOSURE = "IDENTIFIER_SENSITIVE_COEXPOSURE"
    PROTECTED_COHORT_VARIATION = "PROTECTED_COHORT_VARIATION"


class ColumnExposureRole(StrEnum):
    OUTPUT = "OUTPUT"
    REFERENCED = "REFERENCED"
    JOIN = "JOIN"
    GROUP_KEY = "GROUP_KEY"


class DisclosureAtom(StrictModel):
    """One canonical semantic fact in the prospective disclosure state."""

    schema_version: Literal["1.0"] = "1.0"
    kind: DisclosureAtomKind
    release_semantic_sha256: str | None = Field(default=None, pattern=_HASH_PATTERN)
    dataset_urn: str | None = Field(default=None, min_length=1, max_length=2048)
    column_key: str | None = Field(default=None, min_length=1, max_length=4096)
    category: SensitivityCategory | None = None
    column_role: ColumnExposureRole | None = None
    exposure_kind: ProjectionExposureKind | None = None
    aggregate_function: str | None = Field(default=None, min_length=1, max_length=128)
    minimum_group_size: int | None = Field(default=None, ge=1)
    release_family_sha256: str | None = Field(default=None, pattern=_HASH_PATTERN)
    cohort_hmac_sha256: str | None = Field(default=None, pattern=_HASH_PATTERN)
    protected_release: bool | None = None
    identifier_category: SensitivityCategory | None = None
    atom_sha256: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_atom_shape_and_hash(self) -> "DisclosureAtom":
        fields = (
            "release_semantic_sha256",
            "dataset_urn",
            "column_key",
            "category",
            "column_role",
            "exposure_kind",
            "aggregate_function",
            "minimum_group_size",
            "release_family_sha256",
            "cohort_hmac_sha256",
            "protected_release",
            "identifier_category",
        )
        populated = {name for name in fields if getattr(self, name) is not None}

        if self.kind == DisclosureAtomKind.SEMANTIC_RELEASE:
            required = allowed = {"release_semantic_sha256"}
        elif self.kind == DisclosureAtomKind.SOURCE_DATASET:
            required = allowed = {"release_semantic_sha256", "dataset_urn"}
        elif self.kind == DisclosureAtomKind.COLUMN_EXPOSURE:
            required = {
                "release_semantic_sha256",
                "column_key",
                "category",
                "column_role",
            }
            allowed = required | {"exposure_kind"}
            if self.column_role == ColumnExposureRole.OUTPUT:
                required = required | {"exposure_kind"}
            elif self.exposure_kind is not None:
                raise ValueError("only OUTPUT column exposures may carry exposure_kind")
        elif self.kind == DisclosureAtomKind.AGGREGATE_FUNCTION:
            required = allowed = {"release_semantic_sha256", "aggregate_function"}
            if self.aggregate_function != self.aggregate_function.strip().upper():
                raise ValueError("aggregate_function must be normalized uppercase")
        elif self.kind == DisclosureAtomKind.MINIMUM_GROUP_SIZE:
            required = allowed = {"release_semantic_sha256", "minimum_group_size"}
        elif self.kind == DisclosureAtomKind.COHORT:
            required = allowed = {
                "release_semantic_sha256",
                "release_family_sha256",
                "cohort_hmac_sha256",
                "protected_release",
            }
            if self.release_family_sha256 != self.release_semantic_sha256:
                raise ValueError("cohort release family must match semantic release hash")
        elif self.kind == DisclosureAtomKind.CATEGORY_PRESENCE:
            required = allowed = {"category"}
        elif self.kind == DisclosureAtomKind.IDENTIFIER_SENSITIVE_COEXPOSURE:
            required = allowed = {"identifier_category"}
            if self.identifier_category not in _IDENTIFIER_CATEGORIES:
                raise ValueError("coexposure requires a governed identifier category")
        elif self.kind == DisclosureAtomKind.PROTECTED_COHORT_VARIATION:
            required = allowed = {"release_family_sha256"}
        else:  # pragma: no cover - exhaustive enum guard
            raise ValueError("unsupported disclosure atom kind")

        if not required.issubset(populated) or not populated.issubset(allowed):
            raise ValueError(f"invalid field shape for disclosure atom kind {self.kind.value}")
        if self.atom_sha256 != compute_disclosure_atom_sha256(self):
            raise ValueError("disclosure atom hash mismatch")
        return self


class DisclosureInferenceRuleFamily(StrEnum):
    CATEGORY_PRESENCE = "CATEGORY_PRESENCE"
    IDENTIFIER_SENSITIVE_COEXPOSURE = "IDENTIFIER_SENSITIVE_COEXPOSURE"
    PROTECTED_COHORT_VARIATION = "PROTECTED_COHORT_VARIATION"


class DisclosureInferenceRule(StrictModel):
    """One deterministic instantiated hyperedge over canonical disclosure atoms."""

    schema_version: Literal["1.0"] = "1.0"
    inference_version: Literal["0.1.0"] = _INFERENCE_VERSION
    family: DisclosureInferenceRuleFamily
    antecedent_atom_sha256s: tuple[AtomSha256, ...] = Field(min_length=1, max_length=16)
    consequent: DisclosureAtom
    rule_sha256: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_rule(self) -> "DisclosureInferenceRule":
        if self.antecedent_atom_sha256s != tuple(sorted(set(self.antecedent_atom_sha256s))):
            raise ValueError("inference antecedents must be sorted and unique")
        expected_kind = {
            DisclosureInferenceRuleFamily.CATEGORY_PRESENCE: DisclosureAtomKind.CATEGORY_PRESENCE,
            DisclosureInferenceRuleFamily.IDENTIFIER_SENSITIVE_COEXPOSURE: (
                DisclosureAtomKind.IDENTIFIER_SENSITIVE_COEXPOSURE
            ),
            DisclosureInferenceRuleFamily.PROTECTED_COHORT_VARIATION: (
                DisclosureAtomKind.PROTECTED_COHORT_VARIATION
            ),
        }[self.family]
        if self.consequent.kind != expected_kind:
            raise ValueError("inference rule family does not match consequent atom kind")
        if self.rule_sha256 != compute_disclosure_inference_rule_sha256(self):
            raise ValueError("disclosure inference rule hash mismatch")
        return self


_DIRECT_ATOM_KINDS = {
    DisclosureAtomKind.SEMANTIC_RELEASE,
    DisclosureAtomKind.SOURCE_DATASET,
    DisclosureAtomKind.COLUMN_EXPOSURE,
    DisclosureAtomKind.AGGREGATE_FUNCTION,
    DisclosureAtomKind.MINIMUM_GROUP_SIZE,
    DisclosureAtomKind.COHORT,
}
_DERIVED_ATOM_KINDS = {
    DisclosureAtomKind.CATEGORY_PRESENCE,
    DisclosureAtomKind.IDENTIFIER_SENSITIVE_COEXPOSURE,
    DisclosureAtomKind.PROTECTED_COHORT_VARIATION,
}


class DisclosureState(StrictModel):
    """Immutable canonical post-candidate disclosure knowledge state."""

    schema_version: Literal["1.0"] = "1.0"
    model_version: Literal["0.1.0"] = _TWIN_MODEL_VERSION
    inference_version: Literal["0.1.0"] = _INFERENCE_VERSION
    scope: DisclosureScope
    purpose_commitment_sha256: str = Field(pattern=_HASH_PATTERN)
    governance_commitment_sha256: str = Field(pattern=_HASH_PATTERN)
    evidence_root_sha256: str = Field(pattern=_HASH_PATTERN)
    warehouse_snapshot_sha256: str | None = Field(default=None, pattern=_HASH_PATTERN)
    released_atoms: tuple[DisclosureAtom, ...] = Field(min_length=1, max_length=_MAX_STATE_ATOMS)
    derived_atoms: tuple[DisclosureAtom, ...] = Field(default=(), max_length=_MAX_STATE_ATOMS)
    inference_rules_sha256: str = Field(pattern=_HASH_PATTERN)
    state_sha256: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_state(self) -> "DisclosureState":
        _require_canonical_atoms(self.released_atoms, expected_kinds=_DIRECT_ATOM_KINDS)
        _require_canonical_atoms(self.derived_atoms, expected_kinds=_DERIVED_ATOM_KINDS)
        released_hashes = {atom.atom_sha256 for atom in self.released_atoms}
        if released_hashes.intersection(atom.atom_sha256 for atom in self.derived_atoms):
            raise ValueError("released and derived disclosure atoms must be disjoint")

        rules = instantiate_disclosure_inference_rules(self.released_atoms)
        if self.inference_rules_sha256 != compute_inference_rules_sha256(rules):
            raise ValueError("disclosure inference-rule commitment mismatch")
        if self.derived_atoms != least_fixed_point(self.released_atoms, rules):
            raise ValueError("derived disclosure atoms do not match deterministic closure")
        if self.state_sha256 != compute_disclosure_state_sha256(self):
            raise ValueError("disclosure state hash mismatch")
        return self


def build_disclosure_state(
    *,
    scope: DisclosureScope,
    audit_history: tuple[DisclosureHistoryEntry, ...],
    candidate_semantic: DisclosureSemanticRelease,
    candidate_composition: DisclosureComposition | None,
    purpose_commitment_sha256: str,
    governance_commitment_sha256: str,
    evidence_root_sha256: str,
    warehouse_snapshot_sha256: str | None = None,
) -> DisclosureState:
    """Project complete scope history plus the candidate into a post-candidate state."""

    ordered_history = _validate_and_order_history(scope, audit_history)
    active_records = tuple(
        entry.record
        for entry in ordered_history
        if entry.lifecycle != DisclosureHistoryLifecycle.ABORTED
    )

    direct_atoms: dict[str, DisclosureAtom] = {}
    for record in active_records:
        for atom in direct_atoms_for_release(record.event.semantic, record.event.composition):
            direct_atoms[atom.atom_sha256] = atom
    for atom in direct_atoms_for_release(candidate_semantic, candidate_composition):
        direct_atoms[atom.atom_sha256] = atom

    if len(direct_atoms) > _MAX_STATE_ATOMS:
        raise DisclosureTwinError("disclosure state direct-atom budget exceeded")
    released_atoms = tuple(direct_atoms[key] for key in sorted(direct_atoms))
    rules = instantiate_disclosure_inference_rules(released_atoms)
    derived_atoms = least_fixed_point(released_atoms, rules)
    rules_root = compute_inference_rules_sha256(rules)

    provisional = DisclosureState.model_construct(
        scope=scope,
        purpose_commitment_sha256=purpose_commitment_sha256,
        governance_commitment_sha256=governance_commitment_sha256,
        evidence_root_sha256=evidence_root_sha256,
        warehouse_snapshot_sha256=warehouse_snapshot_sha256,
        released_atoms=released_atoms,
        derived_atoms=derived_atoms,
        inference_rules_sha256=rules_root,
        state_sha256="0" * 64,
    )
    return DisclosureState(
        scope=scope,
        purpose_commitment_sha256=purpose_commitment_sha256,
        governance_commitment_sha256=governance_commitment_sha256,
        evidence_root_sha256=evidence_root_sha256,
        warehouse_snapshot_sha256=warehouse_snapshot_sha256,
        released_atoms=released_atoms,
        derived_atoms=derived_atoms,
        inference_rules_sha256=rules_root,
        state_sha256=compute_disclosure_state_sha256(provisional),
    )


def direct_atoms_for_release(
    semantic: DisclosureSemanticRelease,
    composition: DisclosureComposition | None,
) -> tuple[DisclosureAtom, ...]:
    """Project one semantic release into direct atoms without raw SQL or rows."""

    release_sha = semantic.semantic_sha256
    protected = is_protected_release(semantic)
    if composition is None:
        if protected:
            raise DisclosureTwinError("protected semantic release requires composition metadata")
    else:
        if composition.release_family_sha256 != release_sha:
            raise DisclosureTwinError("composition does not match semantic release")
        if composition.protected_release != protected:
            raise DisclosureTwinError("composition protected-release classification mismatch")

    atoms: dict[str, DisclosureAtom] = {}

    def add(atom: DisclosureAtom) -> None:
        atoms[atom.atom_sha256] = atom

    add(_build_atom(DisclosureAtomKind.SEMANTIC_RELEASE, release_semantic_sha256=release_sha))
    for urn in semantic.source_dataset_urns:
        add(
            _build_atom(
                DisclosureAtomKind.SOURCE_DATASET,
                release_semantic_sha256=release_sha,
                dataset_urn=urn,
            )
        )
    for output in semantic.outputs:
        for source in output.sources:
            add(
                _build_atom(
                    DisclosureAtomKind.COLUMN_EXPOSURE,
                    release_semantic_sha256=release_sha,
                    column_key=source.key,
                    category=source.category,
                    column_role=ColumnExposureRole.OUTPUT,
                    exposure_kind=output.kind,
                )
            )
    for role, columns in (
        (ColumnExposureRole.REFERENCED, semantic.referenced_columns),
        (ColumnExposureRole.JOIN, semantic.join_columns),
        (ColumnExposureRole.GROUP_KEY, semantic.group_keys),
    ):
        for column in columns:
            add(
                _build_atom(
                    DisclosureAtomKind.COLUMN_EXPOSURE,
                    release_semantic_sha256=release_sha,
                    column_key=column.key,
                    category=column.category,
                    column_role=role,
                )
            )
    for function in semantic.aggregate_functions:
        add(
            _build_atom(
                DisclosureAtomKind.AGGREGATE_FUNCTION,
                release_semantic_sha256=release_sha,
                aggregate_function=function,
            )
        )
    if semantic.minimum_group_size_present is not None:
        add(
            _build_atom(
                DisclosureAtomKind.MINIMUM_GROUP_SIZE,
                release_semantic_sha256=release_sha,
                minimum_group_size=semantic.minimum_group_size_present,
            )
        )
    if composition is not None:
        add(
            _build_atom(
                DisclosureAtomKind.COHORT,
                release_semantic_sha256=release_sha,
                release_family_sha256=composition.release_family_sha256,
                cohort_hmac_sha256=composition.cohort_hmac_sha256,
                protected_release=composition.protected_release,
            )
        )
    return tuple(atoms[key] for key in sorted(atoms))


def instantiate_disclosure_inference_rules(
    released_atoms: tuple[DisclosureAtom, ...],
) -> tuple[DisclosureInferenceRule, ...]:
    """Instantiate finite P0 inference hyperedges from direct semantic atoms."""

    _require_canonical_atoms(released_atoms, expected_kinds=_DIRECT_ATOM_KINDS)
    rules: dict[str, DisclosureInferenceRule] = {}

    revealing_outputs = tuple(
        atom
        for atom in released_atoms
        if atom.kind == DisclosureAtomKind.COLUMN_EXPOSURE
        and atom.column_role == ColumnExposureRole.OUTPUT
        and atom.exposure_kind in _REVEALING_OUTPUT_KINDS
    )
    for atom in revealing_outputs:
        assert atom.category is not None
        rule = _build_rule(
            DisclosureInferenceRuleFamily.CATEGORY_PRESENCE,
            antecedents=(atom.atom_sha256,),
            consequent=_build_atom(
                DisclosureAtomKind.CATEGORY_PRESENCE,
                category=atom.category,
            ),
        )
        rules[rule.rule_sha256] = rule

    linkable_outputs = tuple(
        atom
        for atom in revealing_outputs
        if atom.exposure_kind in _LINKABLE_OUTPUT_KINDS
    )
    sensitive_outputs = tuple(
        atom
        for atom in linkable_outputs
        if atom.category == SensitivityCategory.SENSITIVE_ATTRIBUTE
    )
    if sensitive_outputs:
        sensitive = min(sensitive_outputs, key=lambda atom: atom.atom_sha256)
        for identifier_category in sorted(_IDENTIFIER_CATEGORIES, key=lambda value: value.value):
            identifier_outputs = tuple(
                atom for atom in linkable_outputs if atom.category == identifier_category
            )
            if not identifier_outputs:
                continue
            identifier = min(identifier_outputs, key=lambda atom: atom.atom_sha256)
            rule = _build_rule(
                DisclosureInferenceRuleFamily.IDENTIFIER_SENSITIVE_COEXPOSURE,
                antecedents=(identifier.atom_sha256, sensitive.atom_sha256),
                consequent=_build_atom(
                    DisclosureAtomKind.IDENTIFIER_SENSITIVE_COEXPOSURE,
                    identifier_category=identifier_category,
                ),
            )
            rules[rule.rule_sha256] = rule

    cohorts_by_family: dict[str, dict[str, DisclosureAtom]] = {}
    for atom in released_atoms:
        if atom.kind != DisclosureAtomKind.COHORT or atom.protected_release is not True:
            continue
        assert atom.release_family_sha256 is not None
        assert atom.cohort_hmac_sha256 is not None
        family = cohorts_by_family.setdefault(atom.release_family_sha256, {})
        existing = family.get(atom.cohort_hmac_sha256)
        if existing is None or atom.atom_sha256 < existing.atom_sha256:
            family[atom.cohort_hmac_sha256] = atom
    for family_sha256, cohorts in sorted(cohorts_by_family.items()):
        distinct = tuple(sorted(cohorts.values(), key=lambda atom: atom.atom_sha256))
        if len(distinct) < 2:
            continue
        rule = _build_rule(
            DisclosureInferenceRuleFamily.PROTECTED_COHORT_VARIATION,
            antecedents=(distinct[0].atom_sha256, distinct[1].atom_sha256),
            consequent=_build_atom(
                DisclosureAtomKind.PROTECTED_COHORT_VARIATION,
                release_family_sha256=family_sha256,
            ),
        )
        rules[rule.rule_sha256] = rule

    if len(rules) > _MAX_INFERENCE_RULES:
        raise DisclosureTwinError("disclosure inference-rule budget exceeded")
    return tuple(rules[key] for key in sorted(rules))


def least_fixed_point(
    released_atoms: tuple[DisclosureAtom, ...],
    rules: tuple[DisclosureInferenceRule, ...],
) -> tuple[DisclosureAtom, ...]:
    """Compute deterministic least fixed point without LLM/probabilistic inference."""

    known = {atom.atom_sha256: atom for atom in released_atoms}
    seed_hashes = set(known)
    ordered_rules = tuple(sorted(rules, key=lambda rule: rule.rule_sha256))
    changed = True
    while changed:
        changed = False
        for rule in ordered_rules:
            if all(digest in known for digest in rule.antecedent_atom_sha256s):
                consequent = rule.consequent
                existing = known.get(consequent.atom_sha256)
                if existing is not None:
                    if existing != consequent:
                        raise DisclosureTwinError("disclosure atom hash collision")
                    continue
                known[consequent.atom_sha256] = consequent
                changed = True
    derived = [atom for digest, atom in known.items() if digest not in seed_hashes]
    if len(derived) > _MAX_STATE_ATOMS:
        raise DisclosureTwinError("disclosure state derived-atom budget exceeded")
    return tuple(sorted(derived, key=lambda atom: atom.atom_sha256))


def compute_disclosure_atom_sha256(atom: DisclosureAtom) -> str:
    return canonical_json_sha256(atom.model_dump(mode="json", exclude={"atom_sha256"}))


def compute_disclosure_inference_rule_sha256(rule: DisclosureInferenceRule) -> str:
    return canonical_json_sha256(rule.model_dump(mode="json", exclude={"rule_sha256"}))


def compute_inference_rules_sha256(rules: tuple[DisclosureInferenceRule, ...]) -> str:
    return canonical_json_sha256(
        {
            "inference_version": _INFERENCE_VERSION,
            "rule_sha256s": sorted(rule.rule_sha256 for rule in rules),
        }
    )


def compute_disclosure_state_sha256(state: DisclosureState) -> str:
    """Hash relevant semantics only; exclude record IDs, timestamps, SQL, aliases."""

    return canonical_json_sha256(
        {
            "schema_version": state.schema_version,
            "model_version": state.model_version,
            "inference_version": state.inference_version,
            "scope_sha256": state.scope.scope_sha256,
            "purpose_commitment_sha256": state.purpose_commitment_sha256,
            "governance_commitment_sha256": state.governance_commitment_sha256,
            "evidence_root_sha256": state.evidence_root_sha256,
            "warehouse_snapshot_sha256": state.warehouse_snapshot_sha256,
            "released_atom_sha256s": [atom.atom_sha256 for atom in state.released_atoms],
            "derived_atom_sha256s": [atom.atom_sha256 for atom in state.derived_atoms],
            "inference_rules_sha256": state.inference_rules_sha256,
        }
    )


def _build_atom(kind: DisclosureAtomKind, **kwargs: object) -> DisclosureAtom:
    provisional = DisclosureAtom.model_construct(kind=kind, atom_sha256="0" * 64, **kwargs)
    return DisclosureAtom(
        kind=kind,
        atom_sha256=compute_disclosure_atom_sha256(provisional),
        **kwargs,
    )


def _build_rule(
    family: DisclosureInferenceRuleFamily,
    *,
    antecedents: tuple[str, ...],
    consequent: DisclosureAtom,
) -> DisclosureInferenceRule:
    canonical = tuple(sorted(set(antecedents)))
    provisional = DisclosureInferenceRule.model_construct(
        family=family,
        antecedent_atom_sha256s=canonical,
        consequent=consequent,
        rule_sha256="0" * 64,
    )
    return DisclosureInferenceRule(
        family=family,
        antecedent_atom_sha256s=canonical,
        consequent=consequent,
        rule_sha256=compute_disclosure_inference_rule_sha256(provisional),
    )


def _require_canonical_atoms(
    atoms: tuple[DisclosureAtom, ...],
    *,
    expected_kinds: set[DisclosureAtomKind],
) -> None:
    hashes = tuple(atom.atom_sha256 for atom in atoms)
    if hashes != tuple(sorted(set(hashes))):
        raise ValueError("disclosure atoms must be sorted and unique")
    if any(atom.kind not in expected_kinds for atom in atoms):
        raise ValueError("disclosure atom partition contains an invalid atom kind")


def _validate_and_order_history(
    scope: DisclosureScope,
    entries: tuple[DisclosureHistoryEntry, ...],
) -> tuple[DisclosureHistoryEntry, ...]:
    ordered = tuple(sorted(entries, key=lambda entry: entry.record.sequence))
    sequences = tuple(entry.record.sequence for entry in ordered)
    if sequences != tuple(sorted(set(sequences))):
        raise DisclosureTwinError("disclosure audit history contains duplicate sequences")

    previous: str | None = None
    for entry in ordered:
        record = entry.record
        if not _same_privacy_scope(record.event.scope, scope):
            raise DisclosureTwinError("disclosure audit history contains a different privacy scope")
        if record.previous_content_sha256 != previous:
            raise DisclosureTwinError("disclosure audit history hash chain is incomplete or broken")
        previous = record.content_sha256
    return ordered


def _same_privacy_scope(left: DisclosureScope, right: DisclosureScope) -> bool:
    return (
        left.scope_sha256 == right.scope_sha256
        and left.principal_id == right.principal_id
        and left.agent_id == right.agent_id
        and left.subject.namespace_sha256 == right.subject.namespace_sha256
        and left.subject.field_path.casefold() == right.subject.field_path.casefold()
        and left.subject.category == right.subject.category
    )
