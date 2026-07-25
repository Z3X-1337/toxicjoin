"""Deterministic forbidden-state predicates for prospective privacy analysis.

State predicates inspect canonical Disclosure Twin atoms. Temporal differencing is
path-sensitive by construction because the existing disclosure ledger does not commit a
warehouse snapshot per historical release. F5 therefore consumes a separate trusted path
context rather than pretending that DisclosureState alone contains temporal provenance.
"""

from __future__ import annotations

from collections import defaultdict
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, model_validator

from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.models import ProjectionExposureKind, SensitivityCategory, StrictModel
from toxicjoin.prospective.twin import (
    ColumnExposureRole,
    DisclosureAtom,
    DisclosureAtomKind,
    DisclosureState,
)

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_FORBIDDEN_POLICY_VERSION = "0.1.0"
Sha256 = Annotated[str, Field(pattern=_HASH_PATTERN)]

_LINKABLE_OUTPUT_KINDS = {
    ProjectionExposureKind.RAW_VALUE,
    ProjectionExposureKind.TRANSFORMED_RAW_VALUE,
    ProjectionExposureKind.GROUP_KEY,
    ProjectionExposureKind.NESTED_SCOPE,
}
_REVEALING_OUTPUT_KINDS = _LINKABLE_OUTPUT_KINDS | {
    ProjectionExposureKind.AGGREGATE_OPERAND,
    ProjectionExposureKind.AGGREGATE_VALUE,
    ProjectionExposureKind.CONDITIONAL_AGGREGATE,
}
_IDENTIFIER_CATEGORIES = {
    SensitivityCategory.DIRECT_IDENTIFIER,
    SensitivityCategory.STABLE_PSEUDONYM,
}


class ForbiddenPredicateError(RuntimeError):
    """Raised when forbidden-state evaluation cannot be performed safely."""


class ForbiddenPredicateId(StrEnum):
    F1_DIRECT_SENSITIVE_LINKAGE = "F1_DIRECT_SENSITIVE_LINKAGE"
    F2_STABLE_LINKABLE_SENSITIVE = "F2_STABLE_LINKABLE_SENSITIVE"
    F3_SMALL_COHORT_SENSITIVE = "F3_SMALL_COHORT_SENSITIVE"
    F4_CROSS_RELEASE_COMPOSITION = "F4_CROSS_RELEASE_COMPOSITION"
    F5_TEMPORAL_DIFFERENCING = "F5_TEMPORAL_DIFFERENCING"
    F6_UNTRUSTED_GOVERNANCE_AUTHORIZATION = "F6_UNTRUSTED_GOVERNANCE_AUTHORIZATION"


class ForbiddenPredicateStatus(StrEnum):
    MATCHED = "MATCHED"
    CLEAR = "CLEAR"
    INDETERMINATE = "INDETERMINATE"


class ForbiddenReasonCode(StrEnum):
    CLEAR = "CLEAR"
    DIRECT_AND_SENSITIVE_LINKABLE_SAME_RELEASE = "DIRECT_AND_SENSITIVE_LINKABLE_SAME_RELEASE"
    STABLE_AND_SENSITIVE_LINKABLE_SAME_RELEASE = "STABLE_AND_SENSITIVE_LINKABLE_SAME_RELEASE"
    SENSITIVE_GROUP_BELOW_MINIMUM = "SENSITIVE_GROUP_BELOW_MINIMUM"
    SENSITIVE_GROUP_MINIMUM_MISSING = "SENSITIVE_GROUP_MINIMUM_MISSING"
    IDENTIFIER_AND_SENSITIVE_ACROSS_RELEASES = "IDENTIFIER_AND_SENSITIVE_ACROSS_RELEASES"
    SENSITIVE_REPLAY_ACROSS_SNAPSHOTS = "SENSITIVE_REPLAY_ACROSS_SNAPSHOTS"
    TEMPORAL_PATH_CONTEXT_MISSING = "TEMPORAL_PATH_CONTEXT_MISSING"
    GOVERNANCE_BINDING_MISSING = "GOVERNANCE_BINDING_MISSING"
    GOVERNANCE_COMMITMENT_MISMATCH = "GOVERNANCE_COMMITMENT_MISMATCH"
    GOVERNANCE_NOT_TRUSTED = "GOVERNANCE_NOT_TRUSTED"


class ForbiddenPredicatePolicy(StrictModel):
    """Versioned security-owned thresholds used by forbidden predicates."""

    schema_version: Literal["1.0"] = "1.0"
    policy_version: Literal["0.1.0"] = _FORBIDDEN_POLICY_VERSION
    minimum_group_size: int = Field(ge=2, le=1_000_000)
    policy_sha256: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_policy(self) -> "ForbiddenPredicatePolicy":
        if self.policy_sha256 != compute_forbidden_policy_sha256(self):
            raise ValueError("forbidden predicate policy hash mismatch")
        return self


class GovernanceTrustBinding(StrictModel):
    """Trusted caller assertion about the exact governance commitment in a Twin state."""

    schema_version: Literal["1.0"] = "1.0"
    governance_commitment_sha256: str = Field(pattern=_HASH_PATTERN)
    trusted: bool
    trust_evidence_sha256: str = Field(pattern=_HASH_PATTERN)
    binding_sha256: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_binding(self) -> "GovernanceTrustBinding":
        if self.binding_sha256 != compute_governance_trust_binding_sha256(self):
            raise ValueError("governance trust binding hash mismatch")
        return self


class TemporalReleaseObservation(StrictModel):
    """One path-local release observation built by the prospective checker."""

    schema_version: Literal["1.0"] = "1.0"
    step_index: int = Field(ge=0, le=5)
    release_semantic_sha256: str = Field(pattern=_HASH_PATTERN)
    warehouse_snapshot_sha256: str | None = Field(default=None, pattern=_HASH_PATTERN)
    sensitive_release: bool
    observation_sha256: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_observation(self) -> "TemporalReleaseObservation":
        if self.observation_sha256 != compute_temporal_observation_sha256(self):
            raise ValueError("temporal release observation hash mismatch")
        return self


class TemporalPathContext(StrictModel):
    """Canonical path-sensitive temporal provenance for F5."""

    schema_version: Literal["1.0"] = "1.0"
    observations: tuple[TemporalReleaseObservation, ...] = Field(default=(), max_length=64)
    path_sha256: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_path(self) -> "TemporalPathContext":
        keys = tuple((item.step_index, item.observation_sha256) for item in self.observations)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("temporal observations must be sorted and unique")
        if self.path_sha256 != compute_temporal_path_sha256(self):
            raise ValueError("temporal path hash mismatch")
        return self


class ForbiddenPredicateEvaluation(StrictModel):
    """One canonical result with deterministic witness commitments."""

    schema_version: Literal["1.0"] = "1.0"
    predicate_id: ForbiddenPredicateId
    status: ForbiddenPredicateStatus
    reason_code: ForbiddenReasonCode
    state_sha256: str = Field(pattern=_HASH_PATTERN)
    witness_atom_sha256s: tuple[Sha256, ...] = Field(default=(), max_length=16)
    witness_release_sha256s: tuple[Sha256, ...] = Field(default=(), max_length=8)
    evaluation_sha256: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_evaluation(self) -> "ForbiddenPredicateEvaluation":
        if self.witness_atom_sha256s != tuple(sorted(set(self.witness_atom_sha256s))):
            raise ValueError("predicate witness atoms must be sorted and unique")
        if self.witness_release_sha256s != tuple(sorted(set(self.witness_release_sha256s))):
            raise ValueError("predicate witness releases must be sorted and unique")
        if self.status == ForbiddenPredicateStatus.CLEAR:
            if self.reason_code != ForbiddenReasonCode.CLEAR:
                raise ValueError("clear predicate evaluation requires CLEAR reason")
            if self.witness_atom_sha256s or self.witness_release_sha256s:
                raise ValueError("clear predicate evaluation must not contain witnesses")
        elif self.reason_code == ForbiddenReasonCode.CLEAR:
            raise ValueError("non-clear predicate evaluation requires a specific reason")
        if self.evaluation_sha256 != compute_forbidden_predicate_evaluation_sha256(self):
            raise ValueError("forbidden predicate evaluation hash mismatch")
        return self


class ForbiddenStateEvaluation(StrictModel):
    """Complete F1-F6 evaluation for one DisclosureState."""

    schema_version: Literal["1.0"] = "1.0"
    state_sha256: str = Field(pattern=_HASH_PATTERN)
    policy_sha256: str = Field(pattern=_HASH_PATTERN)
    governance_binding_sha256: str | None = Field(default=None, pattern=_HASH_PATTERN)
    temporal_path_sha256: str | None = Field(default=None, pattern=_HASH_PATTERN)
    predicates: tuple[ForbiddenPredicateEvaluation, ...] = Field(min_length=6, max_length=6)
    matched_predicates: tuple[ForbiddenPredicateId, ...]
    indeterminate_predicates: tuple[ForbiddenPredicateId, ...]
    forbidden: bool
    evaluation_sha256: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_state_evaluation(self) -> "ForbiddenStateEvaluation":
        ids = tuple(item.predicate_id for item in self.predicates)
        expected_ids = tuple(ForbiddenPredicateId)
        if ids != expected_ids:
            raise ValueError("forbidden predicates must contain canonical F1-F6 order")
        if any(item.state_sha256 != self.state_sha256 for item in self.predicates):
            raise ValueError("predicate evaluation state commitment mismatch")
        expected_matched = tuple(
            item.predicate_id
            for item in self.predicates
            if item.status == ForbiddenPredicateStatus.MATCHED
        )
        expected_indeterminate = tuple(
            item.predicate_id
            for item in self.predicates
            if item.status == ForbiddenPredicateStatus.INDETERMINATE
        )
        if self.matched_predicates != expected_matched:
            raise ValueError("matched predicate summary mismatch")
        if self.indeterminate_predicates != expected_indeterminate:
            raise ValueError("indeterminate predicate summary mismatch")
        if self.forbidden != bool(expected_matched):
            raise ValueError("forbidden summary mismatch")
        if self.evaluation_sha256 != compute_forbidden_state_evaluation_sha256(self):
            raise ValueError("forbidden-state evaluation hash mismatch")
        return self


def build_forbidden_predicate_policy(*, minimum_group_size: int) -> ForbiddenPredicatePolicy:
    provisional = ForbiddenPredicatePolicy.model_construct(
        minimum_group_size=minimum_group_size,
        policy_sha256="0" * 64,
    )
    return ForbiddenPredicatePolicy(
        minimum_group_size=minimum_group_size,
        policy_sha256=compute_forbidden_policy_sha256(provisional),
    )


def build_governance_trust_binding(
    *,
    governance_commitment_sha256: str,
    trusted: bool,
    trust_evidence_sha256: str,
) -> GovernanceTrustBinding:
    provisional = GovernanceTrustBinding.model_construct(
        governance_commitment_sha256=governance_commitment_sha256,
        trusted=trusted,
        trust_evidence_sha256=trust_evidence_sha256,
        binding_sha256="0" * 64,
    )
    return GovernanceTrustBinding(
        governance_commitment_sha256=governance_commitment_sha256,
        trusted=trusted,
        trust_evidence_sha256=trust_evidence_sha256,
        binding_sha256=compute_governance_trust_binding_sha256(provisional),
    )


def build_temporal_release_observation(
    *,
    step_index: int,
    release_semantic_sha256: str,
    warehouse_snapshot_sha256: str | None,
    sensitive_release: bool,
) -> TemporalReleaseObservation:
    provisional = TemporalReleaseObservation.model_construct(
        step_index=step_index,
        release_semantic_sha256=release_semantic_sha256,
        warehouse_snapshot_sha256=warehouse_snapshot_sha256,
        sensitive_release=sensitive_release,
        observation_sha256="0" * 64,
    )
    return TemporalReleaseObservation(
        step_index=step_index,
        release_semantic_sha256=release_semantic_sha256,
        warehouse_snapshot_sha256=warehouse_snapshot_sha256,
        sensitive_release=sensitive_release,
        observation_sha256=compute_temporal_observation_sha256(provisional),
    )


def build_temporal_path_context(
    observations: tuple[TemporalReleaseObservation, ...],
) -> TemporalPathContext:
    canonical = tuple(sorted(observations, key=lambda item: (item.step_index, item.observation_sha256)))
    provisional = TemporalPathContext.model_construct(
        observations=canonical,
        path_sha256="0" * 64,
    )
    return TemporalPathContext(
        observations=canonical,
        path_sha256=compute_temporal_path_sha256(provisional),
    )


def evaluate_forbidden_state(
    state: DisclosureState,
    *,
    policy: ForbiddenPredicatePolicy,
    governance_binding: GovernanceTrustBinding | None,
    temporal_path: TemporalPathContext | None = None,
) -> ForbiddenStateEvaluation:
    """Evaluate F1-F6 with deterministic minimal witnesses.

    F5 is INDETERMINATE when path-local temporal provenance is absent. The later PPMC
    layer must treat indeterminate security predicates according to an explicit fail-closed
    search policy; this state evaluator does not silently reinterpret absence as safety.
    """

    direct = tuple(state.released_atoms)
    output_atoms = tuple(
        atom
        for atom in direct
        if atom.kind == DisclosureAtomKind.COLUMN_EXPOSURE
        and atom.column_role == ColumnExposureRole.OUTPUT
    )
    linkable = tuple(atom for atom in output_atoms if atom.exposure_kind in _LINKABLE_OUTPUT_KINDS)
    revealing = tuple(atom for atom in output_atoms if atom.exposure_kind in _REVEALING_OUTPUT_KINDS)

    by_release_linkable = _by_release(linkable)
    by_release_revealing = _by_release(revealing)
    by_release_all = _by_release(direct)

    predicates = (
        _same_release_linkage(
            state,
            predicate_id=ForbiddenPredicateId.F1_DIRECT_SENSITIVE_LINKAGE,
            identifier_category=SensitivityCategory.DIRECT_IDENTIFIER,
            reason=ForbiddenReasonCode.DIRECT_AND_SENSITIVE_LINKABLE_SAME_RELEASE,
            by_release=by_release_linkable,
        ),
        _same_release_linkage(
            state,
            predicate_id=ForbiddenPredicateId.F2_STABLE_LINKABLE_SENSITIVE,
            identifier_category=SensitivityCategory.STABLE_PSEUDONYM,
            reason=ForbiddenReasonCode.STABLE_AND_SENSITIVE_LINKABLE_SAME_RELEASE,
            by_release=by_release_linkable,
        ),
        _small_cohort_sensitive(state, policy, by_release_revealing, by_release_all),
        _cross_release_composition(state, linkable),
        _temporal_differencing(state, temporal_path),
        _untrusted_governance(state, governance_binding),
    )
    matched = tuple(
        item.predicate_id for item in predicates if item.status == ForbiddenPredicateStatus.MATCHED
    )
    indeterminate = tuple(
        item.predicate_id
        for item in predicates
        if item.status == ForbiddenPredicateStatus.INDETERMINATE
    )
    provisional = ForbiddenStateEvaluation.model_construct(
        state_sha256=state.state_sha256,
        policy_sha256=policy.policy_sha256,
        governance_binding_sha256=(
            governance_binding.binding_sha256 if governance_binding is not None else None
        ),
        temporal_path_sha256=(temporal_path.path_sha256 if temporal_path is not None else None),
        predicates=predicates,
        matched_predicates=matched,
        indeterminate_predicates=indeterminate,
        forbidden=bool(matched),
        evaluation_sha256="0" * 64,
    )
    return ForbiddenStateEvaluation(
        state_sha256=state.state_sha256,
        policy_sha256=policy.policy_sha256,
        governance_binding_sha256=(
            governance_binding.binding_sha256 if governance_binding is not None else None
        ),
        temporal_path_sha256=(temporal_path.path_sha256 if temporal_path is not None else None),
        predicates=predicates,
        matched_predicates=matched,
        indeterminate_predicates=indeterminate,
        forbidden=bool(matched),
        evaluation_sha256=compute_forbidden_state_evaluation_sha256(provisional),
    )


def compute_forbidden_policy_sha256(policy: ForbiddenPredicatePolicy) -> str:
    return canonical_json_sha256(policy.model_dump(mode="json", exclude={"policy_sha256"}))


def compute_governance_trust_binding_sha256(binding: GovernanceTrustBinding) -> str:
    return canonical_json_sha256(binding.model_dump(mode="json", exclude={"binding_sha256"}))


def compute_temporal_observation_sha256(observation: TemporalReleaseObservation) -> str:
    return canonical_json_sha256(
        observation.model_dump(mode="json", exclude={"observation_sha256"})
    )


def compute_temporal_path_sha256(path: TemporalPathContext) -> str:
    return canonical_json_sha256(path.model_dump(mode="json", exclude={"path_sha256"}))


def compute_forbidden_predicate_evaluation_sha256(
    evaluation: ForbiddenPredicateEvaluation,
) -> str:
    return canonical_json_sha256(
        evaluation.model_dump(mode="json", exclude={"evaluation_sha256"})
    )


def compute_forbidden_state_evaluation_sha256(evaluation: ForbiddenStateEvaluation) -> str:
    return canonical_json_sha256(
        evaluation.model_dump(mode="json", exclude={"evaluation_sha256"})
    )


def _same_release_linkage(
    state: DisclosureState,
    *,
    predicate_id: ForbiddenPredicateId,
    identifier_category: SensitivityCategory,
    reason: ForbiddenReasonCode,
    by_release: dict[str, tuple[DisclosureAtom, ...]],
) -> ForbiddenPredicateEvaluation:
    candidates: list[tuple[tuple[str, ...], str]] = []
    for release_sha, atoms in by_release.items():
        identifiers = tuple(atom for atom in atoms if atom.category == identifier_category)
        sensitive = tuple(
            atom for atom in atoms if atom.category == SensitivityCategory.SENSITIVE_ATTRIBUTE
        )
        for identifier in identifiers:
            for sensitive_atom in sensitive:
                candidates.append(
                    (tuple(sorted((identifier.atom_sha256, sensitive_atom.atom_sha256))), release_sha)
                )
    if not candidates:
        return _evaluation(state, predicate_id, ForbiddenPredicateStatus.CLEAR, ForbiddenReasonCode.CLEAR)
    witness_atoms, release_sha = min(candidates)
    return _evaluation(
        state,
        predicate_id,
        ForbiddenPredicateStatus.MATCHED,
        reason,
        witness_atoms=witness_atoms,
        witness_releases=(release_sha,),
    )


def _small_cohort_sensitive(
    state: DisclosureState,
    policy: ForbiddenPredicatePolicy,
    revealing_by_release: dict[str, tuple[DisclosureAtom, ...]],
    all_by_release: dict[str, tuple[DisclosureAtom, ...]],
) -> ForbiddenPredicateEvaluation:
    candidates: list[tuple[str, tuple[str, ...], ForbiddenReasonCode]] = []
    for release_sha, revealing in revealing_by_release.items():
        if not any(atom.category == SensitivityCategory.SENSITIVE_ATTRIBUTE for atom in revealing):
            continue
        all_atoms = all_by_release.get(release_sha, ())
        group_atoms = tuple(
            atom
            for atom in all_atoms
            if atom.kind == DisclosureAtomKind.COLUMN_EXPOSURE
            and (
                atom.column_role == ColumnExposureRole.GROUP_KEY
                or atom.exposure_kind == ProjectionExposureKind.GROUP_KEY
            )
        )
        if not group_atoms:
            continue
        minimum_atoms = tuple(
            atom for atom in all_atoms if atom.kind == DisclosureAtomKind.MINIMUM_GROUP_SIZE
        )
        sensitive_atoms = tuple(
            atom
            for atom in revealing
            if atom.category == SensitivityCategory.SENSITIVE_ATTRIBUTE
        )
        base_witness = tuple(
            sorted(
                {
                    *(atom.atom_sha256 for atom in group_atoms),
                    *(atom.atom_sha256 for atom in sensitive_atoms),
                }
            )
        )
        if not minimum_atoms:
            candidates.append(
                (
                    release_sha,
                    base_witness,
                    ForbiddenReasonCode.SENSITIVE_GROUP_MINIMUM_MISSING,
                )
            )
            continue
        minimum = min(
            minimum_atoms,
            key=lambda atom: (atom.minimum_group_size or 0, atom.atom_sha256),
        )
        assert minimum.minimum_group_size is not None
        if minimum.minimum_group_size < policy.minimum_group_size:
            candidates.append(
                (
                    release_sha,
                    tuple(sorted((*base_witness, minimum.atom_sha256))),
                    ForbiddenReasonCode.SENSITIVE_GROUP_BELOW_MINIMUM,
                )
            )
    if not candidates:
        return _evaluation(
            state,
            ForbiddenPredicateId.F3_SMALL_COHORT_SENSITIVE,
            ForbiddenPredicateStatus.CLEAR,
            ForbiddenReasonCode.CLEAR,
        )
    release_sha, witness, reason = min(candidates)
    return _evaluation(
        state,
        ForbiddenPredicateId.F3_SMALL_COHORT_SENSITIVE,
        ForbiddenPredicateStatus.MATCHED,
        reason,
        witness_atoms=witness,
        witness_releases=(release_sha,),
    )


def _cross_release_composition(
    state: DisclosureState,
    linkable: tuple[DisclosureAtom, ...],
) -> ForbiddenPredicateEvaluation:
    identifiers = tuple(atom for atom in linkable if atom.category in _IDENTIFIER_CATEGORIES)
    sensitive = tuple(
        atom for atom in linkable if atom.category == SensitivityCategory.SENSITIVE_ATTRIBUTE
    )
    candidates: list[tuple[tuple[str, ...], tuple[str, ...]]] = []
    for identifier in identifiers:
        for sensitive_atom in sensitive:
            if identifier.release_semantic_sha256 == sensitive_atom.release_semantic_sha256:
                continue
            assert identifier.release_semantic_sha256 is not None
            assert sensitive_atom.release_semantic_sha256 is not None
            candidates.append(
                (
                    tuple(sorted((identifier.atom_sha256, sensitive_atom.atom_sha256))),
                    tuple(
                        sorted(
                            (
                                identifier.release_semantic_sha256,
                                sensitive_atom.release_semantic_sha256,
                            )
                        )
                    ),
                )
            )
    if not candidates:
        return _evaluation(
            state,
            ForbiddenPredicateId.F4_CROSS_RELEASE_COMPOSITION,
            ForbiddenPredicateStatus.CLEAR,
            ForbiddenReasonCode.CLEAR,
        )
    witness_atoms, releases = min(candidates)
    return _evaluation(
        state,
        ForbiddenPredicateId.F4_CROSS_RELEASE_COMPOSITION,
        ForbiddenPredicateStatus.MATCHED,
        ForbiddenReasonCode.IDENTIFIER_AND_SENSITIVE_ACROSS_RELEASES,
        witness_atoms=witness_atoms,
        witness_releases=releases,
    )


def _temporal_differencing(
    state: DisclosureState,
    path: TemporalPathContext | None,
) -> ForbiddenPredicateEvaluation:
    if path is None:
        return _evaluation(
            state,
            ForbiddenPredicateId.F5_TEMPORAL_DIFFERENCING,
            ForbiddenPredicateStatus.INDETERMINATE,
            ForbiddenReasonCode.TEMPORAL_PATH_CONTEXT_MISSING,
        )
    snapshots: dict[str, set[str]] = defaultdict(set)
    witnesses: dict[str, list[TemporalReleaseObservation]] = defaultdict(list)
    for item in path.observations:
        if not item.sensitive_release or item.warehouse_snapshot_sha256 is None:
            continue
        snapshots[item.release_semantic_sha256].add(item.warehouse_snapshot_sha256)
        witnesses[item.release_semantic_sha256].append(item)
    candidates: list[tuple[str, tuple[str, ...]]] = []
    for release_sha, values in snapshots.items():
        if len(values) < 2:
            continue
        observations = sorted(
            witnesses[release_sha],
            key=lambda item: (item.step_index, item.observation_sha256),
        )
        first = observations[0]
        second = next(
            item
            for item in observations[1:]
            if item.warehouse_snapshot_sha256 != first.warehouse_snapshot_sha256
        )
        candidates.append(
            (
                release_sha,
                tuple(sorted((first.observation_sha256, second.observation_sha256))),
            )
        )
    if not candidates:
        return _evaluation(
            state,
            ForbiddenPredicateId.F5_TEMPORAL_DIFFERENCING,
            ForbiddenPredicateStatus.CLEAR,
            ForbiddenReasonCode.CLEAR,
        )
    release_sha, observation_hashes = min(candidates)
    return _evaluation(
        state,
        ForbiddenPredicateId.F5_TEMPORAL_DIFFERENCING,
        ForbiddenPredicateStatus.MATCHED,
        ForbiddenReasonCode.SENSITIVE_REPLAY_ACROSS_SNAPSHOTS,
        witness_atoms=observation_hashes,
        witness_releases=(release_sha,),
    )


def _untrusted_governance(
    state: DisclosureState,
    binding: GovernanceTrustBinding | None,
) -> ForbiddenPredicateEvaluation:
    predicate_id = ForbiddenPredicateId.F6_UNTRUSTED_GOVERNANCE_AUTHORIZATION
    if binding is None:
        return _evaluation(
            state,
            predicate_id,
            ForbiddenPredicateStatus.MATCHED,
            ForbiddenReasonCode.GOVERNANCE_BINDING_MISSING,
        )
    if binding.governance_commitment_sha256 != state.governance_commitment_sha256:
        return _evaluation(
            state,
            predicate_id,
            ForbiddenPredicateStatus.MATCHED,
            ForbiddenReasonCode.GOVERNANCE_COMMITMENT_MISMATCH,
        )
    if not binding.trusted:
        return _evaluation(
            state,
            predicate_id,
            ForbiddenPredicateStatus.MATCHED,
            ForbiddenReasonCode.GOVERNANCE_NOT_TRUSTED,
        )
    return _evaluation(
        state,
        predicate_id,
        ForbiddenPredicateStatus.CLEAR,
        ForbiddenReasonCode.CLEAR,
    )


def _evaluation(
    state: DisclosureState,
    predicate_id: ForbiddenPredicateId,
    status: ForbiddenPredicateStatus,
    reason: ForbiddenReasonCode,
    *,
    witness_atoms: tuple[str, ...] = (),
    witness_releases: tuple[str, ...] = (),
) -> ForbiddenPredicateEvaluation:
    atoms = tuple(sorted(set(witness_atoms)))
    releases = tuple(sorted(set(witness_releases)))
    provisional = ForbiddenPredicateEvaluation.model_construct(
        predicate_id=predicate_id,
        status=status,
        reason_code=reason,
        state_sha256=state.state_sha256,
        witness_atom_sha256s=atoms,
        witness_release_sha256s=releases,
        evaluation_sha256="0" * 64,
    )
    return ForbiddenPredicateEvaluation(
        predicate_id=predicate_id,
        status=status,
        reason_code=reason,
        state_sha256=state.state_sha256,
        witness_atom_sha256s=atoms,
        witness_release_sha256s=releases,
        evaluation_sha256=compute_forbidden_predicate_evaluation_sha256(provisional),
    )


def _by_release(atoms: tuple[DisclosureAtom, ...]) -> dict[str, tuple[DisclosureAtom, ...]]:
    grouped: dict[str, list[DisclosureAtom]] = defaultdict(list)
    for atom in atoms:
        if atom.release_semantic_sha256 is not None:
            grouped[atom.release_semantic_sha256].append(atom)
    return {
        release: tuple(sorted(values, key=lambda atom: atom.atom_sha256))
        for release, values in grouped.items()
    }
