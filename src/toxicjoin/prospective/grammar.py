"""Finite security-owned Future Action Grammar and deterministic Twin transitions.

P0 never synthesizes arbitrary SQL or literals during prospective search. The grammar is
instantiated once from a canonical, governed context and contains complete future semantic
release variants. A transition accepts only an exact action committed by that grammar.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, ValidationError, model_validator

from toxicjoin.disclosure.composition import is_protected_release
from toxicjoin.disclosure.models import (
    DisclosureComposition,
    DisclosureSemanticRelease,
    GovernedColumn,
    SemanticOutput,
    compute_semantic_sha256,
)
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.models import ProjectionExposureKind, SensitivityCategory, StrictModel
from toxicjoin.prospective.twin import (
    DisclosureState,
    DisclosureTwinError,
    compute_disclosure_state_sha256,
    compute_inference_rules_sha256,
    direct_atoms_for_release,
    instantiate_disclosure_inference_rules,
    least_fixed_point,
)

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_GRAMMAR_VERSION = "0.1.0"
_MAX_ACTIONS_PER_STATE = 32
_MAX_RELEVANT_FIELDS = 16
_MAX_GROUP_FIELDS = 12
_MAX_AGGREGATES = 8
_MAX_COHORT_VARIANTS = 8
_MAX_SNAPSHOT_TRANSITIONS = 8
Sha256 = Annotated[str, Field(pattern=_HASH_PATTERN)]

_SUPPORTED_AGGREGATES = {"AVG", "COUNT", "MAX", "MIN", "SUM"}


class FutureActionGrammarError(RuntimeError):
    """Raised when the finite grammar cannot be instantiated safely."""


class FutureActionTransitionError(RuntimeError):
    """Raised when an action cannot be deterministically applied to a Twin state."""


class FutureActionKind(StrEnum):
    REPLAY = "REPLAY"
    ADD_PROJECTION = "ADD_PROJECTION"
    REMOVE_PROJECTION = "REMOVE_PROJECTION"
    ADD_GROUP_KEY = "ADD_GROUP_KEY"
    DROP_GROUP_KEY = "DROP_GROUP_KEY"
    CHANGE_AGGREGATE = "CHANGE_AGGREGATE"
    COHORT_VARIANT = "COHORT_VARIANT"
    SNAPSHOT_ADVANCE = "SNAPSHOT_ADVANCE"


class FutureActionGrammarContext(StrictModel):
    """Canonical security-owned finite inputs used to instantiate future actions."""

    schema_version: Literal["1.0"] = "1.0"
    grammar_version: Literal["0.1.0"] = _GRAMMAR_VERSION
    base_semantic: DisclosureSemanticRelease
    base_composition: DisclosureComposition
    relevant_projection_fields: tuple[GovernedColumn, ...] = Field(
        default=(), max_length=_MAX_RELEVANT_FIELDS
    )
    group_key_fields: tuple[GovernedColumn, ...] = Field(
        default=(), max_length=_MAX_GROUP_FIELDS
    )
    aggregate_allowlist: tuple[str, ...] = Field(default=(), max_length=_MAX_AGGREGATES)
    cohort_variant_hmacs: tuple[Sha256, ...] = Field(
        default=(), max_length=_MAX_COHORT_VARIANTS
    )
    snapshot_transitions: tuple[Sha256, ...] = Field(
        default=(), max_length=_MAX_SNAPSHOT_TRANSITIONS
    )
    context_sha256: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_context(self) -> "FutureActionGrammarContext":
        if self.base_composition.release_family_sha256 != self.base_semantic.semantic_sha256:
            raise ValueError("base composition must bind the base semantic release")
        if self.base_composition.protected_release != is_protected_release(self.base_semantic):
            raise ValueError("base composition protected classification mismatch")

        _require_canonical_columns(self.relevant_projection_fields, "relevant_projection_fields")
        _require_canonical_columns(self.group_key_fields, "group_key_fields")
        if any(
            column.category == SensitivityCategory.UNCLASSIFIED
            for column in self.relevant_projection_fields
        ):
            raise ValueError("future projection fields must be governed and classified")
        if any(
            column.category != SensitivityCategory.QUASI_IDENTIFIER
            for column in self.group_key_fields
        ):
            raise ValueError("future group-key fields must be governed quasi-identifiers")
        relevant_keys = {column.key for column in self.relevant_projection_fields}
        if not {column.key for column in self.group_key_fields}.issubset(relevant_keys):
            raise ValueError("future group-key fields must belong to the relevant field set")

        if self.aggregate_allowlist != tuple(sorted(set(self.aggregate_allowlist))):
            raise ValueError("aggregate_allowlist must be sorted and unique")
        if any(value != value.strip().upper() for value in self.aggregate_allowlist):
            raise ValueError("aggregate_allowlist values must be normalized uppercase")
        unsupported = sorted(set(self.aggregate_allowlist) - _SUPPORTED_AGGREGATES)
        if unsupported:
            raise ValueError("unsupported future aggregate: " + ", ".join(unsupported))
        if self.cohort_variant_hmacs != tuple(sorted(set(self.cohort_variant_hmacs))):
            raise ValueError("cohort_variant_hmacs must be sorted and unique")
        if self.snapshot_transitions != tuple(sorted(set(self.snapshot_transitions))):
            raise ValueError("snapshot_transitions must be sorted and unique")

        if self.context_sha256 != compute_future_action_context_sha256(self):
            raise ValueError("future action grammar context hash mismatch")
        return self


class FutureAction(StrictModel):
    """One complete, canonical future release or snapshot transition."""

    schema_version: Literal["1.0"] = "1.0"
    grammar_version: Literal["0.1.0"] = _GRAMMAR_VERSION
    kind: FutureActionKind
    semantic: DisclosureSemanticRelease | None = None
    composition: DisclosureComposition | None = None
    snapshot_sha256: str | None = Field(default=None, pattern=_HASH_PATTERN)
    action_sha256: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_action(self) -> "FutureAction":
        if self.kind == FutureActionKind.SNAPSHOT_ADVANCE:
            if self.snapshot_sha256 is None or self.semantic is not None or self.composition is not None:
                raise ValueError("snapshot action must contain only a snapshot commitment")
        else:
            if self.snapshot_sha256 is not None or self.semantic is None or self.composition is None:
                raise ValueError("release action requires semantic and composition metadata")
            if self.composition.release_family_sha256 != self.semantic.semantic_sha256:
                raise ValueError("future action composition must bind its semantic release")
            if self.composition.protected_release != is_protected_release(self.semantic):
                raise ValueError("future action protected classification mismatch")
        if self.action_sha256 != compute_future_action_sha256(self):
            raise ValueError("future action hash mismatch")
        return self


class FutureActionGrammar(StrictModel):
    """Finite canonical action set committed to one security-owned context."""

    schema_version: Literal["1.0"] = "1.0"
    grammar_version: Literal["0.1.0"] = _GRAMMAR_VERSION
    context_sha256: str = Field(pattern=_HASH_PATTERN)
    actions: tuple[FutureAction, ...] = Field(min_length=1, max_length=_MAX_ACTIONS_PER_STATE)
    grammar_sha256: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_grammar(self) -> "FutureActionGrammar":
        hashes = tuple(action.action_sha256 for action in self.actions)
        if hashes != tuple(sorted(set(hashes))):
            raise ValueError("future actions must be sorted and unique")
        if any(action.grammar_version != self.grammar_version for action in self.actions):
            raise ValueError("future action grammar version mismatch")
        if self.grammar_sha256 != compute_future_action_grammar_sha256(self):
            raise ValueError("future action grammar hash mismatch")
        return self


def build_future_action_grammar_context(
    *,
    base_semantic: DisclosureSemanticRelease,
    base_composition: DisclosureComposition,
    relevant_projection_fields: tuple[GovernedColumn, ...] = (),
    group_key_fields: tuple[GovernedColumn, ...] = (),
    aggregate_allowlist: tuple[str, ...] = (),
    cohort_variant_hmacs: tuple[str, ...] = (),
    snapshot_transitions: tuple[str, ...] = (),
) -> FutureActionGrammarContext:
    """Build one canonical context; callers cannot rely on insertion order."""

    relevant = tuple(sorted(relevant_projection_fields, key=lambda column: column.key))
    groups = tuple(sorted(group_key_fields, key=lambda column: column.key))
    aggregates = tuple(sorted(set(value.strip().upper() for value in aggregate_allowlist)))
    cohorts = tuple(sorted(set(cohort_variant_hmacs)))
    snapshots = tuple(sorted(set(snapshot_transitions)))
    provisional = FutureActionGrammarContext.model_construct(
        base_semantic=base_semantic,
        base_composition=base_composition,
        relevant_projection_fields=relevant,
        group_key_fields=groups,
        aggregate_allowlist=aggregates,
        cohort_variant_hmacs=cohorts,
        snapshot_transitions=snapshots,
        context_sha256="0" * 64,
    )
    return FutureActionGrammarContext(
        base_semantic=base_semantic,
        base_composition=base_composition,
        relevant_projection_fields=relevant,
        group_key_fields=groups,
        aggregate_allowlist=aggregates,
        cohort_variant_hmacs=cohorts,
        snapshot_transitions=snapshots,
        context_sha256=compute_future_action_context_sha256(provisional),
    )


def instantiate_future_action_grammar(
    context: FutureActionGrammarContext,
) -> FutureActionGrammar:
    """Instantiate all declared P0 actions; budget exhaustion fails closed."""

    actions: dict[str, FutureAction] = {}

    def add(action: FutureAction) -> None:
        actions[action.action_sha256] = action
        if len(actions) > _MAX_ACTIONS_PER_STATE:
            raise FutureActionGrammarError("future action budget exceeded")

    add(_build_release_action(FutureActionKind.REPLAY, context.base_semantic, context.base_composition))

    single_source_outputs = {
        output.sources[0].key: output
        for output in context.base_semantic.outputs
        if len(output.sources) == 1
    }
    base_group_keys = {column.key for column in context.base_semantic.group_keys}

    for column in context.relevant_projection_fields:
        if column.key not in single_source_outputs:
            semantic = _with_added_projection(context.base_semantic, column)
            add(_release_variant_action(FutureActionKind.ADD_PROJECTION, semantic, context))

    for column_key in sorted(single_source_outputs):
        semantic = _with_removed_projection(context.base_semantic, column_key)
        if semantic is not None:
            add(_release_variant_action(FutureActionKind.REMOVE_PROJECTION, semantic, context))

    for column in context.group_key_fields:
        if column.key not in base_group_keys:
            semantic = _with_added_group_key(context.base_semantic, column)
            add(_release_variant_action(FutureActionKind.ADD_GROUP_KEY, semantic, context))

    for column in context.base_semantic.group_keys:
        semantic = _with_dropped_group_key(context.base_semantic, column.key)
        add(_release_variant_action(FutureActionKind.DROP_GROUP_KEY, semantic, context))

    current_aggregates = tuple(sorted(set(context.base_semantic.aggregate_functions)))
    for current in current_aggregates:
        for replacement in context.aggregate_allowlist:
            if replacement == current:
                continue
            semantic = _with_changed_aggregate(context.base_semantic, current, replacement)
            add(_release_variant_action(FutureActionKind.CHANGE_AGGREGATE, semantic, context))

    for cohort_sha256 in context.cohort_variant_hmacs:
        if cohort_sha256 == context.base_composition.cohort_hmac_sha256:
            continue
        variant = DisclosureComposition(
            protected_release=context.base_composition.protected_release,
            release_family_sha256=context.base_semantic.semantic_sha256,
            cohort_hmac_sha256=cohort_sha256,
        )
        add(_build_release_action(FutureActionKind.COHORT_VARIANT, context.base_semantic, variant))

    for snapshot_sha256 in context.snapshot_transitions:
        add(_build_snapshot_action(snapshot_sha256))

    ordered = tuple(actions[key] for key in sorted(actions))
    provisional = FutureActionGrammar.model_construct(
        context_sha256=context.context_sha256,
        actions=ordered,
        grammar_sha256="0" * 64,
    )
    return FutureActionGrammar(
        context_sha256=context.context_sha256,
        actions=ordered,
        grammar_sha256=compute_future_action_grammar_sha256(provisional),
    )


def apply_future_action(
    state: DisclosureState,
    action: FutureAction,
    grammar: FutureActionGrammar,
) -> DisclosureState:
    """Apply only an exact grammar member to one immutable DisclosureState."""

    canonical = next(
        (candidate for candidate in grammar.actions if candidate.action_sha256 == action.action_sha256),
        None,
    )
    if canonical is None or canonical != action:
        raise FutureActionTransitionError("future action is not authorized by the grammar")

    if action.kind == FutureActionKind.SNAPSHOT_ADVANCE:
        assert action.snapshot_sha256 is not None
        return _rebuild_state(
            state,
            released_atoms=state.released_atoms,
            warehouse_snapshot_sha256=action.snapshot_sha256,
        )

    assert action.semantic is not None
    assert action.composition is not None
    try:
        future_atoms = direct_atoms_for_release(action.semantic, action.composition)
    except DisclosureTwinError as exc:
        raise FutureActionTransitionError("future release cannot be projected safely") from exc
    merged = {atom.atom_sha256: atom for atom in state.released_atoms}
    for atom in future_atoms:
        merged[atom.atom_sha256] = atom
    released_atoms = tuple(merged[key] for key in sorted(merged))
    return _rebuild_state(
        state,
        released_atoms=released_atoms,
        warehouse_snapshot_sha256=state.warehouse_snapshot_sha256,
    )


def compute_future_action_context_sha256(context: FutureActionGrammarContext) -> str:
    return canonical_json_sha256(context.model_dump(mode="json", exclude={"context_sha256"}))


def compute_future_action_sha256(action: FutureAction) -> str:
    return canonical_json_sha256(action.model_dump(mode="json", exclude={"action_sha256"}))


def compute_future_action_grammar_sha256(grammar: FutureActionGrammar) -> str:
    return canonical_json_sha256(grammar.model_dump(mode="json", exclude={"grammar_sha256"}))


def _release_variant_action(
    kind: FutureActionKind,
    semantic: DisclosureSemanticRelease,
    context: FutureActionGrammarContext,
) -> FutureAction:
    composition = DisclosureComposition(
        protected_release=is_protected_release(semantic),
        release_family_sha256=semantic.semantic_sha256,
        cohort_hmac_sha256=context.base_composition.cohort_hmac_sha256,
    )
    return _build_release_action(kind, semantic, composition)


def _build_release_action(
    kind: FutureActionKind,
    semantic: DisclosureSemanticRelease,
    composition: DisclosureComposition,
) -> FutureAction:
    provisional = FutureAction.model_construct(
        kind=kind,
        semantic=semantic,
        composition=composition,
        snapshot_sha256=None,
        action_sha256="0" * 64,
    )
    return FutureAction(
        kind=kind,
        semantic=semantic,
        composition=composition,
        action_sha256=compute_future_action_sha256(provisional),
    )


def _build_snapshot_action(snapshot_sha256: str) -> FutureAction:
    provisional = FutureAction.model_construct(
        kind=FutureActionKind.SNAPSHOT_ADVANCE,
        semantic=None,
        composition=None,
        snapshot_sha256=snapshot_sha256,
        action_sha256="0" * 64,
    )
    return FutureAction(
        kind=FutureActionKind.SNAPSHOT_ADVANCE,
        snapshot_sha256=snapshot_sha256,
        action_sha256=compute_future_action_sha256(provisional),
    )


def _with_added_projection(
    base: DisclosureSemanticRelease,
    column: GovernedColumn,
) -> DisclosureSemanticRelease:
    outputs = tuple(
        sorted(
            (*base.outputs, SemanticOutput(kind=ProjectionExposureKind.RAW_VALUE, sources=(column,))),
            key=_output_key,
        )
    )
    referenced = _merge_columns(base.referenced_columns, (column,))
    datasets = tuple(sorted(set((*base.source_dataset_urns, column.dataset_urn))))
    return _rebuild_semantic(base, outputs=outputs, referenced=referenced, datasets=datasets)


def _with_removed_projection(
    base: DisclosureSemanticRelease,
    column_key: str,
) -> DisclosureSemanticRelease | None:
    outputs = tuple(
        output
        for output in base.outputs
        if not (len(output.sources) == 1 and output.sources[0].key == column_key)
    )
    if not outputs:
        return None
    still_needed = {
        source.key for output in outputs for source in output.sources
    } | {column.key for column in base.join_columns} | {column.key for column in base.group_keys}
    referenced = tuple(column for column in base.referenced_columns if column.key in still_needed)
    return _rebuild_semantic(base, outputs=outputs, referenced=referenced)


def _with_added_group_key(
    base: DisclosureSemanticRelease,
    column: GovernedColumn,
) -> DisclosureSemanticRelease:
    group_keys = _merge_columns(base.group_keys, (column,))
    referenced = _merge_columns(base.referenced_columns, (column,))
    datasets = tuple(sorted(set((*base.source_dataset_urns, column.dataset_urn))))
    outputs = list(base.outputs)
    replaced = False
    for index, output in enumerate(outputs):
        if len(output.sources) == 1 and output.sources[0].key == column.key:
            outputs[index] = SemanticOutput(kind=ProjectionExposureKind.GROUP_KEY, sources=(column,))
            replaced = True
    if not replaced:
        outputs.append(SemanticOutput(kind=ProjectionExposureKind.GROUP_KEY, sources=(column,)))
    return _rebuild_semantic(
        base,
        outputs=tuple(sorted(outputs, key=_output_key)),
        referenced=referenced,
        group_keys=group_keys,
        datasets=datasets,
    )


def _with_dropped_group_key(
    base: DisclosureSemanticRelease,
    column_key: str,
) -> DisclosureSemanticRelease:
    group_keys = tuple(column for column in base.group_keys if column.key != column_key)
    outputs = tuple(
        output
        for output in base.outputs
        if not (
            output.kind == ProjectionExposureKind.GROUP_KEY
            and len(output.sources) == 1
            and output.sources[0].key == column_key
        )
    )
    still_needed = {
        source.key for output in outputs for source in output.sources
    } | {column.key for column in base.join_columns} | {column.key for column in group_keys}
    referenced = tuple(column for column in base.referenced_columns if column.key in still_needed)
    return _rebuild_semantic(base, outputs=outputs, referenced=referenced, group_keys=group_keys)


def _with_changed_aggregate(
    base: DisclosureSemanticRelease,
    current: str,
    replacement: str,
) -> DisclosureSemanticRelease:
    aggregates = tuple(
        sorted(replacement if value == current else value for value in base.aggregate_functions)
    )
    return _rebuild_semantic(base, aggregates=aggregates)


def _rebuild_semantic(
    base: DisclosureSemanticRelease,
    *,
    outputs: tuple[SemanticOutput, ...] | None = None,
    referenced: tuple[GovernedColumn, ...] | None = None,
    group_keys: tuple[GovernedColumn, ...] | None = None,
    aggregates: tuple[str, ...] | None = None,
    datasets: tuple[str, ...] | None = None,
) -> DisclosureSemanticRelease:
    kwargs = {
        "source_dataset_urns": datasets if datasets is not None else base.source_dataset_urns,
        "outputs": tuple(sorted(outputs if outputs is not None else base.outputs, key=_output_key)),
        "referenced_columns": tuple(
            sorted(referenced if referenced is not None else base.referenced_columns, key=lambda c: c.key)
        ),
        "join_columns": base.join_columns,
        "group_keys": tuple(
            sorted(group_keys if group_keys is not None else base.group_keys, key=lambda c: c.key)
        ),
        "aggregate_functions": tuple(
            sorted(set(aggregates if aggregates is not None else base.aggregate_functions))
        ),
        "minimum_group_size_present": base.minimum_group_size_present,
    }
    provisional = DisclosureSemanticRelease.model_construct(**kwargs, semantic_sha256="0" * 64)
    return DisclosureSemanticRelease(**kwargs, semantic_sha256=compute_semantic_sha256(provisional))


def _rebuild_state(
    state: DisclosureState,
    *,
    released_atoms,
    warehouse_snapshot_sha256: str | None,
) -> DisclosureState:
    try:
        rules = instantiate_disclosure_inference_rules(released_atoms)
        derived = least_fixed_point(released_atoms, rules)
        rules_root = compute_inference_rules_sha256(rules)
        provisional = DisclosureState.model_construct(
            scope=state.scope,
            purpose_commitment_sha256=state.purpose_commitment_sha256,
            governance_commitment_sha256=state.governance_commitment_sha256,
            evidence_root_sha256=state.evidence_root_sha256,
            warehouse_snapshot_sha256=warehouse_snapshot_sha256,
            released_atoms=released_atoms,
            derived_atoms=derived,
            inference_rules_sha256=rules_root,
            state_sha256="0" * 64,
        )
        return DisclosureState(
            scope=state.scope,
            purpose_commitment_sha256=state.purpose_commitment_sha256,
            governance_commitment_sha256=state.governance_commitment_sha256,
            evidence_root_sha256=state.evidence_root_sha256,
            warehouse_snapshot_sha256=warehouse_snapshot_sha256,
            released_atoms=released_atoms,
            derived_atoms=derived,
            inference_rules_sha256=rules_root,
            state_sha256=compute_disclosure_state_sha256(provisional),
        )
    except (DisclosureTwinError, ValidationError, ValueError) as exc:
        raise FutureActionTransitionError("future action transition failed closed") from exc


def _merge_columns(
    left: tuple[GovernedColumn, ...],
    right: tuple[GovernedColumn, ...],
) -> tuple[GovernedColumn, ...]:
    merged = {column.key: column for column in (*left, *right)}
    return tuple(merged[key] for key in sorted(merged))


def _require_canonical_columns(columns: tuple[GovernedColumn, ...], label: str) -> None:
    keys = tuple(column.key for column in columns)
    if keys != tuple(sorted(set(keys))):
        raise ValueError(f"{label} must be sorted and unique by governed column key")


def _output_key(output: SemanticOutput) -> tuple[str, tuple[str, ...]]:
    return output.kind.value, tuple(source.key for source in output.sources)
