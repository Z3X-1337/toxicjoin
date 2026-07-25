"""Trusted adapter from prospective semantic actions to the existing PolicyEngine.

Release actions are locally admissible only when the unchanged PolicyEngine returns ALLOW.
The adapter is bound to one exact Future Action Grammar and one trusted normalized governance
context that preserves ColumnContext lineage. This matters because DisclosureSemanticRelease
intentionally omits lineage_sources and cannot safely reconstruct effective policy categories
on its own. SNAPSHOT_ADVANCE is a declared no-release transition and is handled by an explicit
security-owned rule rather than being misrepresented as a PolicyEngine query.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, ValidationError, model_validator

from toxicjoin.disclosure.models import DisclosureSemanticRelease, GovernedColumn
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.models import (
    ColumnContext,
    ColumnRef,
    Decision,
    LineageSource,
    PolicyDecision,
    PolicyInput,
    ProjectionExposure,
    QueryPlan,
    SensitivityCategory,
    StrictModel,
)
from toxicjoin.policy import PolicyEngine
from toxicjoin.prospective.grammar import FutureAction, FutureActionGrammar, FutureActionKind
from toxicjoin.prospective.ppmc_models import LocalOracleDecision, build_local_oracle_decision
from toxicjoin.prospective.twin import DisclosureState

_ADAPTER_VERSION = "0.1.0"
_HASH_PATTERN = r"^[0-9a-f]{64}$"
GovernanceSha256 = Annotated[str, Field(pattern=_HASH_PATTERN)]


class PolicyOracleError(RuntimeError):
    """Raised when the trusted PolicyEngine adapter itself cannot operate safely."""


class PolicyOracleSemanticError(ValueError):
    """Expected fail-closed rejection for semantics that cannot be reconstructed safely."""


class PolicyOracleGovernanceContext(StrictModel):
    """Canonical alias-insensitive governance retained for prospective PolicyEngine replay."""

    schema_version: Literal["1.0"] = "1.0"
    columns: tuple[ColumnContext, ...] = Field(min_length=1, max_length=512)
    context_sha256: GovernanceSha256

    @model_validator(mode="after")
    def validate_context(self) -> "PolicyOracleGovernanceContext":
        keys = tuple(_governed_key(column) for column in self.columns)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("policy-oracle governance columns must be canonical and unique")
        for column in self.columns:
            if (
                not column.resolved
                or column.datahub_urn is None
                or column.category == SensitivityCategory.UNCLASSIFIED
                or column.ref.alias is not None
            ):
                raise ValueError("policy-oracle governance must be resolved and alias-insensitive")
            if column.tags != tuple(sorted(set(column.tags))):
                raise ValueError("policy-oracle governance tags must be canonical")
            if column.glossary_terms != tuple(sorted(set(column.glossary_terms))):
                raise ValueError("policy-oracle governance glossary terms must be canonical")
            lineage_keys = tuple(_lineage_key(source) for source in column.lineage_sources)
            if lineage_keys != tuple(sorted(set(lineage_keys))):
                raise ValueError("policy-oracle lineage must be canonical and unique")
            if any(
                source.ref.alias is not None
                or source.category == SensitivityCategory.UNCLASSIFIED
                for source in column.lineage_sources
            ):
                raise ValueError("policy-oracle lineage must be classified and alias-insensitive")
        if self.context_sha256 != compute_policy_oracle_governance_sha256(self):
            raise ValueError("policy-oracle governance context hash mismatch")
        return self


def build_policy_oracle_governance_context(
    columns: tuple[ColumnContext, ...],
) -> PolicyOracleGovernanceContext:
    """Normalize trusted resolver output into the alias-insensitive oracle trust anchor."""

    by_key: dict[str, ColumnContext] = {}
    for column in columns:
        normalized = _normalize_context(column)
        key = _governed_key(normalized)
        existing = by_key.get(key)
        if existing is not None and existing != normalized:
            raise PolicyOracleSemanticError(f"conflicting governance for prospective column: {key}")
        by_key[key] = normalized
    ordered = tuple(by_key[key] for key in sorted(by_key))
    provisional = PolicyOracleGovernanceContext.model_construct(
        columns=ordered,
        context_sha256="0" * 64,
    )
    return PolicyOracleGovernanceContext(
        columns=ordered,
        context_sha256=compute_policy_oracle_governance_sha256(provisional),
    )


def compute_policy_oracle_governance_sha256(
    context: PolicyOracleGovernanceContext,
) -> str:
    return canonical_json_sha256(context.model_dump(mode="json", exclude={"context_sha256"}))


def build_policy_input_from_semantic(
    state: DisclosureState,
    semantic: DisclosureSemanticRelease,
    governance: PolicyOracleGovernanceContext,
) -> PolicyInput:
    """Reconstruct PolicyInput using the trusted lineage-preserving governance context."""

    _revalidate_inputs(state, semantic, governance)
    governance_by_key = {_governed_key(column): column for column in governance.columns}
    semantic_columns = _semantic_columns(semantic)
    trusted: dict[str, ColumnContext] = {}
    for semantic_column in semantic_columns:
        context = governance_by_key.get(semantic_column.key)
        if context is None:
            raise PolicyOracleSemanticError(
                f"prospective semantic column lacks trusted governance: {semantic_column.key}"
            )
        if (
            context.datahub_urn != semantic_column.dataset_urn
            or context.ref.field_path != semantic_column.field_path
            or context.category != semantic_column.category
        ):
            raise PolicyOracleSemanticError(
                f"prospective semantic governance mismatch: {semantic_column.key}"
            )
        trusted[semantic_column.key] = context

    source_names = _source_dataset_names(semantic, governance)
    referenced_keys = {column.key for column in semantic.referenced_columns}
    required_keys = {
        *(source.key for output in semantic.outputs for source in output.sources),
        *(column.key for column in semantic.join_columns),
        *(column.key for column in semantic.group_keys),
    }
    if not required_keys.issubset(referenced_keys):
        raise PolicyOracleSemanticError("semantic release is missing governed references")

    projected_keys = {
        source.key for output in semantic.outputs for source in output.sources
    }
    projected_columns = tuple(trusted[key].ref for key in sorted(projected_keys))
    projected_context = tuple(trusted[key] for key in sorted(projected_keys))
    referenced_columns = tuple(trusted[column.key].ref for column in semantic.referenced_columns)
    all_referenced_context = tuple(trusted[column.key] for column in semantic.referenced_columns)
    join_columns = tuple(trusted[column.key].ref for column in semantic.join_columns)
    group_columns = tuple(trusted[column.key].ref for column in semantic.group_keys)
    exposures = tuple(
        ProjectionExposure(
            output_name=f"ppmc_output_{index:03d}",
            kind=output.kind,
            source_columns=tuple(trusted[source.key].ref for source in output.sources),
        )
        for index, output in enumerate(semantic.outputs)
    )

    subject_key = _subject_key(state, semantic, trusted)
    if semantic.minimum_group_size_present is not None and subject_key is None:
        raise PolicyOracleSemanticError(
            "minimum-group-size evidence lacks one unambiguous governed subject"
        )

    plan = QueryPlan(
        statement_type="SELECT",
        source_datasets=source_names,
        projected_columns=projected_columns,
        projected_exposures=exposures,
        referenced_columns=referenced_columns,
        join_columns=join_columns,
        group_by_columns=group_columns,
        aggregate_functions=semantic.aggregate_functions,
        minimum_group_size_present=semantic.minimum_group_size_present,
        minimum_group_size_subject=(
            subject_key if semantic.minimum_group_size_present is not None else None
        ),
        is_grouped=bool(semantic.group_keys or semantic.aggregate_functions),
        contains_wildcard=False,
        analysis_warnings=(),
    )
    return PolicyInput(
        task_purpose=f"ppmc:{state.purpose_commitment_sha256}",
        query_plan=plan,
        projected_context=projected_context,
        all_referenced_context=all_referenced_context,
        subject_key=subject_key,
        minimum_group_size_present=semantic.minimum_group_size_present,
        upstream_failures=(),
    )


def evaluate_semantic_with_policy(
    engine: PolicyEngine,
    state: DisclosureState,
    semantic: DisclosureSemanticRelease,
    governance: PolicyOracleGovernanceContext,
) -> tuple[PolicyInput, PolicyDecision]:
    policy_input = build_policy_input_from_semantic(state, semantic, governance)
    return policy_input, engine.evaluate(policy_input)


class PolicyEngineLocalOracle:
    """PPMC local-admissibility oracle bound to exact grammar, policy, and governance."""

    def __init__(
        self,
        engine: PolicyEngine,
        grammar: FutureActionGrammar,
        governance: PolicyOracleGovernanceContext,
    ) -> None:
        self._engine = engine
        self._grammar = FutureActionGrammar.model_validate(grammar.model_dump(mode="json"))
        self._governance = PolicyOracleGovernanceContext.model_validate(
            governance.model_dump(mode="json")
        )
        self._actions = {action.action_sha256: action for action in self._grammar.actions}
        self._policy_config_sha256 = _policy_config_sha256(engine)
        self.oracle_version = (
            f"policy-engine-oracle/{_ADAPTER_VERSION}:"
            f"{self._policy_config_sha256[:12]}:{self._governance.context_sha256[:12]}"
        )

    @property
    def policy_config_sha256(self) -> str:
        return self._policy_config_sha256

    @property
    def governance_context_sha256(self) -> str:
        return self._governance.context_sha256

    @property
    def grammar_sha256(self) -> str:
        return self._grammar.grammar_sha256

    def __call__(self, state: DisclosureState, action: FutureAction) -> LocalOracleDecision:
        self._require_bound_policy()
        expected = self._actions.get(action.action_sha256)
        if expected is None or expected != action:
            return self._reject(state, action, "ACTION_OUTSIDE_BOUND_GRAMMAR")
        if not _state_matches_grammar_context(state, self._grammar):
            return self._reject(state, action, "STATE_OUTSIDE_BOUND_GRAMMAR")

        if action.kind == FutureActionKind.SNAPSHOT_ADVANCE:
            if state.warehouse_snapshot_sha256 != action.snapshot_from_sha256:
                return self._reject(state, action, "SNAPSHOT_SOURCE_MISMATCH")
            return build_local_oracle_decision(
                oracle_version=self.oracle_version,
                state_sha256=state.state_sha256,
                action_sha256=action.action_sha256,
                admissible=True,
                reason_codes=("DECLARED_NO_RELEASE_SNAPSHOT_TRANSITION",),
            )

        if action.semantic is None:
            raise PolicyOracleError("release action unexpectedly lacks semantic metadata")
        try:
            _, decision = evaluate_semantic_with_policy(
                self._engine,
                state,
                action.semantic,
                self._governance,
            )
        except PolicyOracleSemanticError as exc:
            return self._reject(
                state,
                action,
                "SEMANTIC_RECONSTRUCTION_FAIL_CLOSED",
                detail=type(exc).__name__,
            )

        reasons = {
            f"POLICY_DECISION={decision.decision.value}",
            *(f"POLICY_REASON={reason.value}" for reason in decision.reason_codes),
        }
        return build_local_oracle_decision(
            oracle_version=self.oracle_version,
            state_sha256=state.state_sha256,
            action_sha256=action.action_sha256,
            admissible=decision.decision == Decision.ALLOW,
            reason_codes=tuple(sorted(reasons)),
        )

    def evaluate_release_action(
        self,
        state: DisclosureState,
        action: FutureAction,
    ) -> tuple[PolicyInput, PolicyDecision, LocalOracleDecision]:
        self._require_bound_policy()
        expected = self._actions.get(action.action_sha256)
        if expected is None or expected != action or action.semantic is None:
            raise PolicyOracleSemanticError("action is not a bound semantic release action")
        policy_input, decision = evaluate_semantic_with_policy(
            self._engine,
            state,
            action.semantic,
            self._governance,
        )
        local = self(state, action)
        return policy_input, decision, local

    def _require_bound_policy(self) -> None:
        if _policy_config_sha256(self._engine) != self._policy_config_sha256:
            raise PolicyOracleError("PolicyEngine configuration changed after oracle binding")

    def _reject(
        self,
        state: DisclosureState,
        action: FutureAction,
        reason: str,
        *,
        detail: str | None = None,
    ) -> LocalOracleDecision:
        reasons = (reason,) if detail is None else tuple(sorted((reason, detail)))
        return build_local_oracle_decision(
            oracle_version=self.oracle_version,
            state_sha256=state.state_sha256,
            action_sha256=action.action_sha256,
            admissible=False,
            reason_codes=reasons,
        )


def policy_input_sha256(policy_input: PolicyInput) -> str:
    return canonical_json_sha256(policy_input.model_dump(mode="json"))


def policy_decision_sha256(decision: PolicyDecision) -> str:
    return canonical_json_sha256(decision.model_dump(mode="json"))


def _policy_config_sha256(engine: PolicyEngine) -> str:
    return canonical_json_sha256(engine.config.model_dump(mode="json"))


def _governed_key(column: ColumnContext) -> str:
    if column.datahub_urn is None:
        raise PolicyOracleSemanticError("governance column is missing dataset URN")
    return f"{column.datahub_urn}#{column.ref.field_path}"


def _lineage_key(source: LineageSource) -> tuple[str, str, str, str]:
    return (
        source.ref.dataset,
        source.ref.field_path,
        source.category.value,
        source.datahub_urn or "",
    )


def _normalize_context(column: ColumnContext) -> ColumnContext:
    if not column.resolved or column.datahub_urn is None:
        raise PolicyOracleSemanticError("prospective governance requires resolved dataset URNs")
    if column.category == SensitivityCategory.UNCLASSIFIED:
        raise PolicyOracleSemanticError("prospective governance cannot contain unclassified data")
    lineage = tuple(
        sorted(
            (
                LineageSource(
                    ref=ColumnRef(
                        dataset=source.ref.dataset,
                        field_path=source.ref.field_path,
                    ),
                    category=source.category,
                    datahub_urn=source.datahub_urn,
                )
                for source in column.lineage_sources
            ),
            key=_lineage_key,
        )
    )
    if any(source.category == SensitivityCategory.UNCLASSIFIED for source in lineage):
        raise PolicyOracleSemanticError("prospective governance lineage is unclassified")
    return ColumnContext(
        ref=ColumnRef(dataset=column.ref.dataset, field_path=column.ref.field_path),
        category=column.category,
        datahub_urn=column.datahub_urn,
        tags=tuple(sorted(set(column.tags))),
        glossary_terms=tuple(sorted(set(column.glossary_terms))),
        lineage_sources=lineage,
        resolved=True,
    )


def _semantic_columns(semantic: DisclosureSemanticRelease) -> tuple[GovernedColumn, ...]:
    by_key: dict[str, GovernedColumn] = {}
    for column in (
        *semantic.referenced_columns,
        *semantic.join_columns,
        *semantic.group_keys,
        *(source for output in semantic.outputs for source in output.sources),
    ):
        existing = by_key.get(column.key)
        if existing is not None and existing != column:
            raise PolicyOracleSemanticError("conflicting governed semantic column")
        by_key[column.key] = column
    return tuple(by_key[key] for key in sorted(by_key))


def _source_dataset_names(
    semantic: DisclosureSemanticRelease,
    governance: PolicyOracleGovernanceContext,
) -> tuple[str, ...]:
    names: list[str] = []
    for urn in semantic.source_dataset_urns:
        candidates = {
            column.ref.dataset for column in governance.columns if column.datahub_urn == urn
        }
        if len(candidates) != 1:
            raise PolicyOracleSemanticError(
                f"source dataset governance is unresolved or ambiguous: {urn}"
            )
        names.append(next(iter(candidates)))
    return tuple(sorted(names))


def _subject_key(
    state: DisclosureState,
    semantic: DisclosureSemanticRelease,
    trusted: dict[str, ColumnContext],
) -> ColumnRef | None:
    subject = state.scope.subject
    candidates = [
        trusted[column.key].ref
        for column in semantic.referenced_columns
        if column.field_path == subject.field_path
        and column.category == subject.category
        and column.dataset_urn in subject.dataset_urns
    ]
    return candidates[0] if len(candidates) == 1 else None


def _state_matches_grammar_context(
    state: DisclosureState,
    grammar: FutureActionGrammar,
) -> bool:
    context = grammar.context
    state_atoms = {atom.atom_sha256 for atom in state.released_atoms}
    return (
        state.scope.scope_sha256 == context.scope_sha256
        and state.purpose_commitment_sha256 == context.purpose_commitment_sha256
        and state.governance_commitment_sha256 == context.governance_commitment_sha256
        and state.evidence_root_sha256 == context.evidence_root_sha256
        and set(context.base_release_atom_sha256s).issubset(state_atoms)
        and state.warehouse_snapshot_sha256 in _reachable_snapshots(grammar)
    )


def _reachable_snapshots(grammar: FutureActionGrammar) -> set[str | None]:
    reachable: set[str | None] = {grammar.context.base_warehouse_snapshot_sha256}
    changed = True
    while changed:
        changed = False
        for edge in grammar.context.snapshot_transitions:
            if edge.from_snapshot_sha256 in reachable and edge.to_snapshot_sha256 not in reachable:
                reachable.add(edge.to_snapshot_sha256)
                changed = True
    return reachable


def _revalidate_inputs(
    state: DisclosureState,
    semantic: DisclosureSemanticRelease,
    governance: PolicyOracleGovernanceContext,
) -> None:
    try:
        DisclosureState.model_validate(state.model_dump(mode="json"))
        DisclosureSemanticRelease.model_validate(semantic.model_dump(mode="json"))
        PolicyOracleGovernanceContext.model_validate(governance.model_dump(mode="json"))
    except ValidationError as exc:
        raise PolicyOracleSemanticError("prospective policy input failed canonical validation") from exc
