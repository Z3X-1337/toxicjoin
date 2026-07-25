"""Trusted adapter from prospective semantic actions to the existing PolicyEngine.

The adapter does not change PolicyEngine semantics. Release actions are reconstructed into
provider-neutral PolicyInput objects and are locally admissible only when the existing
kernel returns ALLOW. REWRITE/BLOCK remain inadmissible until a separately modeled action
is re-evaluated. SNAPSHOT_ADVANCE is a declared no-release transition and is handled by an
explicit security-owned rule rather than being misrepresented as a PolicyEngine query.
"""

from __future__ import annotations

from toxicjoin.disclosure.models import DisclosureSemanticRelease, GovernedColumn
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.models import (
    ColumnContext,
    ColumnRef,
    Decision,
    PolicyDecision,
    PolicyInput,
    ProjectionExposure,
    QueryPlan,
    SensitivityCategory,
)
from toxicjoin.policy import PolicyEngine
from toxicjoin.prospective.grammar import (
    FutureAction,
    FutureActionGrammar,
    FutureActionKind,
)
from toxicjoin.prospective.ppmc_models import (
    LocalOracleDecision,
    build_local_oracle_decision,
)
from toxicjoin.prospective.twin import DisclosureState

_ADAPTER_VERSION = "0.1.0"


class PolicyOracleError(RuntimeError):
    """Raised when the trusted PolicyEngine adapter itself cannot operate safely."""


class PolicyOracleSemanticError(ValueError):
    """Expected fail-closed rejection for a semantic release that cannot be reconstructed."""


def build_policy_input_from_semantic(
    state: DisclosureState,
    semantic: DisclosureSemanticRelease,
) -> PolicyInput:
    """Reconstruct the PolicyEngine's provider-neutral input from governed semantics.

    DisclosureSemanticRelease is generated from the exact normalized governance context used
    by policy and intentionally contains no SQL aliases or raw values. The reconstruction uses
    dataset URNs as stable dataset identifiers and refuses to guess a threshold subject.
    """

    _revalidate_state_and_semantic(state, semantic)
    columns = _semantic_columns(semantic)
    source_datasets = set(semantic.source_dataset_urns)
    if any(column.dataset_urn not in source_datasets for column in columns):
        raise PolicyOracleSemanticError("semantic column is outside the declared source datasets")
    if any(column.category == SensitivityCategory.UNCLASSIFIED for column in columns):
        raise PolicyOracleSemanticError("prospective policy input cannot contain unclassified data")

    referenced_keys = {column.key for column in semantic.referenced_columns}
    required_keys = {
        *(source.key for output in semantic.outputs for source in output.sources),
        *(column.key for column in semantic.join_columns),
        *(column.key for column in semantic.group_keys),
    }
    if not required_keys.issubset(referenced_keys):
        raise PolicyOracleSemanticError("semantic release is missing governed references")

    refs = {column.key: _column_ref(column) for column in columns}
    contexts = {
        column.key: ColumnContext(
            ref=refs[column.key],
            category=column.category,
            datahub_urn=column.dataset_urn,
            resolved=True,
        )
        for column in columns
    }

    projected_keys = {
        source.key for output in semantic.outputs for source in output.sources
    }
    projected_columns = tuple(refs[key] for key in sorted(projected_keys))
    projected_context = tuple(contexts[key] for key in sorted(projected_keys))
    referenced_columns = tuple(refs[column.key] for column in semantic.referenced_columns)
    all_referenced_context = tuple(contexts[column.key] for column in semantic.referenced_columns)
    join_columns = tuple(refs[column.key] for column in semantic.join_columns)
    group_columns = tuple(refs[column.key] for column in semantic.group_keys)

    exposures = tuple(
        ProjectionExposure(
            output_name=f"ppmc_output_{index:03d}",
            kind=output.kind,
            source_columns=tuple(refs[source.key] for source in output.sources),
        )
        for index, output in enumerate(semantic.outputs)
    )

    subject_key = _subject_key(state, semantic)
    if semantic.minimum_group_size_present is not None and subject_key is None:
        raise PolicyOracleSemanticError(
            "minimum-group-size evidence lacks one unambiguous governed subject"
        )

    plan = QueryPlan(
        statement_type="SELECT",
        source_datasets=semantic.source_dataset_urns,
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
) -> tuple[PolicyInput, PolicyDecision]:
    """Evaluate one prospective semantic release with the unchanged existing PolicyEngine."""

    policy_input = build_policy_input_from_semantic(state, semantic)
    return policy_input, engine.evaluate(policy_input)


class PolicyEngineLocalOracle:
    """PPMC local-admissibility oracle bound to one exact grammar and PolicyConfig."""

    def __init__(self, engine: PolicyEngine, grammar: FutureActionGrammar) -> None:
        self._engine = engine
        self._grammar = FutureActionGrammar.model_validate(grammar.model_dump(mode="json"))
        self._actions = {action.action_sha256: action for action in self._grammar.actions}
        self._policy_config_sha256 = _policy_config_sha256(engine)
        self.oracle_version = (
            f"policy-engine-oracle/{_ADAPTER_VERSION}:"
            f"{self._policy_config_sha256[:24]}"
        )

    @property
    def policy_config_sha256(self) -> str:
        return self._policy_config_sha256

    @property
    def grammar_sha256(self) -> str:
        return self._grammar.grammar_sha256

    def __call__(self, state: DisclosureState, action: FutureAction) -> LocalOracleDecision:
        if _policy_config_sha256(self._engine) != self._policy_config_sha256:
            raise PolicyOracleError("PolicyEngine configuration changed after oracle binding")

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
            _, decision = evaluate_semantic_with_policy(self._engine, state, action.semantic)
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
        """Return the exact PolicyInput/PolicyDecision backing one release action."""

        expected = self._actions.get(action.action_sha256)
        if expected is None or expected != action or action.semantic is None:
            raise PolicyOracleSemanticError("action is not a bound semantic release action")
        policy_input, decision = evaluate_semantic_with_policy(self._engine, state, action.semantic)
        local = self(state, action)
        return policy_input, decision, local

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


def _column_ref(column: GovernedColumn) -> ColumnRef:
    return ColumnRef(dataset=column.dataset_urn, field_path=column.field_path)


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


def _subject_key(
    state: DisclosureState,
    semantic: DisclosureSemanticRelease,
) -> ColumnRef | None:
    subject = state.scope.subject
    candidates = [
        column
        for column in semantic.referenced_columns
        if column.field_path == subject.field_path
        and column.category == subject.category
        and column.dataset_urn in subject.dataset_urns
    ]
    if len(candidates) == 1:
        return _column_ref(candidates[0])
    return None


def _state_matches_grammar_context(
    state: DisclosureState,
    grammar: FutureActionGrammar,
) -> bool:
    context = grammar.context
    return (
        state.scope.scope_sha256 == context.scope_sha256
        and state.purpose_commitment_sha256 == context.purpose_commitment_sha256
        and state.governance_commitment_sha256 == context.governance_commitment_sha256
        and state.evidence_root_sha256 == context.evidence_root_sha256
    )


def _revalidate_state_and_semantic(
    state: DisclosureState,
    semantic: DisclosureSemanticRelease,
) -> None:
    try:
        DisclosureState.model_validate(state.model_dump(mode="json"))
        DisclosureSemanticRelease.model_validate(semantic.model_dump(mode="json"))
    except ValidationError as exc:  # type: ignore[name-defined]
        raise PolicyOracleSemanticError("prospective policy input failed canonical validation") from exc
