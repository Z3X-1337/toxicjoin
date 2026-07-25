"""Deterministic bounded-BFS search engine for ToxicJoin PPMC."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from pydantic import ValidationError

from toxicjoin.disclosure.models import DisclosureSemanticRelease
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.models import SensitivityCategory
from toxicjoin.prospective.forbidden import (
    ForbiddenPredicateId,
    ForbiddenPredicatePolicy,
    ForbiddenStateEvaluation,
    GovernanceTrustBinding,
    TemporalPathContext,
    build_temporal_path_context,
    build_temporal_release_observation,
    evaluate_forbidden_state,
)
from toxicjoin.prospective.grammar import (
    FutureAction,
    FutureActionGrammar,
    FutureActionKind,
    FutureActionTransitionError,
    apply_future_action,
)
from toxicjoin.prospective.ppmc_models import (
    LocalAdmissibilityOracle,
    LocalOracleDecision,
    PpmcError,
    PpmcFailureReason,
    PpmcSearchConfig,
    PpmcSearchResult,
    PpmcStatus,
    _CHECKER_VERSION,
    build_ppmc_search_config,
    compute_ppmc_result_sha256,
)
from toxicjoin.prospective.trace import (
    CounterexampleStep,
    CounterexampleTrace,
    build_counterexample_step,
    build_counterexample_trace,
)
from toxicjoin.prospective.twin import (
    ColumnExposureRole,
    DisclosureAtomKind,
    DisclosureState,
)


@dataclass(frozen=True)
class _SearchNode:
    state: DisclosureState
    depth: int
    steps: tuple[CounterexampleStep, ...]
    temporal_path: TemporalPathContext


@dataclass
class _SearchCounters:
    search_nodes_discovered: int = 1
    nodes_expanded: int = 0
    actions_considered: int = 0
    transition_rejections: int = 0
    oracle_rejections: int = 0
    oracle_admissions: int = 0


class _Transcript:
    def __init__(
        self,
        *,
        initial_state: DisclosureState,
        grammar: FutureActionGrammar,
        config: PpmcSearchConfig,
    ) -> None:
        self.sha256 = canonical_json_sha256(
            {
                "checker_version": _CHECKER_VERSION,
                "initial_state_sha256": initial_state.state_sha256,
                "grammar_sha256": grammar.grammar_sha256,
                "config_sha256": config.config_sha256,
            }
        )

    def add(self, event: dict[str, object]) -> None:
        self.sha256 = canonical_json_sha256(
            {
                "previous_sha256": self.sha256,
                "event": event,
            }
        )


def check_prospective_privacy(
    *,
    initial_state: DisclosureState,
    grammar: FutureActionGrammar,
    forbidden_policy: ForbiddenPredicatePolicy,
    governance_binding: GovernanceTrustBinding | None,
    local_oracle: LocalAdmissibilityOracle,
    config: PpmcSearchConfig | None = None,
) -> PpmcSearchResult:
    """Search for a shortest-depth declared forbidden state using deterministic BFS.

    `NO_COUNTEREXAMPLE_WITHIN_BOUND` is returned only after every reachable locally
    admissible search node inside the configured bound has been explored without a matched
    or indeterminate predicate. Resource exhaustion and dependency failures return an
    explicit FAIL_CLOSED result.
    """

    selected_config = config or build_ppmc_search_config()
    _revalidate_inputs(initial_state, grammar, forbidden_policy, governance_binding, selected_config)
    if grammar.context.initial_state_sha256 != initial_state.state_sha256:
        raise PpmcError("PPMC grammar is not bound to the supplied initial disclosure state")

    counters = _SearchCounters()
    transcript = _Transcript(initial_state=initial_state, grammar=grammar, config=selected_config)
    temporal_path = _initial_temporal_path(initial_state, grammar)

    try:
        initial_evaluation = _evaluate_state(
            initial_state,
            policy=forbidden_policy,
            governance_binding=governance_binding,
            temporal_path=temporal_path,
        )
    except PpmcError:
        transcript.add(
            {
                "event": "PREDICATE_EVALUATION_FAILURE",
                "depth": 0,
                "state_sha256": initial_state.state_sha256,
            }
        )
        return _result(
            status=PpmcStatus.FAIL_CLOSED,
            failure_reason=PpmcFailureReason.PREDICATE_EVALUATION_FAILURE,
            initial_state=initial_state,
            grammar=grammar,
            config=selected_config,
            forbidden_policy=forbidden_policy,
            governance_binding=governance_binding,
            counters=counters,
            transcript=transcript,
        )
    transcript.add(_evaluation_event("INITIAL_EVALUATION", initial_evaluation))
    if initial_evaluation.forbidden:
        trace = build_counterexample_trace(
            bound=selected_config.bound,
            initial_state_sha256=initial_state.state_sha256,
            grammar_sha256=grammar.grammar_sha256,
            steps=(),
            terminal_state_sha256=initial_state.state_sha256,
            terminal_forbidden_evaluation_sha256=initial_evaluation.evaluation_sha256,
            terminal_matched_predicates=initial_evaluation.matched_predicates,
        )
        return _result(
            status=PpmcStatus.PROSPECTIVE_UNSAFE,
            initial_state=initial_state,
            grammar=grammar,
            config=selected_config,
            forbidden_policy=forbidden_policy,
            governance_binding=governance_binding,
            counters=counters,
            transcript=transcript,
            terminal_evaluation=initial_evaluation,
            counterexample=trace,
        )
    if initial_evaluation.indeterminate_predicates:
        return _result(
            status=PpmcStatus.FAIL_CLOSED,
            failure_reason=PpmcFailureReason.INDETERMINATE_SECURITY_PREDICATE,
            initial_state=initial_state,
            grammar=grammar,
            config=selected_config,
            forbidden_policy=forbidden_policy,
            governance_binding=governance_binding,
            counters=counters,
            transcript=transcript,
            terminal_evaluation=initial_evaluation,
            indeterminate_predicates=initial_evaluation.indeterminate_predicates,
        )
    if selected_config.bound == 0:
        return _result(
            status=PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND,
            initial_state=initial_state,
            grammar=grammar,
            config=selected_config,
            forbidden_policy=forbidden_policy,
            governance_binding=governance_binding,
            counters=counters,
            transcript=transcript,
        )

    queue: deque[_SearchNode] = deque(
        [_SearchNode(state=initial_state, depth=0, steps=(), temporal_path=temporal_path)]
    )
    seen = {_search_node_key(initial_state, temporal_path)}

    while queue:
        node = queue.popleft()
        counters.nodes_expanded += 1
        if node.depth >= selected_config.bound:
            continue

        for action in grammar.actions:
            counters.actions_considered += 1
            try:
                next_state = apply_future_action(node.state, action, grammar)
            except FutureActionTransitionError:
                counters.transition_rejections += 1
                transcript.add(
                    {
                        "event": "TRANSITION_REJECTED",
                        "depth": node.depth,
                        "pre_state_sha256": node.state.state_sha256,
                        "action_sha256": action.action_sha256,
                    }
                )
                continue
            except Exception:
                transcript.add(
                    {
                        "event": "TRANSITION_FAILURE",
                        "depth": node.depth,
                        "pre_state_sha256": node.state.state_sha256,
                        "action_sha256": action.action_sha256,
                    }
                )
                return _result(
                    status=PpmcStatus.FAIL_CLOSED,
                    failure_reason=PpmcFailureReason.TRANSITION_FAILURE,
                    initial_state=initial_state,
                    grammar=grammar,
                    config=selected_config,
                    forbidden_policy=forbidden_policy,
                    governance_binding=governance_binding,
                    counters=counters,
                    transcript=transcript,
                )

            decision = _invoke_local_oracle(local_oracle, node.state, action)
            if decision is None:
                transcript.add(
                    {
                        "event": "LOCAL_ORACLE_FAILURE",
                        "depth": node.depth,
                        "pre_state_sha256": node.state.state_sha256,
                        "action_sha256": action.action_sha256,
                    }
                )
                return _result(
                    status=PpmcStatus.FAIL_CLOSED,
                    failure_reason=PpmcFailureReason.LOCAL_ORACLE_FAILURE,
                    initial_state=initial_state,
                    grammar=grammar,
                    config=selected_config,
                    forbidden_policy=forbidden_policy,
                    governance_binding=governance_binding,
                    counters=counters,
                    transcript=transcript,
                )

            transcript.add(
                {
                    "event": "LOCAL_ORACLE_DECISION",
                    "depth": node.depth,
                    "pre_state_sha256": node.state.state_sha256,
                    "action_sha256": action.action_sha256,
                    "admissible": decision.admissible,
                    "decision_sha256": decision.decision_sha256,
                }
            )
            if not decision.admissible:
                counters.oracle_rejections += 1
                continue
            counters.oracle_admissions += 1

            child_depth = node.depth + 1
            next_temporal = _extend_temporal_path(
                node.temporal_path,
                action=action,
                post_state=next_state,
                observation_step=child_depth,
            )
            step = build_counterexample_step(
                step_index=node.depth,
                pre_state_sha256=node.state.state_sha256,
                action_sha256=action.action_sha256,
                local_oracle_commitment_sha256=decision.decision_sha256,
                post_state_sha256=next_state.state_sha256,
            )
            child_steps = (*node.steps, step)

            if next_temporal is None:
                try:
                    next_evaluation = _evaluate_state(
                        next_state,
                        policy=forbidden_policy,
                        governance_binding=governance_binding,
                        temporal_path=None,
                    )
                except PpmcError:
                    transcript.add(
                        {
                            "event": "PREDICATE_EVALUATION_FAILURE",
                            "depth": child_depth,
                            "state_sha256": next_state.state_sha256,
                        }
                    )
                    return _result(
                        status=PpmcStatus.FAIL_CLOSED,
                        failure_reason=PpmcFailureReason.PREDICATE_EVALUATION_FAILURE,
                        initial_state=initial_state,
                        grammar=grammar,
                        config=selected_config,
                        forbidden_policy=forbidden_policy,
                        governance_binding=governance_binding,
                        counters=counters,
                        transcript=transcript,
                    )
                transcript.add(
                    _evaluation_event("STATE_EVALUATION", next_evaluation, depth=child_depth)
                )
                if next_evaluation.forbidden:
                    trace = _trace(
                        config=selected_config,
                        initial_state=initial_state,
                        grammar=grammar,
                        steps=child_steps,
                        terminal_state=next_state,
                        terminal_evaluation=next_evaluation,
                    )
                    return _result(
                        status=PpmcStatus.PROSPECTIVE_UNSAFE,
                        initial_state=initial_state,
                        grammar=grammar,
                        config=selected_config,
                        forbidden_policy=forbidden_policy,
                        governance_binding=governance_binding,
                        counters=counters,
                        transcript=transcript,
                        terminal_evaluation=next_evaluation,
                        counterexample=trace,
                    )
                return _result(
                    status=PpmcStatus.FAIL_CLOSED,
                    failure_reason=PpmcFailureReason.INDETERMINATE_SECURITY_PREDICATE,
                    initial_state=initial_state,
                    grammar=grammar,
                    config=selected_config,
                    forbidden_policy=forbidden_policy,
                    governance_binding=governance_binding,
                    counters=counters,
                    transcript=transcript,
                    terminal_evaluation=next_evaluation,
                    indeterminate_predicates=next_evaluation.indeterminate_predicates,
                )

            child_key = _search_node_key(next_state, next_temporal)
            if child_key in seen:
                transcript.add(
                    {
                        "event": "SEARCH_NODE_DEDUPLICATED",
                        "depth": child_depth,
                        "state_sha256": next_state.state_sha256,
                        "temporal_signature_sha256": child_key[1],
                    }
                )
                continue
            if len(seen) >= selected_config.max_states:
                transcript.add(
                    {
                        "event": "STATE_BUDGET_EXHAUSTED",
                        "depth": child_depth,
                        "state_sha256": next_state.state_sha256,
                    }
                )
                return _result(
                    status=PpmcStatus.FAIL_CLOSED,
                    failure_reason=PpmcFailureReason.STATE_BUDGET_EXHAUSTED,
                    initial_state=initial_state,
                    grammar=grammar,
                    config=selected_config,
                    forbidden_policy=forbidden_policy,
                    governance_binding=governance_binding,
                    counters=counters,
                    transcript=transcript,
                )

            seen.add(child_key)
            counters.search_nodes_discovered = len(seen)
            try:
                next_evaluation = _evaluate_state(
                    next_state,
                    policy=forbidden_policy,
                    governance_binding=governance_binding,
                    temporal_path=next_temporal,
                )
            except PpmcError:
                transcript.add(
                    {
                        "event": "PREDICATE_EVALUATION_FAILURE",
                        "depth": child_depth,
                        "state_sha256": next_state.state_sha256,
                    }
                )
                return _result(
                    status=PpmcStatus.FAIL_CLOSED,
                    failure_reason=PpmcFailureReason.PREDICATE_EVALUATION_FAILURE,
                    initial_state=initial_state,
                    grammar=grammar,
                    config=selected_config,
                    forbidden_policy=forbidden_policy,
                    governance_binding=governance_binding,
                    counters=counters,
                    transcript=transcript,
                )
            transcript.add(
                _evaluation_event("STATE_EVALUATION", next_evaluation, depth=child_depth)
            )
            if next_evaluation.forbidden:
                trace = _trace(
                    config=selected_config,
                    initial_state=initial_state,
                    grammar=grammar,
                    steps=child_steps,
                    terminal_state=next_state,
                    terminal_evaluation=next_evaluation,
                )
                return _result(
                    status=PpmcStatus.PROSPECTIVE_UNSAFE,
                    initial_state=initial_state,
                    grammar=grammar,
                    config=selected_config,
                    forbidden_policy=forbidden_policy,
                    governance_binding=governance_binding,
                    counters=counters,
                    transcript=transcript,
                    terminal_evaluation=next_evaluation,
                    counterexample=trace,
                )
            if next_evaluation.indeterminate_predicates:
                return _result(
                    status=PpmcStatus.FAIL_CLOSED,
                    failure_reason=PpmcFailureReason.INDETERMINATE_SECURITY_PREDICATE,
                    initial_state=initial_state,
                    grammar=grammar,
                    config=selected_config,
                    forbidden_policy=forbidden_policy,
                    governance_binding=governance_binding,
                    counters=counters,
                    transcript=transcript,
                    terminal_evaluation=next_evaluation,
                    indeterminate_predicates=next_evaluation.indeterminate_predicates,
                )
            if child_depth < selected_config.bound:
                queue.append(
                    _SearchNode(
                        state=next_state,
                        depth=child_depth,
                        steps=child_steps,
                        temporal_path=next_temporal,
                    )
                )

    return _result(
        status=PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND,
        initial_state=initial_state,
        grammar=grammar,
        config=selected_config,
        forbidden_policy=forbidden_policy,
        governance_binding=governance_binding,
        counters=counters,
        transcript=transcript,
    )


def _revalidate_inputs(
    initial_state: DisclosureState,
    grammar: FutureActionGrammar,
    policy: ForbiddenPredicatePolicy,
    binding: GovernanceTrustBinding | None,
    config: PpmcSearchConfig,
) -> None:
    try:
        DisclosureState.model_validate(initial_state.model_dump(mode="json"))
        FutureActionGrammar.model_validate(grammar.model_dump(mode="json"))
        ForbiddenPredicatePolicy.model_validate(policy.model_dump(mode="json"))
        PpmcSearchConfig.model_validate(config.model_dump(mode="json"))
        if binding is not None:
            GovernanceTrustBinding.model_validate(binding.model_dump(mode="json"))
    except ValidationError as exc:
        raise PpmcError("PPMC trusted input failed canonical revalidation") from exc


def _invoke_local_oracle(
    oracle: LocalAdmissibilityOracle,
    state: DisclosureState,
    action: FutureAction,
) -> LocalOracleDecision | None:
    try:
        decision = oracle(state, action)
        if not isinstance(decision, LocalOracleDecision):
            return None
        validated = LocalOracleDecision.model_validate(decision.model_dump(mode="json"))
    except Exception:
        return None
    if validated.state_sha256 != state.state_sha256:
        return None
    if validated.action_sha256 != action.action_sha256:
        return None
    return validated


def _initial_temporal_path(
    initial_state: DisclosureState,
    grammar: FutureActionGrammar,
) -> TemporalPathContext | None:
    semantic = grammar.context.base_semantic
    base_atom_hashes = set(grammar.context.base_release_atom_sha256s)
    historical_sensitive = any(
        atom.atom_sha256 not in base_atom_hashes
        and atom.kind == DisclosureAtomKind.COLUMN_EXPOSURE
        and atom.column_role == ColumnExposureRole.OUTPUT
        and atom.category == SensitivityCategory.SENSITIVE_ATTRIBUTE
        for atom in initial_state.released_atoms
    )
    if historical_sensitive:
        # The current ledger does not preserve a warehouse snapshot per historical release.
        # Treat missing temporal provenance as indeterminate instead of fabricating safety.
        return None
    if not _semantic_is_sensitive(semantic):
        return build_temporal_path_context(())
    if initial_state.warehouse_snapshot_sha256 is None:
        return None
    observation = build_temporal_release_observation(
        step_index=0,
        release_semantic_sha256=semantic.semantic_sha256,
        warehouse_snapshot_sha256=initial_state.warehouse_snapshot_sha256,
        sensitive_release=True,
    )
    return build_temporal_path_context((observation,))


def _extend_temporal_path(
    path: TemporalPathContext,
    *,
    action: FutureAction,
    post_state: DisclosureState,
    observation_step: int,
) -> TemporalPathContext | None:
    if action.kind == FutureActionKind.SNAPSHOT_ADVANCE:
        return path
    assert action.semantic is not None
    if not _semantic_is_sensitive(action.semantic):
        return path
    if post_state.warehouse_snapshot_sha256 is None:
        return None
    observation = build_temporal_release_observation(
        step_index=observation_step,
        release_semantic_sha256=action.semantic.semantic_sha256,
        warehouse_snapshot_sha256=post_state.warehouse_snapshot_sha256,
        sensitive_release=True,
    )
    return build_temporal_path_context((*path.observations, observation))


def _semantic_is_sensitive(semantic: DisclosureSemanticRelease) -> bool:
    return any(
        source.category == SensitivityCategory.SENSITIVE_ATTRIBUTE
        for output in semantic.outputs
        for source in output.sources
    )


def _search_node_key(state: DisclosureState, path: TemporalPathContext) -> tuple[str, str]:
    pairs = tuple(
        sorted(
            {
                (item.release_semantic_sha256, item.warehouse_snapshot_sha256)
                for item in path.observations
                if item.sensitive_release and item.warehouse_snapshot_sha256 is not None
            }
        )
    )
    temporal_signature = canonical_json_sha256(
        {
            "schema_version": "1.0",
            "sensitive_release_snapshot_pairs": pairs,
        }
    )
    return state.state_sha256, temporal_signature


def _evaluate_state(
    state: DisclosureState,
    *,
    policy: ForbiddenPredicatePolicy,
    governance_binding: GovernanceTrustBinding | None,
    temporal_path: TemporalPathContext | None,
) -> ForbiddenStateEvaluation:
    try:
        return evaluate_forbidden_state(
            state,
            policy=policy,
            governance_binding=governance_binding,
            temporal_path=temporal_path,
        )
    except Exception as exc:
        raise PpmcError("forbidden-state evaluation failed") from exc


def _evaluation_event(
    event: str,
    evaluation: ForbiddenStateEvaluation,
    *,
    depth: int = 0,
) -> dict[str, object]:
    return {
        "event": event,
        "depth": depth,
        "state_sha256": evaluation.state_sha256,
        "evaluation_sha256": evaluation.evaluation_sha256,
        "forbidden": evaluation.forbidden,
        "matched_predicates": [item.value for item in evaluation.matched_predicates],
        "indeterminate_predicates": [item.value for item in evaluation.indeterminate_predicates],
    }


def _trace(
    *,
    config: PpmcSearchConfig,
    initial_state: DisclosureState,
    grammar: FutureActionGrammar,
    steps: tuple[CounterexampleStep, ...],
    terminal_state: DisclosureState,
    terminal_evaluation: ForbiddenStateEvaluation,
) -> CounterexampleTrace:
    return build_counterexample_trace(
        bound=config.bound,
        initial_state_sha256=initial_state.state_sha256,
        grammar_sha256=grammar.grammar_sha256,
        steps=steps,
        terminal_state_sha256=terminal_state.state_sha256,
        terminal_forbidden_evaluation_sha256=terminal_evaluation.evaluation_sha256,
        terminal_matched_predicates=terminal_evaluation.matched_predicates,
    )


def _result(
    *,
    status: PpmcStatus,
    initial_state: DisclosureState,
    grammar: FutureActionGrammar,
    config: PpmcSearchConfig,
    forbidden_policy: ForbiddenPredicatePolicy,
    governance_binding: GovernanceTrustBinding | None,
    counters: _SearchCounters,
    transcript: _Transcript,
    failure_reason: PpmcFailureReason | None = None,
    terminal_evaluation: ForbiddenStateEvaluation | None = None,
    indeterminate_predicates: tuple[ForbiddenPredicateId, ...] = (),
    counterexample: CounterexampleTrace | None = None,
) -> PpmcSearchResult:
    payload = {
        "schema_version": "1.0",
        "checker_version": _CHECKER_VERSION,
        "status": status,
        "failure_reason": failure_reason,
        "initial_state_sha256": initial_state.state_sha256,
        "grammar_sha256": grammar.grammar_sha256,
        "config_sha256": config.config_sha256,
        "bound": config.bound,
        "max_states": config.max_states,
        "forbidden_policy_sha256": forbidden_policy.policy_sha256,
        "governance_binding_sha256": (
            governance_binding.binding_sha256 if governance_binding is not None else None
        ),
        "search_nodes_discovered": counters.search_nodes_discovered,
        "nodes_expanded": counters.nodes_expanded,
        "actions_considered": counters.actions_considered,
        "transition_rejections": counters.transition_rejections,
        "oracle_rejections": counters.oracle_rejections,
        "oracle_admissions": counters.oracle_admissions,
        "indeterminate_predicates": indeterminate_predicates,
        "terminal_forbidden_evaluation_sha256": (
            terminal_evaluation.evaluation_sha256 if terminal_evaluation is not None else None
        ),
        "counterexample": counterexample,
        "search_transcript_sha256": transcript.sha256,
    }
    provisional = PpmcSearchResult.model_construct(**payload, result_sha256="0" * 64)
    return PpmcSearchResult(**payload, result_sha256=compute_ppmc_result_sha256(provisional))
