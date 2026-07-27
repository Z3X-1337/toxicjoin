"""Prospective Privacy Model Checker (PPMC) public API.

P0 uses deterministic bounded BFS over a finite security-owned Future Action Grammar.
It is intentionally separate from PolicyEngine and does not authorize execution.
"""

from __future__ import annotations

from toxicjoin.disclosure.models import (
    DisclosureComposition,
    DisclosureSemanticRelease,
    GovernedColumn,
    SemanticOutput,
)
from toxicjoin.prospective.forbidden import ForbiddenPredicatePolicy, GovernanceTrustBinding
from toxicjoin.prospective.grammar import (
    DeclaredSnapshotTransition,
    FutureAction,
    FutureActionGrammar,
    FutureActionGrammarContext,
)
from toxicjoin.prospective.ppmc_models import (
    LocalAdmissibilityOracle,
    LocalOracleDecision,
    PpmcError,
    PpmcFailureReason,
    PpmcSearchConfig,
    PpmcSearchResult,
    PpmcStatus,
    build_local_oracle_decision,
    build_ppmc_search_config,
    compute_local_oracle_decision_sha256,
    compute_ppmc_config_sha256,
    compute_ppmc_result_sha256,
)
from toxicjoin.prospective.ppmc_search import (
    check_prospective_privacy as _check_prospective_privacy,
)
from toxicjoin.prospective.twin import DisclosureState


def check_prospective_privacy(
    *,
    initial_state: DisclosureState,
    grammar: FutureActionGrammar,
    forbidden_policy: ForbiddenPredicatePolicy,
    governance_binding: GovernanceTrustBinding | None,
    local_oracle: LocalAdmissibilityOracle,
    config: PpmcSearchConfig | None = None,
) -> PpmcSearchResult:
    """Run PPMC only after the Future Action Grammar passes the exact-type trust gate."""

    try:
        _require_exact_future_action_grammar_types(grammar)
    except (TypeError, ValueError, AttributeError):
        raise PpmcError("PPMC trusted input failed canonical revalidation") from None
    return _check_prospective_privacy(
        initial_state=initial_state,
        grammar=grammar,
        forbidden_policy=forbidden_policy,
        governance_binding=governance_binding,
        local_oracle=local_oracle,
        config=config,
    )


def _require_exact_future_action_grammar_types(grammar: FutureActionGrammar) -> None:
    if type(grammar) is not FutureActionGrammar:
        raise TypeError("PPMC grammar must use the exact FutureActionGrammar type")
    context = grammar.context
    if type(context) is not FutureActionGrammarContext:
        raise TypeError("PPMC grammar context must use the exact model type")

    _require_exact_semantic(context.base_semantic)
    if type(context.base_composition) is not DisclosureComposition:
        raise TypeError("PPMC grammar base composition must use the exact model type")
    for column in (*context.relevant_projection_fields, *context.group_key_fields):
        if type(column) is not GovernedColumn:
            raise TypeError("PPMC grammar governed columns must use the exact model type")
    for transition in context.snapshot_transitions:
        if type(transition) is not DeclaredSnapshotTransition:
            raise TypeError("PPMC grammar snapshot transitions must use the exact model type")

    for action in grammar.actions:
        if type(action) is not FutureAction:
            raise TypeError("PPMC grammar actions must use the exact FutureAction type")
        if action.semantic is not None:
            _require_exact_semantic(action.semantic)
        if action.composition is not None and type(action.composition) is not DisclosureComposition:
            raise TypeError("PPMC grammar action composition must use the exact model type")


def _require_exact_semantic(semantic: DisclosureSemanticRelease) -> None:
    if type(semantic) is not DisclosureSemanticRelease:
        raise TypeError("PPMC grammar semantic release must use the exact model type")
    for output in semantic.outputs:
        if type(output) is not SemanticOutput:
            raise TypeError("PPMC grammar semantic outputs must use the exact model type")
        for source in output.sources:
            if type(source) is not GovernedColumn:
                raise TypeError("PPMC grammar semantic sources must use the exact model type")
    for column in (
        *semantic.referenced_columns,
        *semantic.join_columns,
        *semantic.group_keys,
    ):
        if type(column) is not GovernedColumn:
            raise TypeError("PPMC grammar semantic columns must use the exact model type")


__all__ = [
    "LocalAdmissibilityOracle",
    "LocalOracleDecision",
    "PpmcError",
    "PpmcFailureReason",
    "PpmcSearchConfig",
    "PpmcSearchResult",
    "PpmcStatus",
    "build_local_oracle_decision",
    "build_ppmc_search_config",
    "check_prospective_privacy",
    "compute_local_oracle_decision_sha256",
    "compute_ppmc_config_sha256",
    "compute_ppmc_result_sha256",
]
