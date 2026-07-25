from __future__ import annotations

import pytest

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
from toxicjoin.models import (
    ColumnContext,
    ColumnRef,
    Decision,
    LineageSource,
    ProjectionExposureKind,
    SensitivityCategory,
)
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.prospective.grammar import (
    FutureActionKind,
    build_future_action_grammar_context,
    instantiate_future_action_grammar,
)
from toxicjoin.prospective.policy_oracle import (
    PolicyEngineLocalOracle,
    PolicyOracleSemanticError,
    build_policy_input_from_semantic,
    build_policy_oracle_governance_context,
)
from toxicjoin.prospective.twin import build_disclosure_state

URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.oracle,PROD)"
PURPOSE = "1" * 64
GOVERNANCE = "2" * 64
EVIDENCE = "3" * 64
SNAPSHOT = "4" * 64
COHORT = "5" * 64


def _column(field: str, category: SensitivityCategory) -> GovernedColumn:
    return GovernedColumn(dataset_urn=URN, field_path=field, category=category)


def _semantic(
    *,
    outputs: tuple[SemanticOutput, ...],
    referenced: tuple[GovernedColumn, ...],
    aggregates: tuple[str, ...] = (),
    minimum_group_size: int | None = None,
) -> DisclosureSemanticRelease:
    provisional = DisclosureSemanticRelease.model_construct(
        source_dataset_urns=(URN,),
        outputs=outputs,
        referenced_columns=referenced,
        join_columns=(),
        group_keys=(),
        aggregate_functions=aggregates,
        minimum_group_size_present=minimum_group_size,
        semantic_sha256="0" * 64,
    )
    return DisclosureSemanticRelease(
        source_dataset_urns=(URN,),
        outputs=outputs,
        referenced_columns=referenced,
        join_columns=(),
        group_keys=(),
        aggregate_functions=aggregates,
        minimum_group_size_present=minimum_group_size,
        semantic_sha256=compute_semantic_sha256(provisional),
    )


def _scope() -> DisclosureScope:
    namespace = compute_subject_namespace_sha256(
        "customer_id",
        SensitivityCategory.STABLE_PSEUDONYM,
    )
    subject = GovernedSubjectDomain(
        field_path="customer_id",
        category=SensitivityCategory.STABLE_PSEUDONYM,
        dataset_urns=(URN,),
        governance_domains=(),
        namespace_sha256=namespace,
    )
    return DisclosureScope(
        principal_id="principal-oracle",
        agent_id="agent-oracle",
        subject=subject,
        scope_sha256=compute_scope_sha256(
            principal_id="principal-oracle",
            agent_id="agent-oracle",
            subject_namespace_sha256=namespace,
        ),
    )


def _state(semantic: DisclosureSemanticRelease):
    composition = DisclosureComposition(
        protected_release=True,
        release_family_sha256=semantic.semantic_sha256,
        cohort_hmac_sha256=COHORT,
    )
    return build_disclosure_state(
        scope=_scope(),
        audit_history=(),
        candidate_semantic=semantic,
        candidate_composition=composition,
        purpose_commitment_sha256=PURPOSE,
        governance_commitment_sha256=GOVERNANCE,
        evidence_root_sha256=EVIDENCE,
        warehouse_snapshot_sha256=SNAPSHOT,
    ), composition


def test_policy_oracle_preserves_sensitive_lineage_from_trusted_governance() -> None:
    subject = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    derived = _column("derived_public", SensitivityCategory.PUBLIC_OR_LOW_RISK)
    semantic = _semantic(
        outputs=(
            SemanticOutput(kind=ProjectionExposureKind.RAW_VALUE, sources=(subject,)),
            SemanticOutput(kind=ProjectionExposureKind.RAW_VALUE, sources=(derived,)),
        ),
        referenced=(subject, derived),
    )
    state, _ = _state(semantic)
    governance = build_policy_oracle_governance_context(
        (
            ColumnContext(
                ref=ColumnRef(dataset="derived", field_path="customer_id"),
                category=SensitivityCategory.STABLE_PSEUDONYM,
                datahub_urn=URN,
            ),
            ColumnContext(
                ref=ColumnRef(dataset="derived", field_path="derived_public"),
                category=SensitivityCategory.PUBLIC_OR_LOW_RISK,
                datahub_urn=URN,
                lineage_sources=(
                    LineageSource(
                        ref=ColumnRef(dataset="source", field_path="diagnosis"),
                        category=SensitivityCategory.SENSITIVE_ATTRIBUTE,
                        datahub_urn="urn:li:dataset:(urn:li:dataPlatform:duckdb,source,PROD)",
                    ),
                ),
            ),
        )
    )

    policy_input = build_policy_input_from_semantic(state, semantic, governance)
    decision = PolicyEngine(load_policy()).evaluate(policy_input)

    assert decision.decision == Decision.BLOCK
    assert any(
        source.category == SensitivityCategory.SENSITIVE_ATTRIBUTE
        for context in policy_input.projected_context
        for source in context.lineage_sources
    )


def test_policy_oracle_treats_rewrite_as_inadmissible() -> None:
    subject = _column("customer_id", SensitivityCategory.STABLE_PSEUDONYM)
    sensitive = _column("diagnosis", SensitivityCategory.SENSITIVE_ATTRIBUTE)
    semantic = _semantic(
        outputs=(
            SemanticOutput(
                kind=ProjectionExposureKind.AGGREGATE_VALUE,
                sources=(sensitive,),
            ),
        ),
        referenced=(subject, sensitive),
        aggregates=("COUNT",),
        minimum_group_size=None,
    )
    state, composition = _state(semantic)
    grammar = instantiate_future_action_grammar(
        build_future_action_grammar_context(
            base_state=state,
            base_semantic=semantic,
            base_composition=composition,
        )
    )
    governance = build_policy_oracle_governance_context(
        (
            ColumnContext(
                ref=ColumnRef(dataset="patients", field_path="customer_id"),
                category=SensitivityCategory.STABLE_PSEUDONYM,
                datahub_urn=URN,
            ),
            ColumnContext(
                ref=ColumnRef(dataset="patients", field_path="diagnosis"),
                category=SensitivityCategory.SENSITIVE_ATTRIBUTE,
                datahub_urn=URN,
            ),
        )
    )
    oracle = PolicyEngineLocalOracle(PolicyEngine(load_policy()), grammar, governance)
    replay = next(action for action in grammar.actions if action.kind == FutureActionKind.REPLAY)

    _, decision, local = oracle.evaluate_release_action(state, replay)

    assert decision.decision == Decision.REWRITE
    assert local.admissible is False
    assert "POLICY_DECISION=REWRITE" in local.reason_codes


def test_policy_oracle_rejects_unclassified_lineage_context() -> None:
    with pytest.raises(PolicyOracleSemanticError, match="lineage is unclassified"):
        build_policy_oracle_governance_context(
            (
                ColumnContext(
                    ref=ColumnRef(dataset="derived", field_path="value"),
                    category=SensitivityCategory.PUBLIC_OR_LOW_RISK,
                    datahub_urn=URN,
                    lineage_sources=(
                        LineageSource(
                            ref=ColumnRef(dataset="source", field_path="unknown"),
                            category=SensitivityCategory.UNCLASSIFIED,
                        ),
                    ),
                ),
            )
        )
