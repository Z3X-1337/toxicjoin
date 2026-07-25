from __future__ import annotations

import pytest

import toxicjoin.prospective.twin as twin
from toxicjoin.disclosure.models import (
    DisclosureScope,
    DisclosureSemanticRelease,
    GovernedColumn,
    GovernedSubjectDomain,
    SemanticOutput,
    compute_scope_sha256,
    compute_semantic_sha256,
    compute_subject_namespace_sha256,
)
from toxicjoin.models import ProjectionExposureKind, SensitivityCategory


DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.twin-budget,PROD)"


def _scope() -> DisclosureScope:
    namespace = compute_subject_namespace_sha256(
        "customer_id",
        SensitivityCategory.STABLE_PSEUDONYM,
    )
    subject = GovernedSubjectDomain(
        field_path="customer_id",
        category=SensitivityCategory.STABLE_PSEUDONYM,
        dataset_urns=(DATASET_URN,),
        governance_domains=("urn:li:domain:privacy",),
        namespace_sha256=namespace,
    )
    return DisclosureScope(
        principal_id="principal-budget",
        agent_id="agent-budget",
        subject=subject,
        scope_sha256=compute_scope_sha256(
            principal_id="principal-budget",
            agent_id="agent-budget",
            subject_namespace_sha256=namespace,
        ),
    )


def _public_semantic() -> DisclosureSemanticRelease:
    public = GovernedColumn(
        dataset_urn=DATASET_URN,
        field_path="country_name",
        category=SensitivityCategory.PUBLIC_OR_LOW_RISK,
    )
    output = SemanticOutput(
        kind=ProjectionExposureKind.RAW_VALUE,
        sources=(public,),
    )
    provisional = DisclosureSemanticRelease.model_construct(
        source_dataset_urns=(DATASET_URN,),
        outputs=(output,),
        referenced_columns=(public,),
        join_columns=(),
        group_keys=(),
        aggregate_functions=(),
        minimum_group_size_present=None,
        semantic_sha256="0" * 64,
    )
    return DisclosureSemanticRelease(
        source_dataset_urns=(DATASET_URN,),
        outputs=(output,),
        referenced_columns=(public,),
        join_columns=(),
        group_keys=(),
        aggregate_functions=(),
        minimum_group_size_present=None,
        semantic_sha256=compute_semantic_sha256(provisional),
    )


def _build_state() -> twin.DisclosureState:
    return twin.build_disclosure_state(
        scope=_scope(),
        audit_history=(),
        candidate_semantic=_public_semantic(),
        candidate_composition=None,
        purpose_commitment_sha256="1" * 64,
        governance_commitment_sha256="2" * 64,
        evidence_root_sha256="3" * 64,
        warehouse_snapshot_sha256="4" * 64,
    )


def test_direct_atom_budget_exhaustion_fails_closed(monkeypatch) -> None:
    monkeypatch.setattr(twin, "_MAX_STATE_ATOMS", 1)

    with pytest.raises(twin.DisclosureTwinError, match="direct-atom budget exceeded"):
        _build_state()


def test_inference_rule_budget_exhaustion_fails_closed(monkeypatch) -> None:
    monkeypatch.setattr(twin, "_MAX_INFERENCE_RULES", 0)

    with pytest.raises(twin.DisclosureTwinError, match="inference-rule budget exceeded"):
        _build_state()
