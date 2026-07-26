from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from toxicjoin.agent import (
    DataHubAgentProposalAuthority,
    GovernedAgent,
    build_agent_data_context_from_snapshot,
    build_agent_goal,
    compute_trusted_agent_proposal_evaluation_sha256,
)
from toxicjoin.agent.governance_trust import (
    DataHubGovernanceTrustAuthority,
    GovernanceTrustBinding,
    GovernanceTrustBindingError,
    compute_governance_trust_binding_sha256,
)
from toxicjoin.context.datahub import DataHubSnapshot
from toxicjoin.context.fixture import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.evidence import (
    DataHubDerivationValidation,
    DerivationKind,
    EvidencePolicy,
    EvidenceRule,
    EvidenceSource,
    EvidenceTrustState,
    compute_datahub_derivation_validation_sha256,
    datahub_governance_evidence_policy,
    default_evidence_policy,
    resolve_evidence,
)
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.integrations.datahub_authority import read_only_settings_from_env
from toxicjoin.models import ColumnRef, SensitivityCategory
from toxicjoin.policy import PolicyEngine, load_policy


NOW = datetime(2026, 7, 27, 0, 30, tzinfo=timezone.utc)
DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.day13_trust_adv,PROD)"
READ_TOKEN = "day13-governance-trust-adversarial-token"
PURPOSE = "Count diagnoses with the approved subject threshold"
SQL = (
    "SELECT COUNT(diagnosis) AS diagnosis_count "
    "FROM patients "
    "HAVING COUNT(DISTINCT customer_id) >= 20"
)


class _Planner:
    def propose(self, *, goal, context):
        return {"task_purpose": PURPOSE, "sql": SQL}

    def adapt(self, *, goal, context, previous, feedback):
        return self.propose(goal=goal, context=context)


def _snapshot() -> DataHubSnapshot:
    return DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:day13-governance-trust-adversarial-v1",
            datasets={
                "patients": FixtureDataset(
                    urn=DATASET_URN,
                    fields={
                        "customer_id": FixtureField(
                            category=SensitivityCategory.STABLE_PSEUDONYM,
                            tags=("stable-customer-identifier",),
                        ),
                        "diagnosis": FixtureField(
                            category=SensitivityCategory.SENSITIVE_ATTRIBUTE,
                            tags=("toxicjoin-sensitive-attribute",),
                        ),
                    },
                )
            },
        ),
        verified_entities=(DATASET_URN,),
        field_counts={"patients": 2},
        lineage_sample={"relationships": []},
        discovered_tools=("get_entities", "get_lineage", "list_schema_fields"),
        observed_at=NOW,
    )


def _evaluation(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("DATAHUB_GMS_URL", "https://day13-trust-adversarial.example")
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", READ_TOKEN)
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv("DATAHUB_MCP_ARGS", "mcp-server-datahub")
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")
    settings = read_only_settings_from_env()

    snapshot = _snapshot()
    context = build_agent_data_context_from_snapshot(snapshot)
    goal = build_agent_goal("Count diagnoses without releasing individual records")
    proposal = GovernedAgent(_Planner()).propose(goal=goal, context=context)
    authority = DataHubAgentProposalAuthority(
        snapshot=snapshot,
        read_settings=settings,
        policy_engine=PolicyEngine(load_policy()),
        clock=lambda: NOW + timedelta(seconds=1),
        datahub_max_age_seconds=300,
    )
    return authority.evaluate(
        proposal=proposal,
        goal=goal,
        planning_context=context,
        authorized_task_purpose=PURPOSE,
        subject_key=ColumnRef(dataset="patients", field_path="customer_id"),
    )


def _rehash_evaluation(evaluation, **updates):
    provisional = evaluation.model_copy(
        update={**updates, "evaluation_sha256": "0" * 64}
    )
    return type(evaluation).model_validate(
        provisional.model_copy(
            update={
                "evaluation_sha256": compute_trusted_agent_proposal_evaluation_sha256(
                    provisional
                )
            }
        ).model_dump(mode="json")
    )


def test_general_policy_still_does_not_trust_datahub_explicit_mapping(monkeypatch) -> None:
    evaluation = _evaluation(monkeypatch)
    claim = next(
        claim
        for claim in evaluation.evidence_bundle.claims
        if claim.predicate == "toxicjoin.sensitivity_category"
    )
    assert claim.source == EvidenceSource.DATAHUB_MCP
    assert claim.derivation == DerivationKind.EXPLICIT_MAPPING

    general = resolve_evidence(
        subject=claim.subject,
        predicate=claim.predicate,
        claims=(claim,),
        policy=default_evidence_policy(),
        now=NOW + timedelta(seconds=2),
    )
    dedicated = resolve_evidence(
        subject=claim.subject,
        predicate=claim.predicate,
        claims=(claim,),
        policy=datahub_governance_evidence_policy(),
        now=NOW + timedelta(seconds=2),
    )

    assert general.state == EvidenceTrustState.UNKNOWN
    assert dedicated.state == EvidenceTrustState.TRUSTED


def test_validation_from_future_cannot_create_governance_trust(monkeypatch) -> None:
    evaluation = _evaluation(monkeypatch)
    payload = evaluation.evidence_validation.model_dump(mode="python")
    payload.update(
        {
            "validated_at": NOW + timedelta(seconds=10),
            "validation_sha256": "0" * 64,
        }
    )
    provisional = DataHubDerivationValidation.model_construct(**payload)
    payload["validation_sha256"] = compute_datahub_derivation_validation_sha256(provisional)
    forged_validation = DataHubDerivationValidation.model_validate(payload)
    forged = _rehash_evaluation(evaluation, evidence_validation=forged_validation)

    with pytest.raises(
        GovernanceTrustBindingError,
        match="GOVERNANCE_TRUST_VALIDATION_FROM_FUTURE",
    ):
        DataHubGovernanceTrustAuthority(
            clock=lambda: NOW + timedelta(seconds=2)
        ).bind(forged)


def test_non_datahub_governance_source_cannot_create_binding(monkeypatch) -> None:
    evaluation = _evaluation(monkeypatch)
    forged_binding = evaluation.governance_binding.model_copy(update={"source": "fixture"})
    governance_sha256 = canonical_json_sha256(
        {
            "resolution": evaluation.resolution.model_dump(mode="json"),
            "binding": forged_binding.model_dump(mode="json"),
        }
    )
    forged = _rehash_evaluation(
        evaluation,
        governance_binding=forged_binding,
        governance_sha256=governance_sha256,
    )

    with pytest.raises(
        GovernanceTrustBindingError,
        match="GOVERNANCE_TRUST_SOURCE_MISMATCH",
    ):
        DataHubGovernanceTrustAuthority(
            clock=lambda: NOW + timedelta(seconds=2)
        ).bind(forged)


def test_binding_rejects_substituted_embedded_evidence_policy(monkeypatch) -> None:
    evaluation = _evaluation(monkeypatch)
    binding = DataHubGovernanceTrustAuthority(
        clock=lambda: NOW + timedelta(seconds=2)
    ).bind(evaluation)
    alternate = EvidencePolicy(
        version="datahub-governance-v1",
        trusted_rules=(
            EvidenceRule(
                source=EvidenceSource.DATAHUB_MCP,
                derivation=DerivationKind.RUNTIME_OBSERVED,
            ),
        ),
    )
    policy_sha256 = canonical_json_sha256(alternate.model_dump(mode="json"))
    provisional = binding.model_copy(
        update={
            "evidence_policy": alternate,
            "evidence_policy_sha256": policy_sha256,
            "binding_sha256": "0" * 64,
        }
    )
    forged = provisional.model_copy(
        update={"binding_sha256": compute_governance_trust_binding_sha256(provisional)}
    )

    with pytest.raises(ValueError, match="package-owned Evidence Policy"):
        GovernanceTrustBinding.model_validate(forged.model_dump(mode="json"))


def test_public_error_boundary_detaches_tampered_evaluation(monkeypatch) -> None:
    evaluation = _evaluation(monkeypatch)
    tampered = evaluation.model_copy(update={"evaluation_sha256": "0" * 64})
    authority = DataHubGovernanceTrustAuthority(
        clock=lambda: NOW + timedelta(seconds=2)
    )

    try:
        authority.bind(tampered)
    except GovernanceTrustBindingError as error:
        assert error.code == "GOVERNANCE_TRUST_INPUT_INVALID"
        assert error.__context__ is None
        assert error.__cause__ is None
        cursor = error.__traceback__
        while cursor is not None:
            if cursor.tb_frame.f_code.co_filename.endswith("governance_trust.py"):
                assert all(
                    type(value).__name__ != "TrustedAgentProposalEvaluation"
                    for value in cursor.tb_frame.f_locals.values()
                )
            cursor = cursor.tb_next
    else:
        raise AssertionError("tampered evaluation was accepted")
