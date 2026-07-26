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
)
from toxicjoin.context.datahub import DataHubSnapshot
from toxicjoin.context.fixture import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.evidence import (
    DataHubDerivationValidation,
    DataHubEvidenceBundle,
    DerivationKind,
    EvidenceTrustState,
    build_evidence_claim,
    compute_datahub_derivation_validation_sha256,
    compute_datahub_evidence_root,
)
from toxicjoin.integrations.datahub_authority import (
    ReadOnlyDataHubMcpSettings,
    read_only_settings_from_env,
)
from toxicjoin.models import ColumnRef, LineageSource, SensitivityCategory
from toxicjoin.policy import PolicyEngine, load_policy


NOW = datetime(2026, 7, 27, 0, 0, tzinfo=timezone.utc)
PATIENTS_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.day13_trust_patients,PROD)"
CUSTOMERS_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.day13_trust_customers,PROD)"
READ_TOKEN = "day13-governance-trust-read-token"
PURPOSE = "Count diagnoses with the approved subject threshold"
GOAL_TEXT = "Count diagnoses without releasing individual records"
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


class _MutableClock:
    def __init__(self, current: datetime) -> None:
        self.current = current

    def __call__(self) -> datetime:
        return self.current


def _snapshot() -> DataHubSnapshot:
    return DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:day13-governance-trust-v1",
            datasets={
                "customers": FixtureDataset(
                    urn=CUSTOMERS_URN,
                    fields={
                        "customer_id": FixtureField(
                            category=SensitivityCategory.STABLE_PSEUDONYM,
                            tags=("stable-customer-identifier",),
                        )
                    },
                ),
                "patients": FixtureDataset(
                    urn=PATIENTS_URN,
                    owner="urn:li:corpuser:data-owner",
                    domain="urn:li:domain:clinical-security",
                    fields={
                        "customer_id": FixtureField(
                            category=SensitivityCategory.STABLE_PSEUDONYM,
                            tags=("stable-customer-identifier",),
                        ),
                        "diagnosis": FixtureField(
                            category=SensitivityCategory.SENSITIVE_ATTRIBUTE,
                            tags=("toxicjoin-sensitive-attribute",),
                            lineage_sources=(
                                LineageSource(
                                    ref=ColumnRef(
                                        dataset="customers",
                                        field_path="customer_id",
                                    ),
                                    category=SensitivityCategory.STABLE_PSEUDONYM,
                                    datahub_urn=CUSTOMERS_URN,
                                ),
                            ),
                        ),
                    },
                ),
            },
        ),
        verified_entities=(CUSTOMERS_URN, PATIENTS_URN),
        field_counts={"customers": 1, "patients": 2},
        lineage_sample={"relationships": [{"source": CUSTOMERS_URN}]},
        discovered_tools=("get_entities", "get_lineage", "list_schema_fields"),
        observed_at=NOW,
    )


def _read_settings(monkeypatch: pytest.MonkeyPatch) -> ReadOnlyDataHubMcpSettings:
    monkeypatch.setenv("DATAHUB_GMS_URL", "https://day13-governance-trust.example")
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", READ_TOKEN)
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv("DATAHUB_MCP_ARGS", "mcp-server-datahub")
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")
    return read_only_settings_from_env()


def _evaluation(monkeypatch: pytest.MonkeyPatch):
    snapshot = _snapshot()
    context = build_agent_data_context_from_snapshot(snapshot)
    goal = build_agent_goal(GOAL_TEXT)
    proposal = GovernedAgent(_Planner()).propose(goal=goal, context=context)
    authority = DataHubAgentProposalAuthority(
        snapshot=snapshot,
        read_settings=_read_settings(monkeypatch),
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


def _with_incomplete_diagnosis_classification(evaluation):
    bundle = evaluation.evidence_bundle
    subject = f"{PATIENTS_URN}#diagnosis"
    original = next(
        claim
        for claim in bundle.claims
        if claim.subject == subject
        and claim.predicate == "toxicjoin.sensitivity_category"
    )
    incomplete = build_evidence_claim(
        subject=original.subject,
        predicate=original.predicate,
        value=original.value,
        source=original.source,
        derivation=original.derivation,
        source_identity=original.source_identity,
        observed_at=original.observed_at,
        expires_at=original.expires_at,
        effective_from=original.effective_from,
        effective_until=original.effective_until,
        complete=False,
        supporting_claim_ids=original.supporting_claim_ids,
    )
    claims = tuple(
        sorted(
            (incomplete if claim.claim_id == original.claim_id else claim for claim in bundle.claims),
            key=lambda claim: claim.claim_id,
        )
    )
    provisional_bundle = bundle.model_copy(
        update={"claims": claims, "evidence_root_sha256": "0" * 64}
    )
    rebuilt_bundle = DataHubEvidenceBundle.model_validate(
        provisional_bundle.model_copy(
            update={"evidence_root_sha256": compute_datahub_evidence_root(provisional_bundle)}
        ).model_dump(mode="json")
    )

    validation = evaluation.evidence_validation
    validation_payload = validation.model_dump(mode="python")
    validation_payload.update(
        {
            "evidence_root_sha256": rebuilt_bundle.evidence_root_sha256,
            "observed_claim_ids": tuple(
                sorted(
                    claim.claim_id
                    for claim in rebuilt_bundle.claims
                    if claim.derivation == DerivationKind.RUNTIME_OBSERVED
                )
            ),
            "mapped_claim_ids": tuple(
                sorted(
                    claim.claim_id
                    for claim in rebuilt_bundle.claims
                    if claim.derivation == DerivationKind.EXPLICIT_MAPPING
                )
            ),
            "validation_sha256": "0" * 64,
        }
    )
    provisional_validation = DataHubDerivationValidation.model_construct(**validation_payload)
    validation_payload["validation_sha256"] = compute_datahub_derivation_validation_sha256(
        provisional_validation
    )
    rebuilt_validation = DataHubDerivationValidation.model_validate(validation_payload)

    provisional_evaluation = evaluation.model_copy(
        update={
            "evidence_bundle": rebuilt_bundle,
            "evidence_validation": rebuilt_validation,
            "evaluation_sha256": "0" * 64,
        }
    )
    return type(evaluation).model_validate(
        provisional_evaluation.model_copy(
            update={
                "evaluation_sha256": compute_trusted_agent_proposal_evaluation_sha256(
                    provisional_evaluation
                )
            }
        ).model_dump(mode="json")
    )


def test_positive_binding_requires_trusted_exact_governance_facts(monkeypatch) -> None:
    evaluation = _evaluation(monkeypatch)
    authority = DataHubGovernanceTrustAuthority(
        clock=lambda: NOW + timedelta(seconds=2)
    )

    binding = authority.bind(evaluation)

    assert binding.governance_trusted is True
    assert binding.evidence_trust_resolved is True
    assert binding.prospective_privacy_checked is False
    assert binding.execution_authorized is False
    assert binding.evaluation_sha256 == evaluation.evaluation_sha256
    assert binding.source_snapshot_sha256 == evaluation.source_snapshot_sha256
    assert binding.evidence_root_sha256 == evaluation.evidence_bundle.evidence_root_sha256
    assert binding.governance_sha256 == evaluation.governance_sha256
    assert binding.evidence_policy.version == "datahub-governance-v1"
    assert all(
        resolution.state == EvidenceTrustState.TRUSTED
        for resolution in binding.resolutions
    )

    requirements = {
        (requirement.subject, requirement.predicate): requirement.expected_value
        for requirement in binding.requirements
    }
    diagnosis_subject = f"{PATIENTS_URN}#diagnosis"
    customer_subject = f"{CUSTOMERS_URN}#customer_id"
    assert requirements[(diagnosis_subject, "toxicjoin.sensitivity_category")] == (
        SensitivityCategory.SENSITIVE_ATTRIBUTE.value
    )
    assert requirements[(diagnosis_subject, "datahub.lineage_transport_complete")] == "true"
    assert requirements[(diagnosis_subject, "toxicjoin.lineage_governance_complete")] == "true"
    assert requirements[(CUSTOMERS_URN, "datahub.logical_name")] == "customers"
    assert requirements[(customer_subject, "toxicjoin.sensitivity_category")] == (
        SensitivityCategory.STABLE_PSEUDONYM.value
    )


def test_binding_round_trip_preserves_positive_authority_invariants(monkeypatch) -> None:
    evaluation = _evaluation(monkeypatch)
    binding = DataHubGovernanceTrustAuthority(
        clock=lambda: NOW + timedelta(seconds=2)
    ).bind(evaluation)

    replayed = GovernanceTrustBinding.model_validate(binding.model_dump(mode="json"))

    assert replayed == binding
    assert replayed.binding_sha256 == binding.binding_sha256


def test_stale_bundle_cannot_create_governance_trust(monkeypatch) -> None:
    evaluation = _evaluation(monkeypatch)
    authority = DataHubGovernanceTrustAuthority(
        clock=lambda: NOW + timedelta(seconds=301)
    )

    with pytest.raises(
        GovernanceTrustBindingError,
        match="GOVERNANCE_TRUST_EVIDENCE_STALE",
    ):
        authority.bind(evaluation)


def test_expiry_before_artifact_construction_fails_closed(monkeypatch) -> None:
    evaluation = _evaluation(monkeypatch)
    samples = iter(
        (
            NOW + timedelta(seconds=299),
            NOW + timedelta(seconds=301),
        )
    )
    authority = DataHubGovernanceTrustAuthority(clock=lambda: next(samples))

    with pytest.raises(
        GovernanceTrustBindingError,
        match="GOVERNANCE_TRUST_STALE_AT_ISSUE",
    ):
        authority.bind(evaluation)


def test_expiry_after_artifact_construction_fails_closed(monkeypatch) -> None:
    evaluation = _evaluation(monkeypatch)
    samples = iter(
        (
            NOW + timedelta(seconds=299),
            NOW + timedelta(seconds=299, milliseconds=500),
            NOW + timedelta(seconds=301),
        )
    )
    authority = DataHubGovernanceTrustAuthority(clock=lambda: next(samples))

    with pytest.raises(
        GovernanceTrustBindingError,
        match="GOVERNANCE_TRUST_STALE_AT_ISSUE",
    ):
        authority.bind(evaluation)


def test_incomplete_classification_cannot_create_governance_trust(monkeypatch) -> None:
    evaluation = _with_incomplete_diagnosis_classification(_evaluation(monkeypatch))
    authority = DataHubGovernanceTrustAuthority(
        clock=lambda: NOW + timedelta(seconds=2)
    )

    with pytest.raises(
        GovernanceTrustBindingError,
        match="GOVERNANCE_TRUST_REQUIRED_FACT_NOT_TRUSTED",
    ):
        authority.bind(evaluation)


def test_clock_rollback_across_bindings_fails_closed(monkeypatch) -> None:
    evaluation = _evaluation(monkeypatch)
    clock = _MutableClock(NOW + timedelta(seconds=10))
    authority = DataHubGovernanceTrustAuthority(clock=clock)

    first = authority.bind(evaluation)
    assert first.governance_trusted is True

    clock.current = NOW + timedelta(seconds=5)
    with pytest.raises(
        GovernanceTrustBindingError,
        match="GOVERNANCE_TRUST_TIME_ROLLBACK",
    ):
        authority.bind(evaluation)


def test_model_copy_tampered_evaluation_is_revalidated(monkeypatch) -> None:
    evaluation = _evaluation(monkeypatch)
    tampered = evaluation.model_copy(update={"evaluation_sha256": "0" * 64})
    authority = DataHubGovernanceTrustAuthority(
        clock=lambda: NOW + timedelta(seconds=2)
    )

    with pytest.raises(
        GovernanceTrustBindingError,
        match="GOVERNANCE_TRUST_INPUT_INVALID",
    ):
        authority.bind(tampered)
