from __future__ import annotations

from datetime import datetime, timedelta, timezone

from pydantic import SecretStr

from toxicjoin.context.datahub import DataHubSnapshot
from toxicjoin.context.fixture import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.evidence.datahub import build_datahub_evidence_bundle
from toxicjoin.integrations.datahub_mcp import DataHubMcpSettings
from toxicjoin.models import ColumnRef, SensitivityCategory
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.prospective.grammar import DeclaredSnapshotTransition
from toxicjoin.prospective.ppmc import PpmcStatus, build_ppmc_search_config
from toxicjoin.repair import (
    CpccStatus,
    CpccValidationOutcome,
    CpccValidationStage,
    RemediationOperator,
    TrustedSensitiveAggregate,
    build_remediation_action,
    build_remediation_space,
    enumerate_cpcc_candidates,
    run_cpcc,
)
from toxicjoin.repair.validator import DataHubCpccCandidateValidator

OBSERVED_AT = datetime(2026, 7, 25, 15, 0, tzinfo=timezone.utc)
URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.cpcc_full,PROD)"
SUBJECT = ColumnRef(dataset="patients", field_path="customer_id")
WAREHOUSE_A = "a" * 64
WAREHOUSE_B = "b" * 64
COHORT = "c" * 64


def _settings() -> DataHubMcpSettings:
    return DataHubMcpSettings(
        gms_url="https://datahub.example",
        gms_token=SecretStr("cpcc-validator-secret"),
        command="uvx",
        args=("mcp-server-datahub",),
    )


def _snapshot() -> DataHubSnapshot:
    dataset = FixtureDataset(
        urn=URN,
        owner="urn:li:corpuser:cpcc-owner",
        domain="urn:li:domain:privacy",
        fields={
            "customer_id": FixtureField(
                category=SensitivityCategory.STABLE_PSEUDONYM,
                tags=("toxicjoin:stable-pseudonym",),
            ),
            "diagnosis": FixtureField(
                category=SensitivityCategory.SENSITIVE_ATTRIBUTE,
                glossary_terms=("Sensitive Attribute",),
            ),
            "country": FixtureField(
                category=SensitivityCategory.PUBLIC_OR_LOW_RISK,
            ),
        },
    )
    return DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:cpcc-full-v1",
            datasets={"patients": dataset},
        ),
        verified_entities=(URN,),
        field_counts={"patients": 3},
        lineage_sample={"relationships": []},
        discovered_tools=("get_entities", "get_lineage", "list_schema_fields"),
        observed_at=OBSERVED_AT,
    )


def _validator(
    sql: str,
    *,
    snapshot_transitions: tuple[DeclaredSnapshotTransition, ...] = (),
    governance_trusted: bool = True,
) -> DataHubCpccCandidateValidator:
    return DataHubCpccCandidateValidator(
        original_sql=sql,
        task_purpose="cpcc-full-validator-test",
        subject_key=SUBJECT,
        snapshot=_snapshot(),
        datahub_settings=_settings(),
        policy_engine=PolicyEngine(load_policy()),
        principal_id="principal-cpcc",
        agent_id="agent-cpcc",
        cohort_hmac_sha256=COHORT,
        warehouse_snapshot_sha256=WAREHOUSE_A,
        snapshot_transitions=snapshot_transitions,
        validation_time=OBSERVED_AT + timedelta(seconds=30),
        governance_trusted=governance_trusted,
        ppmc_config=build_ppmc_search_config(bound=3, max_states=100),
    )


def _single_candidate(operator: RemediationOperator, **kwargs):
    action = build_remediation_action(operator, **kwargs)
    return enumerate_cpcc_candidates(build_remediation_space((action,)))[0]


def test_full_validator_rebuilds_real_evidence_policy_twin_and_ppmc() -> None:
    sql = "SELECT customer_id, diagnosis FROM patients"
    candidate = _single_candidate(RemediationOperator.REMOVE_STABLE_IDENTIFIER)
    validator = _validator(sql)

    validation = validator(candidate)
    expected_evidence = build_datahub_evidence_bundle(_snapshot(), _settings())

    assert validation.outcome == CpccValidationOutcome.ELIGIBLE_SAFE
    assert validation.failure_stage is None
    assert validation.generated_sql_sha256 is not None
    assert validation.reparsed_plan_sha256 is not None
    assert validation.reground_governance_sha256 is not None
    assert validation.evidence_root_sha256 == expected_evidence.evidence_root_sha256
    assert validation.local_policy_allowed is True
    assert validation.local_policy_decision_sha256 is not None
    assert validation.disclosure_state_sha256 is not None
    assert validation.ppmc_status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND
    assert validation.ppmc_result_sha256 is not None


def test_ppmc_changes_cpcc_selection_when_cheaper_local_allow_is_temporally_unsafe() -> None:
    sql = "SELECT customer_id, diagnosis FROM patients"
    remove_stable = build_remediation_action(RemediationOperator.REMOVE_STABLE_IDENTIFIER)
    remove_sensitive = build_remediation_action(RemediationOperator.REMOVE_SENSITIVE_PROJECTION)
    space = build_remediation_space((remove_stable, remove_sensitive))
    candidates = enumerate_cpcc_candidates(space)
    validator = _validator(
        sql,
        snapshot_transitions=(
            DeclaredSnapshotTransition(
                from_snapshot_sha256=WAREHOUSE_A,
                to_snapshot_sha256=WAREHOUSE_B,
            ),
        ),
    )

    stable_candidate = next(
        candidate
        for candidate in candidates
        if len(candidate.actions) == 1
        and candidate.actions[0].operator == RemediationOperator.REMOVE_STABLE_IDENTIFIER
    )
    sensitive_candidate = next(
        candidate
        for candidate in candidates
        if len(candidate.actions) == 1
        and candidate.actions[0].operator == RemediationOperator.REMOVE_SENSITIVE_PROJECTION
    )
    stable_validation = validator(stable_candidate)
    sensitive_validation = validator(sensitive_candidate)
    result = run_cpcc(remediation_space=space, validator=validator)

    assert stable_validation.local_policy_allowed is True
    assert stable_validation.outcome == CpccValidationOutcome.INELIGIBLE
    assert stable_validation.failure_stage == CpccValidationStage.PPMC
    assert stable_validation.ppmc_status == PpmcStatus.PROSPECTIVE_UNSAFE

    assert sensitive_validation.outcome == CpccValidationOutcome.ELIGIBLE_SAFE
    assert sensitive_validation.ppmc_status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND

    assert result.status == CpccStatus.REPAIR_FOUND
    assert result.selected_candidate == sensitive_candidate
    assert result.selected_candidate.cost.ordering_key > stable_candidate.cost.ordering_key


def test_local_policy_rewrite_is_deterministic_ineligible_not_fail_closed() -> None:
    sql = "SELECT diagnosis FROM patients WHERE customer_id IS NOT NULL"
    candidate = _single_candidate(
        RemediationOperator.AGGREGATE_SENSITIVE,
        field_key=f"{URN}#diagnosis",
        aggregate_operator=TrustedSensitiveAggregate.COUNT,
    )
    validation = _validator(sql)(candidate)

    assert validation.outcome == CpccValidationOutcome.INELIGIBLE
    assert validation.failure_stage == CpccValidationStage.LOCAL_POLICY
    assert validation.local_policy_allowed is False
    assert validation.local_policy_decision_sha256 is not None
    assert validation.evidence_root_sha256 is not None
    assert validation.disclosure_state_sha256 is None
    assert validation.ppmc_result_sha256 is None


def test_untrusted_governance_prevents_candidate_from_being_marked_safe() -> None:
    sql = "SELECT customer_id, diagnosis FROM patients"
    candidate = _single_candidate(RemediationOperator.REMOVE_STABLE_IDENTIFIER)
    validation = _validator(sql, governance_trusted=False)(candidate)

    assert validation.outcome == CpccValidationOutcome.INELIGIBLE
    assert validation.failure_stage == CpccValidationStage.PPMC
    assert validation.local_policy_allowed is True
    assert validation.ppmc_status == PpmcStatus.PROSPECTIVE_UNSAFE
