from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import SecretStr

from toxicjoin.auth import RequestIdentity
from toxicjoin.context.datahub import DataHubSnapshot, DataHubSnapshotContextResolver
from toxicjoin.context.fixture import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.disclosure.composition import is_protected_release
from toxicjoin.disclosure.models import (
    DisclosureComposition,
    DisclosureScope,
    compute_scope_sha256,
)
from toxicjoin.disclosure.semantic import (
    build_semantic_release_from_resolution,
    resolve_governed_subject_domain,
)
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.evidence.datahub import build_datahub_evidence_bundle
from toxicjoin.evidence.derivation import validate_datahub_evidence_derivations
from toxicjoin.execute.proof_binding import (
    ExecutionPrivacyProofBindingError,
    verify_execution_privacy_proof,
)
from toxicjoin.integrations.datahub_mcp import DataHubMcpSettings
from toxicjoin.models import ColumnRef, SensitivityCategory
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.proofs import (
    PreExecutionProofError,
    build_preexecution_privacy_proof,
    compute_preexecution_privacy_proof_hmac,
    compute_preexecution_privacy_proof_sha256,
    verify_preexecution_privacy_proof,
)
from toxicjoin.prospective.forbidden import (
    build_forbidden_predicate_policy,
    build_governance_trust_binding,
)
from toxicjoin.prospective.grammar import (
    build_future_action_grammar_context,
    instantiate_future_action_grammar,
)
from toxicjoin.prospective.policy_oracle import (
    PolicyEngineLocalOracle,
    build_policy_oracle_governance_context,
)
from toxicjoin.prospective.ppmc import (
    PpmcStatus,
    build_ppmc_search_config,
    check_prospective_privacy,
    compute_ppmc_result_sha256,
)
from toxicjoin.prospective.twin import build_disclosure_state
from toxicjoin.sql import analyze_sql


OBSERVED_AT = datetime(2026, 7, 27, 6, 0, tzinfo=timezone.utc)
ISSUED_AT = OBSERVED_AT + timedelta(seconds=30)
KEY = b"proof-profile-integrity-key-32-bytes!!"
URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.proof_profile,PROD)"
SQL = "SELECT country FROM patients WHERE customer_id IS NOT NULL"
PURPOSE = "preexecution-proof-profile-test"
SUBJECT = ColumnRef(dataset="patients", field_path="customer_id")
WAREHOUSE = "a" * 64
COHORT = "c" * 64
IDENTITY = RequestIdentity(
    principal_id="principal-proof-profile",
    credential_id="credential-proof-profile",
    agent_id="agent-proof-profile",
    session_id="session-proof-profile",
)


def _settings() -> DataHubMcpSettings:
    return DataHubMcpSettings(
        gms_url="https://datahub.example",
        gms_token=SecretStr("proof-profile-test-secret"),
        command="uvx",
        args=("mcp-server-datahub",),
    )


def _snapshot() -> DataHubSnapshot:
    return DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:preexecution-proof-profile-v1",
            datasets={
                "patients": FixtureDataset(
                    urn=URN,
                    owner="urn:li:corpuser:proof-profile-owner",
                    domain="urn:li:domain:privacy",
                    fields={
                        "customer_id": FixtureField(
                            category=SensitivityCategory.STABLE_PSEUDONYM,
                            tags=("toxicjoin:stable-pseudonym",),
                        ),
                        "country": FixtureField(
                            category=SensitivityCategory.PUBLIC_OR_LOW_RISK,
                            tags=("toxicjoin:public-or-low-risk",),
                        ),
                    },
                )
            },
        ),
        verified_entities=(URN,),
        field_counts={"patients": 2},
        lineage_sample={"relationships": []},
        discovered_tools=("get_entities", "get_lineage", "list_schema_fields"),
        observed_at=OBSERVED_AT,
    )


def _artifacts():
    snapshot = _snapshot()
    settings = _settings()
    resolver = DataHubSnapshotContextResolver(
        snapshot,
        max_age_seconds=300,
        clock=lambda: ISSUED_AT,
    )
    plan = analyze_sql(SQL)
    context, governance_binding = resolver.resolve_with_governance_binding(plan)
    assert context.failures == ()

    bundle = build_datahub_evidence_bundle(snapshot, settings, max_age_seconds=300)
    validation = validate_datahub_evidence_derivations(
        bundle,
        snapshot,
        settings,
        max_age_seconds=300,
        now=ISSUED_AT,
    )

    policy_engine = PolicyEngine(load_policy())
    semantic = build_semantic_release_from_resolution(plan, context)
    subject = resolve_governed_subject_domain(
        snapshot.catalog,
        subject_key=SUBJECT,
        source_datasets=plan.source_datasets,
    )
    scope = DisclosureScope(
        principal_id=IDENTITY.principal_id,
        agent_id=IDENTITY.agent_id,
        subject=subject,
        scope_sha256=compute_scope_sha256(
            principal_id=IDENTITY.principal_id,
            agent_id=IDENTITY.agent_id,
            subject_namespace_sha256=subject.namespace_sha256,
        ),
    )
    composition = DisclosureComposition(
        protected_release=is_protected_release(semantic),
        release_family_sha256=semantic.semantic_sha256,
        cohort_hmac_sha256=COHORT,
    )
    governance_sha256 = canonical_json_sha256(
        governance_binding.model_dump(mode="json")
    )
    state = build_disclosure_state(
        scope=scope,
        audit_history=(),
        candidate_semantic=semantic,
        candidate_composition=composition,
        purpose_commitment_sha256=canonical_json_sha256(
            {"task_purpose": PURPOSE}
        ),
        governance_commitment_sha256=governance_sha256,
        evidence_root_sha256=bundle.evidence_root_sha256,
        warehouse_snapshot_sha256=WAREHOUSE,
    )
    grammar = instantiate_future_action_grammar(
        build_future_action_grammar_context(
            base_state=state,
            base_semantic=semantic,
            base_composition=composition,
        )
    )
    oracle_governance = build_policy_oracle_governance_context(
        context.projected_context + context.all_referenced_context
    )
    oracle = PolicyEngineLocalOracle(policy_engine, grammar, oracle_governance)
    trust_binding = build_governance_trust_binding(
        governance_commitment_sha256=governance_sha256,
        trusted=True,
        trust_evidence_sha256=validation.validation_sha256,
    )
    ppmc = check_prospective_privacy(
        initial_state=state,
        grammar=grammar,
        forbidden_policy=build_forbidden_predicate_policy(
            minimum_group_size=policy_engine.config.minimum_group_size
        ),
        governance_binding=trust_binding,
        local_oracle=oracle,
        config=build_ppmc_search_config(bound=3, max_states=100),
    )
    return {
        "context": context,
        "governance_binding": governance_binding,
        "bundle": bundle,
        "validation": validation,
        "policy_engine": policy_engine,
        "state": state,
        "grammar": grammar,
        "oracle": oracle,
        "trust_binding": trust_binding,
        "ppmc": ppmc,
    }


def _weak_bound_ppmc(artifacts):
    return check_prospective_privacy(
        initial_state=artifacts["state"],
        grammar=artifacts["grammar"],
        forbidden_policy=build_forbidden_predicate_policy(
            minimum_group_size=artifacts["policy_engine"].config.minimum_group_size
        ),
        governance_binding=artifacts["trust_binding"],
        local_oracle=artifacts["oracle"],
        config=build_ppmc_search_config(bound=0, max_states=100),
    )


def _build_proof_with_ppmc(artifacts, ppmc_result):
    return build_preexecution_privacy_proof(
        identity=IDENTITY,
        task_purpose=PURPOSE,
        sql=SQL,
        subject_key=SUBJECT,
        context=artifacts["context"],
        governance_binding=artifacts["governance_binding"],
        evidence_bundle=artifacts["bundle"],
        evidence_validation=artifacts["validation"],
        policy_engine=artifacts["policy_engine"],
        state=artifacts["state"],
        grammar=artifacts["grammar"],
        governance_trust_binding=artifacts["trust_binding"],
        ppmc_result=ppmc_result,
        integrity_key=KEY,
        issued_at=ISSUED_AT,
    )


def _proof():
    artifacts = _artifacts()
    assert artifacts["ppmc"].status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND
    return _build_proof_with_ppmc(artifacts, artifacts["ppmc"]), artifacts


def _resign(proof, **updates):
    unsigned = proof.model_copy(
        update={
            **updates,
            "privacy_proof_sha256": "0" * 64,
            "integrity_hmac_sha256": "0" * 64,
        }
    )
    with_content = unsigned.model_copy(
        update={
            "privacy_proof_sha256": compute_preexecution_privacy_proof_sha256(unsigned)
        }
    )
    return with_content.model_copy(
        update={
            "integrity_hmac_sha256": compute_preexecution_privacy_proof_hmac(
                with_content,
                integrity_key=KEY,
            )
        }
    )


def _resign_with_weak_bound(proof):
    weak_config = build_ppmc_search_config(
        bound=0,
        max_states=proof.ppmc_max_states,
    )
    return _resign(
        proof,
        ppmc_bound=0,
        ppmc_config_sha256=weak_config.config_sha256,
    )


def test_preexecution_builder_rejects_weak_ppmc_bound() -> None:
    artifacts = _artifacts()
    weak_ppmc = _weak_bound_ppmc(artifacts)
    assert weak_ppmc.status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND
    assert weak_ppmc.bound == 0

    with pytest.raises(PreExecutionProofError, match="PROOF_PPMC_PROFILE_INVALID"):
        _build_proof_with_ppmc(artifacts, weak_ppmc)


def test_preexecution_builder_rejects_rebound_ppmc_config_hash() -> None:
    artifacts = _artifacts()
    ppmc = artifacts["ppmc"]
    provisional = ppmc.model_copy(
        update={
            "config_sha256": "f" * 64,
            "result_sha256": "0" * 64,
        }
    )
    forged = provisional.model_copy(
        update={"result_sha256": compute_ppmc_result_sha256(provisional)}
    )

    with pytest.raises(PreExecutionProofError, match="PROOF_PPMC_PROFILE_INVALID"):
        _build_proof_with_ppmc(artifacts, forged)


def test_proof_verifier_rejects_valid_hmac_with_weak_ppmc_profile() -> None:
    proof, _ = _proof()
    weak_proof = _resign_with_weak_bound(proof)

    result = verify_preexecution_privacy_proof(
        weak_proof,
        integrity_key=KEY,
        now=ISSUED_AT,
    )

    assert result.valid is False
    assert tuple(failure.value for failure in result.failures) == (
        "PROOF_PPMC_PROFILE_INVALID",
    )


def test_proof_verifier_rejects_valid_hmac_with_rebound_ppmc_config() -> None:
    proof, _ = _proof()
    forged = _resign(proof, ppmc_config_sha256="e" * 64)

    result = verify_preexecution_privacy_proof(
        forged,
        integrity_key=KEY,
        now=ISSUED_AT,
    )

    assert result.valid is False
    assert tuple(failure.value for failure in result.failures) == (
        "PROOF_PPMC_PROFILE_INVALID",
    )


def test_execution_verifier_rejects_valid_hmac_with_weak_ppmc_profile() -> None:
    proof, artifacts = _proof()
    weak_proof = _resign_with_weak_bound(proof)
    plan = analyze_sql(SQL)
    decision = artifacts["policy_engine"].evaluate(
        artifacts["context"].to_policy_input(
            task_purpose=PURPOSE,
            query_plan=plan,
            subject_key=SUBJECT,
        )
    )

    with pytest.raises(
        ExecutionPrivacyProofBindingError,
        match="AUTH_PRIVACY_PROOF_PROFILE_INVALID",
    ):
        verify_execution_privacy_proof(
            weak_proof,
            integrity_key=KEY,
            now_epoch_seconds=ISSUED_AT.timestamp(),
            sql=SQL,
            query_plan=plan,
            resolution=artifacts["context"],
            governance_binding=artifacts["governance_binding"],
            policy_engine=artifacts["policy_engine"],
            policy_decision=decision,
            task_purpose=PURPOSE,
            identity=IDENTITY,
            subject_key=SUBJECT,
        )
