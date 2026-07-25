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
from toxicjoin.integrations.datahub_mcp import DataHubMcpSettings
from toxicjoin.models import ColumnRef, SensitivityCategory
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.proofs import (
    PreExecutionProofError,
    ProofVerificationFailure,
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
)
from toxicjoin.prospective.twin import build_disclosure_state
from toxicjoin.sql import analyze_sql

OBSERVED_AT = datetime(2026, 7, 25, 12, 0, tzinfo=timezone.utc)
ISSUED_AT = OBSERVED_AT + timedelta(seconds=30)
KEY = b"proof-integrity-key-32-bytes-minimum!!"
WRONG_KEY = b"different-proof-key-32-bytes-minimum!"
URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.proof,PROD)"
SQL = "SELECT country FROM patients WHERE customer_id IS NOT NULL"
PURPOSE = "preexecution-proof-test"
SUBJECT = ColumnRef(dataset="patients", field_path="customer_id")
WAREHOUSE = "a" * 64
COHORT = "c" * 64
IDENTITY = RequestIdentity(
    principal_id="principal-proof",
    credential_id="credential-proof",
    agent_id="agent-proof",
    session_id="session-proof",
)


def _settings() -> DataHubMcpSettings:
    return DataHubMcpSettings(
        gms_url="https://datahub.example",
        gms_token=SecretStr("proof-test-secret"),
        command="uvx",
        args=("mcp-server-datahub",),
    )


def _snapshot() -> DataHubSnapshot:
    return DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:preexecution-proof-v1",
            datasets={
                "patients": FixtureDataset(
                    urn=URN,
                    owner="urn:li:corpuser:proof-owner",
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


def _artifacts(*, trusted: bool = True):
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
        trusted=trusted,
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
        "trust_binding": trust_binding,
        "ppmc": ppmc,
    }


def _proof():
    artifacts = _artifacts()
    assert artifacts["ppmc"].status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND
    proof = build_preexecution_privacy_proof(
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
        ppmc_result=artifacts["ppmc"],
        integrity_key=KEY,
        issued_at=ISSUED_AT,
    )
    return proof, artifacts


def test_build_and_verify_preexecution_privacy_proof() -> None:
    proof, artifacts = _proof()

    result = verify_preexecution_privacy_proof(
        proof,
        integrity_key=KEY,
        now=ISSUED_AT + timedelta(seconds=1),
    )

    assert result.valid is True
    assert result.failures == ()
    assert result.privacy_proof_sha256 == proof.privacy_proof_sha256
    assert proof.ppmc_status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND.value
    assert proof.ppmc_result_sha256 == artifacts["ppmc"].result_sha256
    assert proof.disclosure_state_sha256 == artifacts["state"].state_sha256
    assert proof.evidence_root_sha256 == artifacts["bundle"].evidence_root_sha256
    assert proof.repair is None
    assert proof.expires_at - proof.issued_at <= timedelta(seconds=60)


def test_tamper_is_detected_by_content_hash_and_hmac() -> None:
    proof, _ = _proof()
    payload = proof.model_dump(mode="json")
    payload["sql_sha256"] = "f" * 64

    result = verify_preexecution_privacy_proof(
        payload,
        integrity_key=KEY,
        now=ISSUED_AT + timedelta(seconds=1),
    )

    assert result.valid is False
    assert result.failures == (
        ProofVerificationFailure.CONTENT_HASH_MISMATCH,
        ProofVerificationFailure.HMAC_MISMATCH,
    )


def test_recomputed_public_content_hash_still_requires_integrity_key() -> None:
    proof, _ = _proof()
    payload = proof.model_dump(mode="json")
    payload["sql_sha256"] = "e" * 64
    payload["privacy_proof_sha256"] = compute_preexecution_privacy_proof_sha256(payload)

    result = verify_preexecution_privacy_proof(
        payload,
        integrity_key=KEY,
        now=ISSUED_AT + timedelta(seconds=1),
    )

    assert result.valid is False
    assert result.failures == (ProofVerificationFailure.HMAC_MISMATCH,)


def test_wrong_integrity_key_is_rejected() -> None:
    proof, _ = _proof()

    result = verify_preexecution_privacy_proof(
        proof,
        integrity_key=WRONG_KEY,
        now=ISSUED_AT + timedelta(seconds=1),
    )

    assert result.failures == (ProofVerificationFailure.HMAC_MISMATCH,)


def test_expired_proof_is_rejected_even_with_valid_hmac() -> None:
    proof, _ = _proof()

    result = verify_preexecution_privacy_proof(
        proof,
        integrity_key=KEY,
        now=proof.expires_at,
    )

    assert result.failures == (ProofVerificationFailure.EXPIRED,)


def test_not_yet_valid_proof_is_rejected() -> None:
    proof, _ = _proof()

    result = verify_preexecution_privacy_proof(
        proof,
        integrity_key=KEY,
        now=proof.issued_at - timedelta(seconds=2),
    )

    assert result.failures == (ProofVerificationFailure.NOT_YET_VALID,)


def test_schema_failure_is_machine_readable() -> None:
    result = verify_preexecution_privacy_proof(
        {"schema_version": "9.9"},
        integrity_key=KEY,
        now=ISSUED_AT,
    )

    assert result.valid is False
    assert result.failures == (ProofVerificationFailure.SCHEMA_INVALID,)


def test_builder_refuses_ppmc_result_with_untrusted_governance() -> None:
    artifacts = _artifacts(trusted=False)
    assert artifacts["ppmc"].status == PpmcStatus.PROSPECTIVE_UNSAFE

    with pytest.raises(PreExecutionProofError, match="PROOF_PPMC_NOT_SAFE"):
        build_preexecution_privacy_proof(
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
            ppmc_result=artifacts["ppmc"],
            integrity_key=KEY,
            issued_at=ISSUED_AT,
        )


def test_builder_refuses_identity_scope_substitution() -> None:
    artifacts = _artifacts()
    substituted = IDENTITY.model_copy(update={"principal_id": "other-principal"})

    with pytest.raises(PreExecutionProofError, match="PROOF_SCOPE_PRINCIPAL_MISMATCH"):
        build_preexecution_privacy_proof(
            identity=substituted,
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
            ppmc_result=artifacts["ppmc"],
            integrity_key=KEY,
            issued_at=ISSUED_AT,
        )


def test_builder_refuses_stale_governance_and_evidence() -> None:
    artifacts = _artifacts()

    with pytest.raises(PreExecutionProofError, match="PROOF_GOVERNANCE_STALE"):
        build_preexecution_privacy_proof(
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
            ppmc_result=artifacts["ppmc"],
            integrity_key=KEY,
            issued_at=OBSERVED_AT + timedelta(seconds=301),
        )


def test_hmac_has_explicit_domain_separation() -> None:
    proof, _ = _proof()
    normal = compute_preexecution_privacy_proof_hmac(proof, integrity_key=KEY)
    payload = proof.model_dump(mode="json")
    payload["integrity_hmac_sha256"] = "0" * 64

    # A plain HMAC over the canonical artifact must not equal the domain-separated proof MAC.
    import hashlib
    import hmac
    import json

    plain = hmac.new(
        KEY,
        json.dumps(
            {k: v for k, v in payload.items() if k != "integrity_hmac_sha256"},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    assert normal != plain
