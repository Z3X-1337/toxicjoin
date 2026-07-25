from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from toxicjoin.auth import RequestIdentity, bind_request_identity
from toxicjoin.context.datahub import DataHubSnapshot, DataHubSnapshotContextResolver
from toxicjoin.context.fixture import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.execute import (
    ExecutionAuthorizationError,
    ExecutionAuthorizer,
    ProofBoundExecutionAuthorization,
    ProofBoundExecutionAuthorizer,
)
from toxicjoin.models import ColumnRef, SensitivityCategory
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.proofs import (
    PreExecutionPrivacyProof,
    compute_preexecution_privacy_proof_hmac,
    compute_preexecution_privacy_proof_sha256,
)
from toxicjoin.sql import analyze_sql

AUTH_KEY = b"proof-bound-execution-auth-key-32-bytes!!"
PROOF_KEY = b"proof-bound-proof-integrity-key-32-bytes!!"
NOW = 1_800_000_000.0
NOW_DT = datetime.fromtimestamp(NOW, tz=timezone.utc)
URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.proof_auth,PROD)"
SQL = "SELECT c.coarse_region FROM customers c LIMIT 5"
TASK = "List coarse regions for a bounded preview"
SUBJECT = ColumnRef(dataset="customers", field_path="customer_id", alias="c")
IDENTITY = RequestIdentity(
    principal_id="principal-proof-auth",
    credential_id="credential-proof-auth",
    agent_id="agent-proof-auth",
    session_id="session-proof-auth",
)
DUMMY = "d" * 64


def _snapshot() -> DataHubSnapshot:
    catalog = FixtureCatalog(
        version="datahub-mcp:proof-auth-v1",
        datasets={
            "customers": FixtureDataset(
                urn=URN,
                owner="urn:li:corpuser:proof-auth-owner",
                domain="urn:li:domain:privacy",
                fields={
                    "customer_id": FixtureField(
                        category=SensitivityCategory.STABLE_PSEUDONYM,
                        tags=("toxicjoin:stable-pseudonym",),
                    ),
                    "coarse_region": FixtureField(
                        category=SensitivityCategory.PUBLIC_OR_LOW_RISK,
                        tags=("toxicjoin:public-or-low-risk",),
                    ),
                },
            )
        },
    )
    return DataHubSnapshot(
        catalog=catalog,
        verified_entities=(URN,),
        field_counts={"customers": 2},
        lineage_sample={"relationships": []},
        discovered_tools=("get_entities", "get_lineage", "list_schema_fields"),
        observed_at=NOW_DT - timedelta(seconds=30),
    )


def _runtime():
    resolver = DataHubSnapshotContextResolver(
        _snapshot(),
        max_age_seconds=300,
        clock=lambda: NOW_DT,
    )
    engine = PolicyEngine(load_policy())
    plan = analyze_sql(SQL)
    resolution, binding = resolver.resolve_with_governance_binding(plan)
    decision = engine.evaluate(
        resolution.to_policy_input(
            task_purpose=TASK,
            query_plan=plan,
            subject_key=SUBJECT,
        )
    )
    return resolver, engine, plan, resolution, binding, decision


def _sealed_proof(*, transcript_sha256: str = DUMMY) -> PreExecutionPrivacyProof:
    _, engine, plan, resolution, binding, decision = _runtime()
    proof = PreExecutionPrivacyProof(
        issued_at=NOW_DT - timedelta(seconds=1),
        expires_at=NOW_DT + timedelta(seconds=4),
        request_identity_sha256=canonical_json_sha256(
            IDENTITY.model_dump(mode="json")
        ),
        task_purpose_sha256=hashlib.sha256(TASK.encode("utf-8")).hexdigest(),
        purpose_commitment_sha256=DUMMY,
        subject_key_sha256=canonical_json_sha256(SUBJECT.model_dump(mode="json")),
        sql_sha256=hashlib.sha256(SQL.encode("utf-8")).hexdigest(),
        query_plan_sha256=canonical_json_sha256(plan.model_dump(mode="json")),
        governance_context_sha256=canonical_json_sha256(
            resolution.model_dump(mode="json")
        ),
        governance_binding_sha256=canonical_json_sha256(
            binding.model_dump(mode="json")
        ),
        evidence_root_sha256=DUMMY,
        evidence_validation_sha256=DUMMY,
        disclosure_state_sha256=DUMMY,
        warehouse_snapshot_sha256=DUMMY,
        policy_sha256=canonical_json_sha256(engine.config.model_dump(mode="json")),
        policy_decision_sha256=canonical_json_sha256(
            decision.model_dump(mode="json")
        ),
        grammar_sha256=DUMMY,
        ppmc_config_sha256=DUMMY,
        ppmc_forbidden_policy_sha256=DUMMY,
        ppmc_governance_binding_sha256=DUMMY,
        ppmc_search_transcript_sha256=transcript_sha256,
        ppmc_result_sha256=DUMMY,
        ppmc_bound=3,
        ppmc_max_states=100,
        privacy_proof_sha256="0" * 64,
        integrity_hmac_sha256="0" * 64,
    )
    content_sha256 = compute_preexecution_privacy_proof_sha256(proof)
    proof = proof.model_copy(update={"privacy_proof_sha256": content_sha256})
    return proof.model_copy(
        update={
            "integrity_hmac_sha256": compute_preexecution_privacy_proof_hmac(
                proof,
                integrity_key=PROOF_KEY,
            )
        }
    )


def _authorizer() -> ProofBoundExecutionAuthorizer:
    resolver, engine, *_ = _runtime()
    return ProofBoundExecutionAuthorizer(
        context_resolver=resolver,
        policy_engine=engine,
        privacy_proof_integrity_key=PROOF_KEY,
        secret_key=AUTH_KEY,
        ttl_seconds=5,
        clock=lambda: NOW,
    )


def test_proof_bound_authorization_binds_exact_proof_and_caps_ttl() -> None:
    authorizer = _authorizer()
    proof = _sealed_proof()

    with bind_request_identity(IDENTITY):
        authorization = authorizer.issue(
            SQL,
            task_purpose=TASK,
            subject_key=SUBJECT,
            privacy_proof=proof,
        )
        plan = authorizer.verify_and_consume(
            authorization,
            SQL,
            task_purpose=TASK,
            subject_key=SUBJECT,
            privacy_proof=proof,
        )

    assert isinstance(authorization, ProofBoundExecutionAuthorization)
    assert authorization.privacy_proof_sha256 == proof.privacy_proof_sha256
    assert authorization.expires_at == pytest.approx(proof.expires_at.timestamp())
    assert authorization.expires_at < authorization.issued_at + 5
    assert {ref.key for ref in plan.projected_columns} == {"customers.coarse_region"}


def test_proof_is_required_at_issue_and_consume() -> None:
    authorizer = _authorizer()
    proof = _sealed_proof()

    with bind_request_identity(IDENTITY):
        with pytest.raises(ExecutionAuthorizationError, match="AUTH_PRIVACY_PROOF_REQUIRED"):
            authorizer.issue(SQL, task_purpose=TASK, subject_key=SUBJECT)

        authorization = authorizer.issue(
            SQL,
            task_purpose=TASK,
            subject_key=SUBJECT,
            privacy_proof=proof,
        )
        with pytest.raises(ExecutionAuthorizationError, match="AUTH_PRIVACY_PROOF_REQUIRED"):
            authorizer.verify_and_consume(
                authorization,
                SQL,
                task_purpose=TASK,
                subject_key=SUBJECT,
            )


def test_tampered_proof_is_rejected_before_authorization_issue() -> None:
    authorizer = _authorizer()
    proof = _sealed_proof()
    tampered = proof.model_copy(update={"sql_sha256": "f" * 64})

    with bind_request_identity(IDENTITY):
        with pytest.raises(ExecutionAuthorizationError, match="AUTH_PRIVACY_PROOF_INVALID"):
            authorizer.issue(
                SQL,
                task_purpose=TASK,
                subject_key=SUBJECT,
                privacy_proof=tampered,
            )


def test_runtime_binding_mismatch_is_rejected_even_for_valid_hmac_proof() -> None:
    authorizer = _authorizer()
    proof = _sealed_proof()
    payload = proof.model_dump(mode="json")
    payload["task_purpose_sha256"] = "e" * 64
    payload["privacy_proof_sha256"] = compute_preexecution_privacy_proof_sha256(payload)
    payload["integrity_hmac_sha256"] = compute_preexecution_privacy_proof_hmac(
        payload,
        integrity_key=PROOF_KEY,
    )
    different = PreExecutionPrivacyProof.model_validate(payload)

    with bind_request_identity(IDENTITY):
        with pytest.raises(
            ExecutionAuthorizationError,
            match="AUTH_PRIVACY_PROOF_TASK_MISMATCH",
        ):
            authorizer.issue(
                SQL,
                task_purpose=TASK,
                subject_key=SUBJECT,
                privacy_proof=different,
            )


def test_swapping_another_valid_proof_after_issue_is_rejected() -> None:
    authorizer = _authorizer()
    proof = _sealed_proof()
    other = _sealed_proof(transcript_sha256="e" * 64)
    assert other.privacy_proof_sha256 != proof.privacy_proof_sha256

    with bind_request_identity(IDENTITY):
        authorization = authorizer.issue(
            SQL,
            task_purpose=TASK,
            subject_key=SUBJECT,
            privacy_proof=proof,
        )
        with pytest.raises(
            ExecutionAuthorizationError,
            match="AUTH_PRIVACY_PROOF_BINDING_MISMATCH",
        ):
            authorizer.verify_and_consume(
                authorization,
                SQL,
                task_purpose=TASK,
                subject_key=SUBJECT,
                privacy_proof=other,
            )


def test_privacy_proof_commitment_is_covered_by_authorization_mac() -> None:
    authorizer = _authorizer()
    proof = _sealed_proof()

    with bind_request_identity(IDENTITY):
        authorization = authorizer.issue(
            SQL,
            task_purpose=TASK,
            subject_key=SUBJECT,
            privacy_proof=proof,
        )
        forged = authorization.model_copy(
            update={"privacy_proof_sha256": "0" * 64}
        )
        with pytest.raises(ExecutionAuthorizationError, match="AUTH_INVALID_MAC"):
            authorizer.verify_and_consume(
                forged,
                SQL,
                task_purpose=TASK,
                subject_key=SUBJECT,
                privacy_proof=proof,
            )


def test_legacy_authorizer_remains_available_for_staged_migration() -> None:
    resolver, engine, *_ = _runtime()
    legacy = ExecutionAuthorizer(
        context_resolver=resolver,
        policy_engine=engine,
        secret_key=AUTH_KEY,
        ttl_seconds=5,
        clock=lambda: NOW,
    )

    with bind_request_identity(IDENTITY):
        authorization = legacy.issue(SQL, task_purpose=TASK, subject_key=SUBJECT)
        plan = legacy.verify_and_consume(
            authorization,
            SQL,
            task_purpose=TASK,
            subject_key=SUBJECT,
        )

    assert not hasattr(authorization, "privacy_proof_sha256")
    assert {ref.key for ref in plan.projected_columns} == {"customers.coarse_region"}


def test_proof_bound_authorizer_rejects_short_proof_key() -> None:
    resolver, engine, *_ = _runtime()
    with pytest.raises(ValueError, match="privacy proof integrity key"):
        ProofBoundExecutionAuthorizer(
            context_resolver=resolver,
            policy_engine=engine,
            privacy_proof_integrity_key=b"too-short",
            secret_key=AUTH_KEY,
            clock=lambda: NOW,
        )
