from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from toxicjoin.auth import RequestIdentity, bind_request_identity
from toxicjoin.context.datahub import DataHubSnapshot, DataHubSnapshotContextResolver
from toxicjoin.context.fixture import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.execute import ExecutionAuthorizationError, ProofBoundExecutionAuthorizer
from toxicjoin.models import ColumnRef, SensitivityCategory
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.proofs import (
    AgentPpmcProofBinding,
    PreExecutionPrivacyProof,
    compute_agent_ppmc_proof_binding_sha256,
    compute_agent_ppmc_provenance_hmac,
    compute_preexecution_privacy_proof_hmac,
    compute_preexecution_privacy_proof_sha256,
)
from toxicjoin.prospective.ppmc import build_ppmc_search_config
from toxicjoin.sql import analyze_sql

AUTH_KEY = b"agent-proof-auth-key-distinct-32-bytes!!"
PROOF_KEY = b"agent-proof-integrity-key-distinct-32!!"
PROVENANCE_KEY = b"agent-proof-provenance-key-distinct-32!!"
NOW = 1_800_100_000.0
NOW_DT = datetime.fromtimestamp(NOW, tz=timezone.utc)
URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.agent_proof,PROD)"
SQL = "SELECT coarse_region FROM customers LIMIT 5"
TASK = "List coarse regions for a bounded preview"
SUBJECT = ColumnRef(dataset="customers", field_path="customer_id")
IDENTITY = RequestIdentity(
    principal_id="principal-agent-proof",
    credential_id="credential-agent-proof",
    agent_id="agent-agent-proof",
    session_id="session-agent-proof",
)
ALT_IDENTITY = RequestIdentity(
    principal_id=IDENTITY.principal_id,
    credential_id="credential-agent-proof-alt",
    agent_id=IDENTITY.agent_id,
    session_id="session-agent-proof-alt",
)
DUMMY = "d" * 64


def _runtime():
    snapshot = DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:agent-proof-v1",
            datasets={
                "customers": FixtureDataset(
                    urn=URN,
                    owner="urn:li:corpuser:agent-proof-owner",
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
        ),
        verified_entities=(URN,),
        field_counts={"customers": 2},
        lineage_sample={"relationships": []},
        discovered_tools=("get_entities", "get_lineage", "list_schema_fields"),
        observed_at=NOW_DT - timedelta(seconds=30),
    )
    resolver = DataHubSnapshotContextResolver(
        snapshot,
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


def _generic_sealed_proof() -> PreExecutionPrivacyProof:
    _, engine, plan, resolution, binding, decision = _runtime()
    config = build_ppmc_search_config(bound=3, max_states=100)
    proof = PreExecutionPrivacyProof(
        issued_at=NOW_DT - timedelta(seconds=1),
        expires_at=NOW_DT + timedelta(seconds=4),
        request_identity_sha256=canonical_json_sha256(IDENTITY.model_dump(mode="json")),
        task_purpose_sha256=hashlib.sha256(TASK.encode("utf-8")).hexdigest(),
        purpose_commitment_sha256=DUMMY,
        subject_key_sha256=canonical_json_sha256(SUBJECT.model_dump(mode="json")),
        sql_sha256=hashlib.sha256(SQL.encode("utf-8")).hexdigest(),
        query_plan_sha256=canonical_json_sha256(plan.model_dump(mode="json")),
        governance_context_sha256=canonical_json_sha256(resolution.model_dump(mode="json")),
        governance_binding_sha256=canonical_json_sha256(binding.model_dump(mode="json")),
        evidence_root_sha256=DUMMY,
        evidence_validation_sha256=DUMMY,
        disclosure_state_sha256=DUMMY,
        warehouse_snapshot_sha256=DUMMY,
        policy_sha256=canonical_json_sha256(engine.config.model_dump(mode="json")),
        policy_decision_sha256=canonical_json_sha256(decision.model_dump(mode="json")),
        grammar_sha256=DUMMY,
        ppmc_config_sha256=config.config_sha256,
        ppmc_forbidden_policy_sha256=DUMMY,
        ppmc_governance_binding_sha256=DUMMY,
        ppmc_search_transcript_sha256=DUMMY,
        ppmc_result_sha256=DUMMY,
        ppmc_bound=3,
        ppmc_max_states=100,
        privacy_proof_sha256="0" * 64,
        integrity_hmac_sha256="0" * 64,
    )
    content = compute_preexecution_privacy_proof_sha256(proof)
    proof = proof.model_copy(update={"privacy_proof_sha256": content})
    return proof.model_copy(
        update={
            "integrity_hmac_sha256": compute_preexecution_privacy_proof_hmac(
                proof,
                integrity_key=PROOF_KEY,
            )
        }
    )


def _binding_payload(proof: PreExecutionPrivacyProof, *, ppmc_result_sha256: str) -> dict:
    return {
        "agent_proposal_sha256": "1" * 64,
        "agent_evaluation_sha256": "2" * 64,
        "agent_ppmc_evaluation_sha256": "3" * 64,
        "f6_clearance_sha256": "4" * 64,
        "sql_sha256": proof.sql_sha256,
        "query_plan_sha256": proof.query_plan_sha256,
        "task_purpose_sha256": proof.task_purpose_sha256,
        "purpose_commitment_sha256": proof.purpose_commitment_sha256,
        "subject_key_sha256": proof.subject_key_sha256,
        "governance_context_sha256": proof.governance_context_sha256,
        "governance_binding_sha256": proof.governance_binding_sha256,
        "evidence_root_sha256": proof.evidence_root_sha256,
        "evidence_validation_sha256": proof.evidence_validation_sha256,
        "policy_sha256": proof.policy_sha256,
        "policy_decision_sha256": proof.policy_decision_sha256,
        "disclosure_state_sha256": proof.disclosure_state_sha256,
        "grammar_sha256": proof.grammar_sha256,
        "ppmc_governance_binding_sha256": proof.ppmc_governance_binding_sha256,
        "ppmc_result_sha256": ppmc_result_sha256,
        "evidence_expires_at": proof.expires_at,
    }


def _reseal_with_provenance(
    proof: PreExecutionPrivacyProof,
    *,
    ppmc_result_sha256: str,
    authority_key: bytes,
) -> PreExecutionPrivacyProof:
    binding_payload = _binding_payload(proof, ppmc_result_sha256=ppmc_result_sha256)
    provisional = AgentPpmcProofBinding.model_construct(
        **binding_payload,
        binding_sha256="0" * 64,
        authority_hmac_sha256="0" * 64,
    )
    binding_sha256 = compute_agent_ppmc_proof_binding_sha256(provisional)
    unsigned_provenance = AgentPpmcProofBinding.model_construct(
        **binding_payload,
        binding_sha256=binding_sha256,
        authority_hmac_sha256="0" * 64,
    )
    provenance = AgentPpmcProofBinding(
        **binding_payload,
        binding_sha256=binding_sha256,
        authority_hmac_sha256=compute_agent_ppmc_provenance_hmac(
            unsigned_provenance,
            integrity_key=authority_key,
        ),
    )
    unsigned = proof.model_copy(
        update={
            "agent_ppmc_provenance": provenance,
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
                integrity_key=PROOF_KEY,
            )
        }
    )


def _reseal_for_identity(
    proof: PreExecutionPrivacyProof,
    identity: RequestIdentity,
) -> PreExecutionPrivacyProof:
    unsigned = proof.model_copy(
        update={
            "request_identity_sha256": canonical_json_sha256(identity.model_dump(mode="json")),
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
        agent_provenance_integrity_key=PROVENANCE_KEY,
        secret_key=AUTH_KEY,
        ttl_seconds=5,
        clock=lambda: NOW,
    )


def test_public_proof_bound_authorizer_rejects_generic_proof_without_agent_provenance() -> None:
    authorizer = _authorizer()
    proof = _generic_sealed_proof()

    with bind_request_identity(IDENTITY):
        with pytest.raises(
            ExecutionAuthorizationError,
            match="AUTH_PRIVACY_PROOF_AGENT_PROVENANCE_REQUIRED",
        ):
            authorizer.issue(
                SQL,
                task_purpose=TASK,
                subject_key=SUBJECT,
                privacy_proof=proof,
                expected_governance_binding=authorizer.context_resolver.current_governance_binding(),
            )


def test_public_proof_bound_authorizer_rejects_hmac_valid_rebound_agent_provenance() -> None:
    authorizer = _authorizer()
    generic = _generic_sealed_proof()
    forged = _reseal_with_provenance(
        generic,
        ppmc_result_sha256="e" * 64,
        authority_key=PROVENANCE_KEY,
    )

    assert forged.integrity_hmac_sha256 != generic.integrity_hmac_sha256
    assert forged.agent_ppmc_provenance is not None
    assert forged.agent_ppmc_provenance.ppmc_result_sha256 != forged.ppmc_result_sha256

    with bind_request_identity(IDENTITY):
        with pytest.raises(
            ExecutionAuthorizationError,
            match="AUTH_PRIVACY_PROOF_AGENT_PROVENANCE_INVALID",
        ):
            authorizer.issue(
                SQL,
                task_purpose=TASK,
                subject_key=SUBJECT,
                privacy_proof=forged,
                expected_governance_binding=authorizer.context_resolver.current_governance_binding(),
            )


def test_generic_proof_key_cannot_self_mint_agent_provenance() -> None:
    authorizer = _authorizer()
    generic = _generic_sealed_proof()
    forged = _reseal_with_provenance(
        generic,
        ppmc_result_sha256=generic.ppmc_result_sha256,
        authority_key=PROOF_KEY,
    )

    provenance = forged.agent_ppmc_provenance
    assert provenance is not None
    assert provenance.ppmc_result_sha256 == forged.ppmc_result_sha256
    assert provenance.authority_hmac_sha256 == compute_agent_ppmc_provenance_hmac(
        provenance,
        integrity_key=PROOF_KEY,
    )
    assert provenance.authority_hmac_sha256 != compute_agent_ppmc_provenance_hmac(
        provenance,
        integrity_key=PROVENANCE_KEY,
    )

    with bind_request_identity(IDENTITY):
        with pytest.raises(
            ExecutionAuthorizationError,
            match="AUTH_PRIVACY_PROOF_AGENT_PROVENANCE_UNTRUSTED",
        ):
            authorizer.issue(
                SQL,
                task_purpose=TASK,
                subject_key=SUBJECT,
                privacy_proof=forged,
                expected_governance_binding=authorizer.context_resolver.current_governance_binding(),
            )


def test_agent_provenance_cannot_be_transplanted_to_another_request_identity() -> None:
    authorizer = _authorizer()
    generic = _generic_sealed_proof()
    genuine = _reseal_with_provenance(
        generic,
        ppmc_result_sha256=generic.ppmc_result_sha256,
        authority_key=PROVENANCE_KEY,
    )
    transplanted = _reseal_for_identity(genuine, ALT_IDENTITY)

    assert transplanted.agent_ppmc_provenance is not None
    assert transplanted.request_identity_sha256 != generic.request_identity_sha256

    with bind_request_identity(ALT_IDENTITY):
        with pytest.raises(
            ExecutionAuthorizationError,
            match="AUTH_PRIVACY_PROOF_AGENT_PROVENANCE_INVALID",
        ):
            authorizer.issue(
                SQL,
                task_purpose=TASK,
                subject_key=SUBJECT,
                privacy_proof=transplanted,
                expected_governance_binding=authorizer.context_resolver.current_governance_binding(),
            )
