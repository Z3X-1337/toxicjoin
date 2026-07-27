from __future__ import annotations

from datetime import datetime, timedelta, timezone

import duckdb
import pytest
from pydantic import SecretStr

from toxicjoin.auth import RequestIdentity, bind_request_identity
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
from toxicjoin.execute import (
    DuckDBExecutor,
    ExecutionError,
    ProofBoundExecutionAuthorizer,
)
from toxicjoin.integrations.datahub_mcp import DataHubMcpSettings
from toxicjoin.models import ColumnRef, SensitivityCategory
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.proofs import (
    AgentPpmcProofBinding,
    PreExecutionPrivacyProof,
    build_preexecution_privacy_proof,
    compute_agent_ppmc_proof_binding_sha256,
    compute_agent_ppmc_provenance_hmac,
    compute_preexecution_privacy_proof_hmac,
    compute_preexecution_privacy_proof_sha256,
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
from toxicjoin.verify import verify_and_execute

OBSERVED_AT = datetime(2026, 7, 25, 14, 0, tzinfo=timezone.utc)
ISSUED_AT = OBSERVED_AT + timedelta(seconds=30)
VERIFY_AT = ISSUED_AT + timedelta(seconds=1)
PROOF_KEY = b"integration-proof-integrity-key-32-bytes!!"
PROVENANCE_KEY = b"integration-agent-provenance-key-32-bytes!!"
AUTH_KEY = b"integration-execution-auth-key-32-bytes!!!"
URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.proof_execution,PROD)"
SQL = "SELECT country FROM patients WHERE customer_id IS NOT NULL"
PURPOSE = "proof-bound execution integration"
SUBJECT = ColumnRef(dataset="patients", field_path="customer_id")
WAREHOUSE = "a" * 64
COHORT = "c" * 64
IDENTITY = RequestIdentity(
    principal_id="principal-proof-exec",
    credential_id="credential-proof-exec",
    agent_id="agent-proof-exec",
    session_id="session-proof-exec",
)


class SpyDuckDBExecutor(DuckDBExecutor):
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.connect_calls = 0

    def _connect(self):
        self.connect_calls += 1
        return super()._connect()


def _settings() -> DataHubMcpSettings:
    return DataHubMcpSettings(
        gms_url="https://datahub.example",
        gms_token=SecretStr("proof-execution-secret"),
        command="uvx",
        args=("mcp-server-datahub",),
    )


def _snapshot() -> DataHubSnapshot:
    return DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:proof-execution-v1",
            datasets={
                "patients": FixtureDataset(
                    urn=URN,
                    owner="urn:li:corpuser:proof-execution-owner",
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


def _with_agent_provenance(proof: PreExecutionPrivacyProof) -> PreExecutionPrivacyProof:
    payload = {
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
        "ppmc_result_sha256": proof.ppmc_result_sha256,
        "evidence_expires_at": proof.expires_at,
    }
    provisional = AgentPpmcProofBinding.model_construct(
        **payload,
        binding_sha256="0" * 64,
        authority_hmac_sha256="0" * 64,
    )
    binding_sha256 = compute_agent_ppmc_proof_binding_sha256(provisional)
    unsigned_provenance = AgentPpmcProofBinding.model_construct(
        **payload,
        binding_sha256=binding_sha256,
        authority_hmac_sha256="0" * 64,
    )
    provenance = AgentPpmcProofBinding(
        **payload,
        binding_sha256=binding_sha256,
        authority_hmac_sha256=compute_agent_ppmc_provenance_hmac(
            unsigned_provenance,
            integrity_key=PROVENANCE_KEY,
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


def _build_runtime(tmp_path):
    database = tmp_path / "proof-execution.duckdb"
    connection = duckdb.connect(str(database))
    try:
        connection.execute("CREATE TABLE patients(customer_id VARCHAR, country VARCHAR)")
        connection.execute(
            "INSERT INTO patients VALUES ('c1', 'JO'), ('c2', 'US'), ('c3', 'JO')"
        )
    finally:
        connection.close()

    snapshot = _snapshot()
    settings = _settings()
    resolver = DataHubSnapshotContextResolver(
        snapshot,
        max_age_seconds=300,
        clock=lambda: VERIFY_AT,
    )
    policy_engine = PolicyEngine(load_policy())
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
    oracle = PolicyEngineLocalOracle(
        policy_engine,
        grammar,
        build_policy_oracle_governance_context(
            context.projected_context + context.all_referenced_context
        ),
    )
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
    assert ppmc.status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND

    proof = build_preexecution_privacy_proof(
        identity=IDENTITY,
        task_purpose=PURPOSE,
        sql=SQL,
        subject_key=SUBJECT,
        context=context,
        governance_binding=governance_binding,
        evidence_bundle=bundle,
        evidence_validation=validation,
        policy_engine=policy_engine,
        state=state,
        grammar=grammar,
        governance_trust_binding=trust_binding,
        ppmc_result=ppmc,
        integrity_key=PROOF_KEY,
        issued_at=ISSUED_AT,
    )
    proof = _with_agent_provenance(proof)

    executor = SpyDuckDBExecutor(database, max_preview_rows=10)
    executor.bind_authorizer(
        ProofBoundExecutionAuthorizer(
            context_resolver=resolver,
            policy_engine=policy_engine,
            privacy_proof_integrity_key=PROOF_KEY,
            agent_provenance_integrity_key=PROVENANCE_KEY,
            secret_key=AUTH_KEY,
            ttl_seconds=5,
            clock=lambda: VERIFY_AT.timestamp(),
        )
    )
    return executor, resolver, policy_engine, governance_binding, proof


def _verify(executor, resolver, policy_engine, *, proof):
    with bind_request_identity(IDENTITY):
        return verify_and_execute(
            SQL,
            task_purpose=PURPOSE,
            subject_key=SUBJECT,
            context_resolver=resolver,
            policy_engine=policy_engine,
            executor=executor,
            required_minimum_group_size=policy_engine.config.minimum_group_size,
            require_subject_threshold=False,
            privacy_proof=proof,
        )


def _reseal_with_transcript(
    proof: PreExecutionPrivacyProof,
    transcript_sha256: str,
) -> PreExecutionPrivacyProof:
    payload = proof.model_dump(mode="json")
    payload["ppmc_search_transcript_sha256"] = transcript_sha256
    payload["privacy_proof_sha256"] = compute_preexecution_privacy_proof_sha256(payload)
    payload["integrity_hmac_sha256"] = compute_preexecution_privacy_proof_hmac(
        payload,
        integrity_key=PROOF_KEY,
    )
    return PreExecutionPrivacyProof.model_validate(payload)


def test_public_verifier_executes_only_with_matching_real_privacy_proof(tmp_path) -> None:
    executor, resolver, policy_engine, _, proof = _build_runtime(tmp_path)

    result = _verify(executor, resolver, policy_engine, proof=proof)

    assert result.passed is True
    assert result.execution is not None
    assert result.execution.rows == (("JO",), ("US",), ("JO",))
    assert executor.connect_calls == 1


def test_missing_proof_fails_before_duckdb_connection(tmp_path) -> None:
    executor, resolver, policy_engine, _, _ = _build_runtime(tmp_path)

    result = _verify(executor, resolver, policy_engine, proof=None)

    assert result.passed is False
    assert result.execution is None
    assert result.execution_attempted is False
    assert result.execution_error is not None
    assert "AUTH_PRIVACY_PROOF_REQUIRED" in result.execution_error
    assert executor.connect_calls == 0


def test_tampered_proof_fails_before_duckdb_connection(tmp_path) -> None:
    executor, resolver, policy_engine, _, proof = _build_runtime(tmp_path)
    tampered = proof.model_copy(update={"sql_sha256": "f" * 64})

    result = _verify(executor, resolver, policy_engine, proof=tampered)

    assert result.passed is False
    assert result.execution is None
    assert result.execution_attempted is False
    assert result.execution_error is not None
    assert "AUTH_PRIVACY_PROOF_INVALID" in result.execution_error
    assert executor.connect_calls == 0


def test_executor_rejects_swapped_valid_proof_before_duckdb_connection(tmp_path) -> None:
    executor, _, _, governance_binding, proof = _build_runtime(tmp_path)
    other = _reseal_with_transcript(proof, "e" * 64)
    assert other.privacy_proof_sha256 != proof.privacy_proof_sha256

    with bind_request_identity(IDENTITY):
        authorization = executor.issue_authorization(
            SQL,
            task_purpose=PURPOSE,
            subject_key=SUBJECT,
            expected_governance_binding=governance_binding,
            privacy_proof=proof,
        )
        with pytest.raises(ExecutionError, match="AUTH_PRIVACY_PROOF_BINDING_MISMATCH"):
            executor.execute_authorized(
                SQL,
                authorization=authorization,
                task_purpose=PURPOSE,
                subject_key=SUBJECT,
                privacy_proof=other,
            )

    assert executor.connect_calls == 0


def test_proof_mode_rejects_non_duckdb_executor() -> None:
    proof = PreExecutionPrivacyProof.model_construct()
    with pytest.raises(TypeError, match="requires a DuckDBExecutor"):
        verify_and_execute(
            SQL,
            privacy_proof=proof,
            executor=object(),
        )
