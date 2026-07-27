"""Build and independently verify P0 pre-execution privacy proofs."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from pydantic import ValidationError

from toxicjoin.auth import RequestIdentity
from toxicjoin.context.governance import GovernanceContextBinding
from toxicjoin.context.models import ContextResolution
from toxicjoin.disclosure.models import compute_scope_sha256
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.evidence.datahub import DataHubEvidenceBundle
from toxicjoin.evidence.derivation import DataHubDerivationValidation
from toxicjoin.models import ColumnRef, Decision
from toxicjoin.policy import PolicyEngine
from toxicjoin.proofs.models import (
    AgentPpmcProofBinding,
    PreExecutionPrivacyProof,
    ProofVerificationFailure,
    ProofVerificationResult,
    RepairProofBinding,
    compute_repair_proof_binding_sha256,
)
from toxicjoin.proofs.ppmc_profile import (
    PREEXECUTION_PPMC_PROFILE,
    is_approved_preexecution_ppmc_profile,
)
from toxicjoin.prospective.forbidden import GovernanceTrustBinding
from toxicjoin.prospective.grammar import FutureActionGrammar
from toxicjoin.prospective.ppmc import PpmcSearchResult, PpmcStatus
from toxicjoin.prospective.twin import DisclosureState
from toxicjoin.repair.models import (
    CpccCandidateValidation,
    CpccResult,
    CpccStatus,
    CpccValidationOutcome,
)
from toxicjoin.sql import analyze_sql

_PROOF_HMAC_DOMAIN = b"toxicjoin:preexecution-privacy-proof:v1\x00"
_MIN_INTEGRITY_KEY_BYTES = 32
_MAX_PROOF_TTL_SECONDS = 60.0
_CONTENT_HASH_EXCLUDED = {"privacy_proof_sha256", "integrity_hmac_sha256"}
_HMAC_EXCLUDED = {"integrity_hmac_sha256"}


class PreExecutionProofError(RuntimeError):
    """Fail-closed proof-construction error with a stable internal code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def build_preexecution_privacy_proof(
    *,
    identity: RequestIdentity,
    task_purpose: str,
    sql: str,
    subject_key: ColumnRef,
    context: ContextResolution,
    governance_binding: GovernanceContextBinding,
    evidence_bundle: DataHubEvidenceBundle,
    evidence_validation: DataHubDerivationValidation,
    policy_engine: PolicyEngine,
    state: DisclosureState,
    grammar: FutureActionGrammar,
    governance_trust_binding: GovernanceTrustBinding,
    ppmc_result: PpmcSearchResult,
    integrity_key: bytes,
    cpcc_result: CpccResult | None = None,
    cpcc_selected_validation: CpccCandidateValidation | None = None,
    issued_at: datetime | None = None,
    dialect: str = "duckdb",
) -> PreExecutionPrivacyProof:
    """Construct one HMAC-authenticated proof from actual trusted artifacts.

    No caller-selected security hash is accepted. Every commitment is recomputed from the
    supplied typed artifact, and the builder rejects any cross-artifact mismatch.
    """

    _validate_integrity_key(integrity_key)
    issued = _utc(issued_at or datetime.now(timezone.utc))
    if not task_purpose.strip():
        raise PreExecutionProofError("PROOF_INVALID_TASK_PURPOSE")
    if not sql.strip():
        raise PreExecutionProofError("PROOF_INVALID_SQL")
    if dialect != "duckdb":
        raise PreExecutionProofError("PROOF_UNSUPPORTED_DIALECT")

    identity = RequestIdentity.model_validate(identity.model_dump(mode="json"))
    subject_key = ColumnRef.model_validate(subject_key.model_dump(mode="json"))
    context = ContextResolution.model_validate(context.model_dump(mode="json"))
    governance_binding = GovernanceContextBinding.model_validate(
        governance_binding.model_dump(mode="json")
    )
    evidence_bundle = DataHubEvidenceBundle.model_validate(
        evidence_bundle.model_dump(mode="json")
    )
    evidence_validation = DataHubDerivationValidation.model_validate(
        evidence_validation.model_dump(mode="json")
    )
    state = DisclosureState.model_validate(state.model_dump(mode="json"))
    grammar = FutureActionGrammar.model_validate(grammar.model_dump(mode="json"))
    governance_trust_binding = GovernanceTrustBinding.model_validate(
        governance_trust_binding.model_dump(mode="json")
    )
    ppmc_result = PpmcSearchResult.model_validate(ppmc_result.model_dump(mode="json"))

    try:
        governance_binding.assert_fresh(issued)
    except Exception as exc:
        raise PreExecutionProofError("PROOF_GOVERNANCE_STALE") from exc
    _require_evidence_fresh_at_issue(
        evidence_bundle=evidence_bundle,
        evidence_validation=evidence_validation,
        issued_at=issued,
    )
    _require_evidence_governance_alignment(
        governance_binding=governance_binding,
        evidence_bundle=evidence_bundle,
        evidence_validation=evidence_validation,
    )

    try:
        query_plan = analyze_sql(sql, dialect=dialect)
    except Exception as exc:
        raise PreExecutionProofError("PROOF_SQL_ANALYSIS_FAILED") from exc
    if context.failures:
        raise PreExecutionProofError("PROOF_CONTEXT_INCOMPLETE")

    policy_input = context.to_policy_input(
        task_purpose=task_purpose,
        query_plan=query_plan,
        subject_key=subject_key,
    )
    try:
        policy_decision = policy_engine.evaluate(policy_input)
    except Exception as exc:
        raise PreExecutionProofError("PROOF_POLICY_EVALUATION_FAILED") from exc
    if policy_decision.decision != Decision.ALLOW or policy_decision.rewrite_required:
        raise PreExecutionProofError("PROOF_POLICY_NOT_ALLOW")

    governance_binding_sha256 = canonical_json_sha256(
        governance_binding.model_dump(mode="json")
    )
    purpose_commitment_sha256 = canonical_json_sha256(
        {"task_purpose": task_purpose}
    )
    _require_state_alignment(
        state=state,
        identity=identity,
        subject_key=subject_key,
        purpose_commitment_sha256=purpose_commitment_sha256,
        governance_binding_sha256=governance_binding_sha256,
        evidence_root_sha256=evidence_bundle.evidence_root_sha256,
    )
    _require_grammar_alignment(state=state, grammar=grammar)
    _require_ppmc_alignment(
        state=state,
        grammar=grammar,
        governance_trust_binding=governance_trust_binding,
        governance_binding_sha256=governance_binding_sha256,
        ppmc_result=ppmc_result,
    )

    query_plan_sha256 = canonical_json_sha256(query_plan.model_dump(mode="json"))
    governance_context_sha256 = canonical_json_sha256(context.model_dump(mode="json"))
    policy_sha256 = canonical_json_sha256(policy_engine.config.model_dump(mode="json"))
    policy_decision_sha256 = canonical_json_sha256(
        policy_decision.model_dump(mode="json")
    )
    repair = _build_repair_binding(
        cpcc_result=cpcc_result,
        selected_validation=cpcc_selected_validation,
        sql=sql,
        query_plan_sha256=query_plan_sha256,
        context=context,
        governance_binding=governance_binding,
        evidence_root_sha256=evidence_bundle.evidence_root_sha256,
        policy_decision_sha256=policy_decision_sha256,
        state=state,
        ppmc_result=ppmc_result,
    )

    expires = min(
        issued + timedelta(seconds=_MAX_PROOF_TTL_SECONDS),
        governance_binding.expires_at,
        evidence_bundle.expires_at,
        evidence_validation.evidence_expires_at,
    )
    if expires <= issued:
        raise PreExecutionProofError("PROOF_NO_FRESHNESS_WINDOW")

    payload = {
        "issued_at": issued,
        "expires_at": expires,
        "request_identity_sha256": canonical_json_sha256(
            identity.model_dump(mode="json")
        ),
        "task_purpose_sha256": _sha256_text(task_purpose),
        "purpose_commitment_sha256": purpose_commitment_sha256,
        "subject_key_sha256": canonical_json_sha256(subject_key.model_dump(mode="json")),
        "sql_sha256": _sha256_text(sql),
        "query_plan_sha256": query_plan_sha256,
        "governance_context_sha256": governance_context_sha256,
        "governance_binding_sha256": governance_binding_sha256,
        "evidence_root_sha256": evidence_bundle.evidence_root_sha256,
        "evidence_validation_sha256": evidence_validation.validation_sha256,
        "disclosure_state_sha256": state.state_sha256,
        "warehouse_snapshot_sha256": state.warehouse_snapshot_sha256,
        "policy_sha256": policy_sha256,
        "policy_decision_sha256": policy_decision_sha256,
        "grammar_sha256": grammar.grammar_sha256,
        "ppmc_execution_profile": PREEXECUTION_PPMC_PROFILE,
        "ppmc_config_sha256": ppmc_result.config_sha256,
        "ppmc_forbidden_policy_sha256": ppmc_result.forbidden_policy_sha256,
        "ppmc_governance_binding_sha256": governance_trust_binding.binding_sha256,
        "ppmc_search_transcript_sha256": ppmc_result.search_transcript_sha256,
        "ppmc_result_sha256": ppmc_result.result_sha256,
        "ppmc_status": ppmc_result.status.value,
        "ppmc_bound": ppmc_result.bound,
        "ppmc_max_states": ppmc_result.max_states,
        "repair": repair,
    }
    unsigned = PreExecutionPrivacyProof(
        **payload,
        privacy_proof_sha256="0" * 64,
        integrity_hmac_sha256="0" * 64,
    )
    content_sha256 = compute_preexecution_privacy_proof_sha256(unsigned)
    with_content = unsigned.model_copy(
        update={"privacy_proof_sha256": content_sha256}
    )
    return with_content.model_copy(
        update={
            "integrity_hmac_sha256": compute_preexecution_privacy_proof_hmac(
                with_content,
                integrity_key=integrity_key,
            )
        }
    )


def compute_preexecution_privacy_proof_sha256(
    proof_or_payload: PreExecutionPrivacyProof | Mapping[str, Any],
) -> str:
    payload = _payload(proof_or_payload)
    canonical_payload = {
        key: value
        for key, value in payload.items()
        if key not in _CONTENT_HASH_EXCLUDED
    }
    return canonical_json_sha256(canonical_payload)


def compute_preexecution_privacy_proof_hmac(
    proof_or_payload: PreExecutionPrivacyProof | Mapping[str, Any],
    *,
    integrity_key: bytes,
) -> str:
    _validate_integrity_key(integrity_key)
    payload = _payload(proof_or_payload)
    canonical_payload = {
        key: value for key, value in payload.items() if key not in _HMAC_EXCLUDED
    }
    encoded = json.dumps(
        canonical_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hmac.new(
        integrity_key,
        _PROOF_HMAC_DOMAIN + encoded,
        hashlib.sha256,
    ).hexdigest()


def verify_preexecution_privacy_proof(
    proof_or_payload: PreExecutionPrivacyProof | Mapping[str, Any],
    *,
    integrity_key: bytes,
    now: datetime | None = None,
) -> ProofVerificationResult:
    """Verify structure, content commitment, HMAC authenticity, and proof lifetime."""

    _validate_integrity_key(integrity_key)
    try:
        if isinstance(proof_or_payload, PreExecutionPrivacyProof):
            _require_exact_proof_types(proof_or_payload)
            proof = proof_or_payload
        else:
            proof = PreExecutionPrivacyProof.model_validate(dict(proof_or_payload))
            _require_exact_proof_types(proof)
    except (ValidationError, TypeError, ValueError):
        return ProofVerificationResult(
            valid=False,
            failures=(ProofVerificationFailure.SCHEMA_INVALID,),
        )

    failures: set[ProofVerificationFailure] = set()
    expected_content = compute_preexecution_privacy_proof_sha256(proof)
    if not hmac.compare_digest(expected_content, proof.privacy_proof_sha256):
        failures.add(ProofVerificationFailure.CONTENT_HASH_MISMATCH)

    expected_hmac = compute_preexecution_privacy_proof_hmac(
        proof,
        integrity_key=integrity_key,
    )
    if not hmac.compare_digest(expected_hmac, proof.integrity_hmac_sha256):
        failures.add(ProofVerificationFailure.HMAC_MISMATCH)

    if not is_approved_preexecution_ppmc_profile(
        profile=proof.ppmc_execution_profile,
        bound=proof.ppmc_bound,
        max_states=proof.ppmc_max_states,
        config_sha256=proof.ppmc_config_sha256,
    ):
        failures.add(ProofVerificationFailure.PPMC_PROFILE_INVALID)

    current = _utc(now or datetime.now(timezone.utc))
    if proof.issued_at > current + timedelta(seconds=1):
        failures.add(ProofVerificationFailure.NOT_YET_VALID)
    if current >= proof.expires_at:
        failures.add(ProofVerificationFailure.EXPIRED)

    canonical_failures = tuple(
        failure
        for failure in ProofVerificationFailure
        if failure in failures
    )
    return ProofVerificationResult(
        valid=not canonical_failures,
        privacy_proof_sha256=proof.privacy_proof_sha256,
        failures=canonical_failures,
    )


def _build_repair_binding(
    *,
    cpcc_result: CpccResult | None,
    selected_validation: CpccCandidateValidation | None,
    sql: str,
    query_plan_sha256: str,
    context: ContextResolution,
    governance_binding: GovernanceContextBinding,
    evidence_root_sha256: str,
    policy_decision_sha256: str,
    state: DisclosureState,
    ppmc_result: PpmcSearchResult,
) -> RepairProofBinding | None:
    if cpcc_result is None and selected_validation is None:
        return None
    if cpcc_result is None or selected_validation is None:
        raise PreExecutionProofError("PROOF_REPAIR_BINDING_INCOMPLETE")

    cpcc_result = CpccResult.model_validate(cpcc_result.model_dump(mode="json"))
    selected_validation = CpccCandidateValidation.model_validate(
        selected_validation.model_dump(mode="json")
    )
    if cpcc_result.status != CpccStatus.REPAIR_FOUND:
        raise PreExecutionProofError("PROOF_CPCC_REPAIR_NOT_FOUND")
    selected = cpcc_result.selected_candidate
    if selected is None:
        raise PreExecutionProofError("PROOF_CPCC_SELECTED_CANDIDATE_MISSING")
    if selected_validation.outcome != CpccValidationOutcome.ELIGIBLE_SAFE:
        raise PreExecutionProofError("PROOF_CPCC_SELECTED_VALIDATION_NOT_SAFE")
    if selected_validation.candidate_sha256 != selected.candidate_sha256:
        raise PreExecutionProofError("PROOF_CPCC_CANDIDATE_MISMATCH")
    if selected_validation.validation_sha256 not in cpcc_result.validation_sha256s:
        raise PreExecutionProofError("PROOF_CPCC_VALIDATION_NOT_COMMITTED")

    generated_sql_sha256 = canonical_json_sha256({"sql": sql})
    reground_governance_sha256 = canonical_json_sha256(
        {
            "resolution": context.model_dump(mode="json"),
            "governance_binding": governance_binding.model_dump(mode="json"),
        }
    )
    expected = {
        "generated_sql_sha256": generated_sql_sha256,
        "reparsed_plan_sha256": query_plan_sha256,
        "reground_governance_sha256": reground_governance_sha256,
        "evidence_root_sha256": evidence_root_sha256,
        "local_policy_decision_sha256": policy_decision_sha256,
        "disclosure_state_sha256": state.state_sha256,
        "ppmc_result_sha256": ppmc_result.result_sha256,
    }
    for field_name, expected_value in expected.items():
        if getattr(selected_validation, field_name) != expected_value:
            raise PreExecutionProofError(
                f"PROOF_CPCC_{field_name.upper()}_MISMATCH"
            )
    if selected_validation.ppmc_status != PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND:
        raise PreExecutionProofError("PROOF_CPCC_PPMC_NOT_SAFE")
    if not selected_validation.local_policy_allowed:
        raise PreExecutionProofError("PROOF_CPCC_LOCAL_POLICY_NOT_ALLOW")

    provisional = RepairProofBinding.model_construct(
        cpcc_result_sha256=cpcc_result.result_sha256,
        remediation_space_sha256=cpcc_result.remediation_space_sha256,
        selected_candidate_sha256=selected.candidate_sha256,
        selected_validation_sha256=selected_validation.validation_sha256,
        generated_sql_sha256=generated_sql_sha256,
        binding_sha256="0" * 64,
    )
    return RepairProofBinding(
        cpcc_result_sha256=cpcc_result.result_sha256,
        remediation_space_sha256=cpcc_result.remediation_space_sha256,
        selected_candidate_sha256=selected.candidate_sha256,
        selected_validation_sha256=selected_validation.validation_sha256,
        generated_sql_sha256=generated_sql_sha256,
        binding_sha256=compute_repair_proof_binding_sha256(provisional),
    )


def _require_evidence_fresh_at_issue(
    *,
    evidence_bundle: DataHubEvidenceBundle,
    evidence_validation: DataHubDerivationValidation,
    issued_at: datetime,
) -> None:
    if issued_at < evidence_bundle.observed_at or issued_at >= evidence_bundle.expires_at:
        raise PreExecutionProofError("PROOF_EVIDENCE_NOT_FRESH")
    if issued_at < evidence_validation.validated_at:
        raise PreExecutionProofError("PROOF_EVIDENCE_VALIDATION_FROM_FUTURE")
    if issued_at >= evidence_validation.evidence_expires_at:
        raise PreExecutionProofError("PROOF_EVIDENCE_VALIDATION_STALE")


def _require_evidence_governance_alignment(
    *,
    governance_binding: GovernanceContextBinding,
    evidence_bundle: DataHubEvidenceBundle,
    evidence_validation: DataHubDerivationValidation,
) -> None:
    if evidence_bundle.evidence_root_sha256 != evidence_validation.evidence_root_sha256:
        raise PreExecutionProofError("PROOF_EVIDENCE_VALIDATION_ROOT_MISMATCH")
    if governance_binding.snapshot_sha256 != evidence_bundle.snapshot_sha256:
        raise PreExecutionProofError("PROOF_GOVERNANCE_EVIDENCE_SNAPSHOT_MISMATCH")
    if governance_binding.catalog_version != evidence_bundle.catalog_version:
        raise PreExecutionProofError("PROOF_GOVERNANCE_EVIDENCE_CATALOG_MISMATCH")
    if governance_binding.observed_at != evidence_bundle.observed_at:
        raise PreExecutionProofError("PROOF_GOVERNANCE_EVIDENCE_TIME_MISMATCH")


def _require_state_alignment(
    *,
    state: DisclosureState,
    identity: RequestIdentity,
    subject_key: ColumnRef,
    purpose_commitment_sha256: str,
    governance_binding_sha256: str,
    evidence_root_sha256: str,
) -> None:
    if state.scope.principal_id != identity.principal_id:
        raise PreExecutionProofError("PROOF_SCOPE_PRINCIPAL_MISMATCH")
    if state.scope.agent_id != identity.agent_id:
        raise PreExecutionProofError("PROOF_SCOPE_AGENT_MISMATCH")
    expected_scope = compute_scope_sha256(
        principal_id=identity.principal_id,
        agent_id=identity.agent_id,
        subject_namespace_sha256=state.scope.subject.namespace_sha256,
    )
    if state.scope.scope_sha256 != expected_scope:
        raise PreExecutionProofError("PROOF_SCOPE_HASH_MISMATCH")
    if state.scope.subject.field_path != subject_key.field_path:
        raise PreExecutionProofError("PROOF_SCOPE_SUBJECT_MISMATCH")
    if state.purpose_commitment_sha256 != purpose_commitment_sha256:
        raise PreExecutionProofError("PROOF_PURPOSE_STATE_MISMATCH")
    if state.governance_commitment_sha256 != governance_binding_sha256:
        raise PreExecutionProofError("PROOF_GOVERNANCE_STATE_MISMATCH")
    if state.evidence_root_sha256 != evidence_root_sha256:
        raise PreExecutionProofError("PROOF_EVIDENCE_STATE_MISMATCH")


def _require_grammar_alignment(
    *,
    state: DisclosureState,
    grammar: FutureActionGrammar,
) -> None:
    context = grammar.context
    if context.initial_state_sha256 != state.state_sha256:
        raise PreExecutionProofError("PROOF_GRAMMAR_STATE_MISMATCH")
    if context.scope_sha256 != state.scope.scope_sha256:
        raise PreExecutionProofError("PROOF_GRAMMAR_SCOPE_MISMATCH")
    if context.purpose_commitment_sha256 != state.purpose_commitment_sha256:
        raise PreExecutionProofError("PROOF_GRAMMAR_PURPOSE_MISMATCH")
    if context.governance_commitment_sha256 != state.governance_commitment_sha256:
        raise PreExecutionProofError("PROOF_GRAMMAR_GOVERNANCE_MISMATCH")
    if context.evidence_root_sha256 != state.evidence_root_sha256:
        raise PreExecutionProofError("PROOF_GRAMMAR_EVIDENCE_MISMATCH")
    if context.base_warehouse_snapshot_sha256 != state.warehouse_snapshot_sha256:
        raise PreExecutionProofError("PROOF_GRAMMAR_WAREHOUSE_SNAPSHOT_MISMATCH")


def _require_ppmc_alignment(
    *,
    state: DisclosureState,
    grammar: FutureActionGrammar,
    governance_trust_binding: GovernanceTrustBinding,
    governance_binding_sha256: str,
    ppmc_result: PpmcSearchResult,
) -> None:
    if ppmc_result.status != PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND:
        raise PreExecutionProofError("PROOF_PPMC_NOT_SAFE")
    if not is_approved_preexecution_ppmc_profile(
        profile=PREEXECUTION_PPMC_PROFILE,
        bound=ppmc_result.bound,
        max_states=ppmc_result.max_states,
        config_sha256=ppmc_result.config_sha256,
    ):
        raise PreExecutionProofError("PROOF_PPMC_PROFILE_INVALID")
    if ppmc_result.initial_state_sha256 != state.state_sha256:
        raise PreExecutionProofError("PROOF_PPMC_STATE_MISMATCH")
    if ppmc_result.grammar_sha256 != grammar.grammar_sha256:
        raise PreExecutionProofError("PROOF_PPMC_GRAMMAR_MISMATCH")
    if not governance_trust_binding.trusted:
        raise PreExecutionProofError("PROOF_GOVERNANCE_NOT_TRUSTED")
    if (
        governance_trust_binding.governance_commitment_sha256
        != governance_binding_sha256
    ):
        raise PreExecutionProofError("PROOF_PPMC_GOVERNANCE_COMMITMENT_MISMATCH")
    if ppmc_result.governance_binding_sha256 != governance_trust_binding.binding_sha256:
        raise PreExecutionProofError("PROOF_PPMC_GOVERNANCE_BINDING_MISMATCH")


def _require_exact_proof_types(proof: PreExecutionPrivacyProof) -> None:
    if type(proof) is not PreExecutionPrivacyProof:
        raise TypeError("privacy proof must use the exact proof model type")
    if (
        proof.agent_ppmc_provenance is not None
        and type(proof.agent_ppmc_provenance) is not AgentPpmcProofBinding
    ):
        raise TypeError("privacy proof must use the exact Agent provenance model type")
    if proof.repair is not None and type(proof.repair) is not RepairProofBinding:
        raise TypeError("privacy proof must use the exact repair binding model type")


def _payload(
    proof_or_payload: PreExecutionPrivacyProof | Mapping[str, Any],
) -> dict[str, Any]:
    if isinstance(proof_or_payload, PreExecutionPrivacyProof):
        _require_exact_proof_types(proof_or_payload)
        return proof_or_payload.model_dump(mode="json")
    return _json_compatible(dict(proof_or_payload))


def _json_compatible(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, Mapping):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    if isinstance(value, tuple | list):
        return [_json_compatible(item) for item in value]
    return value


def _validate_integrity_key(integrity_key: bytes) -> None:
    if not isinstance(integrity_key, bytes | bytearray):
        raise TypeError("privacy proof integrity key must be bytes")
    if len(integrity_key) < _MIN_INTEGRITY_KEY_BYTES:
        raise ValueError("privacy proof integrity key must be at least 32 bytes")


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("privacy proof clock must be timezone-aware")
    return value.astimezone(timezone.utc)


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
