"""Security-owned bridge from Governed-Agent PPMC evaluation into pre-execution proof.

The generic proof builder remains available as a rollback-safe primitive, but it cannot mint
trusted Governed-Agent provenance. This authority consumes the exact Agent proposal as a
non-authoritative preimage witness plus the security-owned proposal/PPMC capabilities, rebinds the
execution-relevant artifacts, authenticates provenance under an independent authority key, and only
then seals the enclosing pre-execution privacy proof.

Authenticated request identity is derived from the bound request context and is never accepted as a
caller-selected proof-authority input. Nothing in this module executes SQL or mutates
DisclosureState/DataHub state.
"""

from __future__ import annotations

import hashlib
import hmac
import threading
from datetime import datetime, timezone

from pydantic import ValidationError

from toxicjoin.agent.models import AgentProposal
from toxicjoin.agent.ppmc_authority import TrustedAgentPpmcEvaluation
from toxicjoin.agent.ppmc_handoff import (
    AgentPpmcEvaluationCapsule,
    AgentPpmcEvaluationCapsuleError,
    require_agent_ppmc_evaluation_capsule,
)
from toxicjoin.agent.proposal_authority import TrustedAgentProposalEvaluation
from toxicjoin.auth import RequestIdentity, current_request_identity
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.proofs.agent_provenance import (
    compute_agent_bound_proof_core_sha256,
    compute_agent_ppmc_provenance_hmac,
)
from toxicjoin.proofs.models import (
    AgentPpmcProofBinding,
    PreExecutionPrivacyProof,
    compute_agent_ppmc_proof_binding_sha256,
)
from toxicjoin.proofs.preexec import (
    PreExecutionProofError,
    build_preexecution_privacy_proof,
    compute_preexecution_privacy_proof_hmac,
    compute_preexecution_privacy_proof_sha256,
)
from toxicjoin.prospective.grammar import FutureActionGrammar
from toxicjoin.prospective.ppmc import PpmcStatus
from toxicjoin.prospective.twin import DisclosureState
from toxicjoin.sql import analyze_sql

_MIN_KEY_BYTES = 32


class AgentPreExecutionProofAuthorityError(RuntimeError):
    """Stable fail-closed error for the Governed-Agent proof authority boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class DataHubAgentPreExecutionProofAuthority:
    """Mint Agent-provenance-bound pre-execution proofs from trusted upstream capabilities."""

    def __init__(
        self,
        *,
        integrity_key: bytes,
        provenance_integrity_key: bytes,
        clock=None,
    ) -> None:
        try:
            proof_key = _strict_key(integrity_key)
            provenance_key = _strict_key(provenance_integrity_key)
            if hmac.compare_digest(proof_key, provenance_key):
                raise ValueError("proof/provenance keys must differ")
        except Exception:
            raise AgentPreExecutionProofAuthorityError(
                "AGENT_PROOF_INTEGRITY_KEY_INVALID"
            ) from None

        self._integrity_key = proof_key
        self._provenance_integrity_key = provenance_key
        self._clock = (lambda: datetime.now(timezone.utc)) if clock is None else clock
        self._clock_lock = threading.Lock()
        self._last_clock_sample: datetime | None = None

    def build(
        self,
        *,
        proposal: AgentProposal,
        evaluation: TrustedAgentProposalEvaluation,
        ppmc_evaluation: AgentPpmcEvaluationCapsule,
        sql: str,
        state: DisclosureState,
        grammar: FutureActionGrammar,
    ) -> PreExecutionPrivacyProof:
        """Return one proof carrying independently authenticated Governed-Agent PPMC provenance."""

        stable_code = "AGENT_PROOF_INTERNAL_FAILED"
        try:
            return self._build_impl(
                proposal=proposal,
                evaluation=evaluation,
                ppmc_evaluation=ppmc_evaluation,
                sql=sql,
                state=state,
                grammar=grammar,
            )
        except AgentPreExecutionProofAuthorityError as error:
            stable_code = error.code
            _detach_exception(error)
        except Exception as error:
            _detach_exception(error)

        proposal = None  # type: ignore[assignment]
        evaluation = None  # type: ignore[assignment]
        ppmc_evaluation = None  # type: ignore[assignment]
        sql = None  # type: ignore[assignment]
        state = None  # type: ignore[assignment]
        grammar = None  # type: ignore[assignment]
        self = None  # type: ignore[assignment]
        raise AgentPreExecutionProofAuthorityError(stable_code) from None

    def _build_impl(
        self,
        *,
        proposal: AgentProposal,
        evaluation: TrustedAgentProposalEvaluation,
        ppmc_evaluation: AgentPpmcEvaluationCapsule,
        sql: str,
        state: DisclosureState,
        grammar: FutureActionGrammar,
    ) -> PreExecutionPrivacyProof:
        if type(ppmc_evaluation) is TrustedAgentPpmcEvaluation:
            raise AgentPreExecutionProofAuthorityError(
                "AGENT_PROOF_PPMC_AUTHORITY_UNTRUSTED"
            )
        if (
            type(proposal) is not AgentProposal
            or type(evaluation) is not TrustedAgentProposalEvaluation
            or type(ppmc_evaluation) is not AgentPpmcEvaluationCapsule
            or type(sql) is not str
            or type(state) is not DisclosureState
            or type(grammar) is not FutureActionGrammar
        ):
            raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_INPUT_INVALID")
        if not sql.strip():
            raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_INPUT_INVALID")

        # Authority authenticity must be established before serializing the nested PPMC evaluation.
        # A self-consistent caller-reconstructed evaluation is not sufficient proof of PPMC origin.
        try:
            authoritative_ppmc = require_agent_ppmc_evaluation_capsule(
                ppmc_evaluation,
                integrity_key=self._provenance_integrity_key,
            )
        except AgentPpmcEvaluationCapsuleError:
            raise AgentPreExecutionProofAuthorityError(
                "AGENT_PROOF_PPMC_AUTHORITY_UNTRUSTED"
            ) from None

        bound_identity = current_request_identity()
        if bound_identity is None:
            raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_IDENTITY_REQUIRED")

        try:
            trusted_proposal = AgentProposal.model_validate(proposal.model_dump(mode="json"))
            trusted_evaluation = TrustedAgentProposalEvaluation.model_validate(
                evaluation.model_dump(mode="json")
            )
            trusted_ppmc = TrustedAgentPpmcEvaluation.model_validate(
                authoritative_ppmc.model_dump(mode="json")
            )
            trusted_identity = RequestIdentity.model_validate(
                bound_identity.model_dump(mode="json")
            )
            trusted_state = DisclosureState.model_validate(state.model_dump(mode="json"))
            trusted_grammar = FutureActionGrammar.model_validate(grammar.model_dump(mode="json"))
        except (ValidationError, ValueError, AttributeError):
            raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_INPUT_INVALID") from None

        if trusted_proposal.proposal_sha256 != trusted_evaluation.proposal_sha256:
            raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_PROPOSAL_MISMATCH")
        if trusted_proposal.query_plan_sha256 != trusted_evaluation.query_plan_sha256:
            raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_PROPOSAL_PLAN_MISMATCH")
        exact_sql_sha256 = hashlib.sha256(sql.encode("utf-8")).hexdigest()
        if exact_sql_sha256 != trusted_proposal.sql_sha256:
            raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_SQL_BINDING_MISMATCH")

        if trusted_ppmc.agent_evaluation_sha256 != trusted_evaluation.evaluation_sha256:
            raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_EVALUATION_MISMATCH")
        if trusted_ppmc.ppmc_result.status != PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND:
            raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_PPMC_NOT_SAFE")
        if trusted_ppmc.disclosure_state_sha256 != trusted_state.state_sha256:
            raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_STATE_MISMATCH")
        if trusted_ppmc.ppmc_result.grammar_sha256 != trusted_grammar.grammar_sha256:
            raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_GRAMMAR_MISMATCH")

        try:
            reparsed_plan = analyze_sql(sql, dialect="duckdb")
        except Exception:
            raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_SQL_INVALID") from None
        if reparsed_plan != trusted_evaluation.query_plan:
            raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_QUERY_PLAN_MISMATCH")

        governance_binding_sha256 = canonical_json_sha256(
            trusted_evaluation.governance_binding.model_dump(mode="json")
        )
        clearance = trusted_ppmc.f6_clearance
        if clearance.evaluation_sha256 != trusted_evaluation.evaluation_sha256:
            raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_F6_EVALUATION_MISMATCH")
        if clearance.disclosure_state_sha256 != trusted_state.state_sha256:
            raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_F6_STATE_MISMATCH")
        if clearance.governance_commitment_sha256 != governance_binding_sha256:
            raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_F6_GOVERNANCE_MISMATCH")
        if clearance.evidence_root_sha256 != trusted_evaluation.evidence_bundle.evidence_root_sha256:
            raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_F6_EVIDENCE_MISMATCH")
        if clearance.purpose_commitment_sha256 != trusted_evaluation.authorized_task_purpose_sha256:
            raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_F6_PURPOSE_MISMATCH")
        if trusted_ppmc.governance_binding_sha256 != clearance.f6_binding.binding_sha256:
            raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_F6_BINDING_MISMATCH")

        package_policy = load_policy()
        package_policy_sha256 = canonical_json_sha256(package_policy.model_dump(mode="json"))
        if (
            trusted_evaluation.policy_version != package_policy.version
            or trusted_evaluation.policy_config_sha256 != package_policy_sha256
        ):
            raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_POLICY_MISMATCH")

        issued_at = self._sample_clock()
        if issued_at < trusted_ppmc.ppmc_started_at:
            raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_PPMC_FROM_FUTURE")
        if issued_at >= trusted_ppmc.evidence_expires_at:
            raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_EVIDENCE_STALE")
        if issued_at >= trusted_evaluation.evidence_validation.evidence_expires_at:
            raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_EVIDENCE_STALE")

        try:
            base_proof = build_preexecution_privacy_proof(
                identity=trusted_identity,
                task_purpose=trusted_evaluation.authorized_task_purpose,
                sql=sql,
                subject_key=trusted_evaluation.subject_key,
                context=trusted_evaluation.resolution,
                governance_binding=trusted_evaluation.governance_binding,
                evidence_bundle=trusted_evaluation.evidence_bundle,
                evidence_validation=trusted_evaluation.evidence_validation,
                policy_engine=PolicyEngine(package_policy),
                state=trusted_state,
                grammar=trusted_grammar,
                governance_trust_binding=clearance.f6_binding,
                ppmc_result=trusted_ppmc.ppmc_result,
                integrity_key=self._integrity_key,
                issued_at=issued_at,
                dialect="duckdb",
            )
        except PreExecutionProofError as error:
            mapping = {
                "PROOF_PPMC_PROFILE_INVALID": "AGENT_PROOF_PPMC_PROFILE_INVALID",
                "PROOF_PPMC_NOT_SAFE": "AGENT_PROOF_PPMC_NOT_SAFE",
            }
            raise AgentPreExecutionProofAuthorityError(
                mapping.get(error.code, "AGENT_PROOF_BUILD_FAILED")
            ) from None
        except Exception:
            raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_BUILD_FAILED") from None

        binding_payload = {
            "agent_proposal_sha256": trusted_evaluation.proposal_sha256,
            "agent_evaluation_sha256": trusted_evaluation.evaluation_sha256,
            "agent_ppmc_evaluation_sha256": trusted_ppmc.evaluation_sha256,
            "f6_clearance_sha256": trusted_ppmc.f6_clearance_sha256,
            "proof_core_sha256": compute_agent_bound_proof_core_sha256(base_proof),
            "request_identity_sha256": base_proof.request_identity_sha256,
            "sql_sha256": base_proof.sql_sha256,
            "query_plan_sha256": base_proof.query_plan_sha256,
            "task_purpose_sha256": base_proof.task_purpose_sha256,
            "purpose_commitment_sha256": base_proof.purpose_commitment_sha256,
            "subject_key_sha256": base_proof.subject_key_sha256,
            "governance_context_sha256": base_proof.governance_context_sha256,
            "governance_binding_sha256": base_proof.governance_binding_sha256,
            "evidence_root_sha256": base_proof.evidence_root_sha256,
            "evidence_validation_sha256": base_proof.evidence_validation_sha256,
            "policy_sha256": base_proof.policy_sha256,
            "policy_decision_sha256": base_proof.policy_decision_sha256,
            "disclosure_state_sha256": base_proof.disclosure_state_sha256,
            "grammar_sha256": base_proof.grammar_sha256,
            "ppmc_execution_profile": base_proof.ppmc_execution_profile,
            "ppmc_config_sha256": base_proof.ppmc_config_sha256,
            "ppmc_forbidden_policy_sha256": base_proof.ppmc_forbidden_policy_sha256,
            "ppmc_governance_binding_sha256": base_proof.ppmc_governance_binding_sha256,
            "ppmc_search_transcript_sha256": base_proof.ppmc_search_transcript_sha256,
            "ppmc_result_sha256": base_proof.ppmc_result_sha256,
            "ppmc_status": base_proof.ppmc_status,
            "ppmc_bound": base_proof.ppmc_bound,
            "ppmc_max_states": base_proof.ppmc_max_states,
            "evidence_expires_at": trusted_ppmc.evidence_expires_at,
        }
        provisional_binding = AgentPpmcProofBinding.model_construct(
            **binding_payload,
            binding_sha256="0" * 64,
            authority_hmac_sha256="0" * 64,
        )
        binding_sha256 = compute_agent_ppmc_proof_binding_sha256(provisional_binding)
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
                integrity_key=self._provenance_integrity_key,
            ),
        )

        unsigned = base_proof.model_copy(
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
        sealed = with_content.model_copy(
            update={
                "integrity_hmac_sha256": compute_preexecution_privacy_proof_hmac(
                    with_content,
                    integrity_key=self._integrity_key,
                )
            }
        )
        try:
            return PreExecutionPrivacyProof.model_validate(sealed.model_dump(mode="json"))
        except (ValidationError, ValueError):
            raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_RESULT_INVALID") from None

    def _sample_clock(self) -> datetime:
        with self._clock_lock:
            try:
                current = self._clock()
                if not isinstance(current, datetime) or current.tzinfo is None:
                    raise ValueError("Agent proof clock must be timezone-aware")
                normalized = current.astimezone(timezone.utc)
            except Exception:
                raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_TIME_INVALID") from None
            if self._last_clock_sample is not None and normalized < self._last_clock_sample:
                raise AgentPreExecutionProofAuthorityError("AGENT_PROOF_TIME_ROLLBACK")
            self._last_clock_sample = normalized
            return normalized


def _strict_key(value: bytes) -> bytes:
    if type(value) is not bytes or len(value) < _MIN_KEY_BYTES:
        raise ValueError("integrity key must be at least 32 bytes")
    return bytes(value)


def _detach_exception(error: BaseException) -> None:
    error.__traceback__ = None
    error.__context__ = None
    error.__cause__ = None
    error.__suppress_context__ = True
