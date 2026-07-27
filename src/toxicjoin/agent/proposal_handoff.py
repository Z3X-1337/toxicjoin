"""Authenticated handoff from Agent proposal authority into downstream security stages.

``TrustedAgentProposalEvaluation`` remains a content-integrity artifact so the underlying proposal
authority can still be used as a staged analysis primitive. This module adds authority authenticity
for downstream stages that rely on trusted request scope, grounded DataHub evidence, and the local
PolicyEngine decision without re-running ``DataHubAgentProposalAuthority`` themselves.

The handoff reuses the existing Agent-provenance trust root under a distinct HMAC domain. It is not
an execution capability and the planning Agent never receives the key or the capsule authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime
from typing import Callable, Literal

from pydantic import Field

from toxicjoin.agent.models import AgentDataContext, AgentGoal, AgentProposal
from toxicjoin.agent.proposal_authority import (
    AgentProposalAuthorityError,
    DataHubAgentProposalAuthority,
    TrustedAgentProposalEvaluation,
    compute_trusted_agent_proposal_evaluation_sha256,
)
from toxicjoin.context.datahub import DataHubSnapshot
from toxicjoin.context.governance import GovernanceContextBinding
from toxicjoin.context.models import ContextResolution
from toxicjoin.evidence.datahub import DataHubEvidenceBundle
from toxicjoin.evidence.derivation import DataHubDerivationValidation
from toxicjoin.integrations.datahub_authority import ReadOnlyDataHubMcpSettings
from toxicjoin.models import (
    ColumnRef,
    PolicyDecision,
    PolicyInput,
    QueryPlan,
    StrictModel,
)
from toxicjoin.policy import PolicyEngine

_HANDOFF_HMAC_DOMAIN = b"toxicjoin:agent-proposal-evaluation-handoff:v1\x00"
_MIN_INTEGRITY_KEY_BYTES = 32
_HASH_PATTERN = r"^[0-9a-f]{64}$"


class AgentProposalEvaluationCapsule(StrictModel):
    """Authenticated security-owned handoff for one exact proposal evaluation."""

    schema_version: Literal["1.0"] = "1.0"
    evaluation: TrustedAgentProposalEvaluation
    evaluation_sha256: str = Field(pattern=_HASH_PATTERN)
    proposal_sha256: str = Field(pattern=_HASH_PATTERN)
    goal_sha256: str = Field(pattern=_HASH_PATTERN)
    planning_context_sha256: str = Field(pattern=_HASH_PATTERN)
    source_snapshot_sha256: str = Field(pattern=_HASH_PATTERN)
    authorized_task_purpose_sha256: str = Field(pattern=_HASH_PATTERN)
    subject_key_sha256: str = Field(pattern=_HASH_PATTERN)
    query_plan_sha256: str = Field(pattern=_HASH_PATTERN)
    governance_sha256: str = Field(pattern=_HASH_PATTERN)
    policy_input_sha256: str = Field(pattern=_HASH_PATTERN)
    policy_decision_sha256: str = Field(pattern=_HASH_PATTERN)
    evidence_root_sha256: str = Field(pattern=_HASH_PATTERN)
    evidence_expires_at: datetime
    capsule_sha256: str = Field(pattern=_HASH_PATTERN)
    authority_hmac_sha256: str = Field(pattern=_HASH_PATTERN)


class AgentProposalEvaluationCapsuleError(RuntimeError):
    """Stable fail-closed error for proposal-evaluation handoff validation."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class DataHubAgentProposalHandoffAuthority:
    """Run proposal authority and return only an authenticated downstream capsule."""

    def __init__(
        self,
        *,
        snapshot: DataHubSnapshot,
        read_settings: ReadOnlyDataHubMcpSettings,
        policy_engine: PolicyEngine,
        provenance_integrity_key: bytes,
        clock: Callable[[], datetime] | None = None,
        datahub_max_age_seconds: float = 300.0,
        dialect: str = "duckdb",
    ) -> None:
        stable_code = "AGENT_PROPOSAL_HANDOFF_INTEGRITY_KEY_INVALID"
        key = None
        authority = None
        try:
            key = _validated_key(provenance_integrity_key)
            authority = DataHubAgentProposalAuthority(
                snapshot=snapshot,
                read_settings=read_settings,
                policy_engine=policy_engine,
                clock=clock,
                datahub_max_age_seconds=datahub_max_age_seconds,
                dialect=dialect,
            )
            self._integrity_key = key
            self._proposal_authority = authority
            return
        except AgentProposalAuthorityError as error:
            stable_code = error.code
            _detach_exception(error)
        except Exception as error:
            _detach_exception(error)

        snapshot = None  # type: ignore[assignment]
        read_settings = None  # type: ignore[assignment]
        policy_engine = None  # type: ignore[assignment]
        provenance_integrity_key = None  # type: ignore[assignment]
        clock = None
        key = None
        authority = None
        self = None  # type: ignore[assignment]
        raise AgentProposalEvaluationCapsuleError(stable_code) from None

    def evaluate(
        self,
        *,
        proposal: AgentProposal,
        goal: AgentGoal,
        planning_context: AgentDataContext,
        authorized_task_purpose: str,
        subject_key: ColumnRef,
    ) -> AgentProposalEvaluationCapsule:
        """Evaluate and authenticate one Agent proposal under trusted request scope."""

        stable_code = "AGENT_PROPOSAL_HANDOFF_INTERNAL_FAILED"
        evaluation = None
        try:
            evaluation = self._proposal_authority.evaluate(
                proposal=proposal,
                goal=goal,
                planning_context=planning_context,
                authorized_task_purpose=authorized_task_purpose,
                subject_key=subject_key,
            )
            return seal_agent_proposal_evaluation_capsule(
                evaluation,
                integrity_key=self._integrity_key,
            )
        except AgentProposalAuthorityError as error:
            stable_code = error.code
            _detach_exception(error)
        except AgentProposalEvaluationCapsuleError as error:
            stable_code = error.code
            _detach_exception(error)
        except Exception as error:
            _detach_exception(error)

        proposal = None  # type: ignore[assignment]
        goal = None  # type: ignore[assignment]
        planning_context = None  # type: ignore[assignment]
        authorized_task_purpose = None  # type: ignore[assignment]
        subject_key = None  # type: ignore[assignment]
        evaluation = None
        self = None  # type: ignore[assignment]
        raise AgentProposalEvaluationCapsuleError(stable_code) from None


def seal_agent_proposal_evaluation_capsule(
    evaluation: TrustedAgentProposalEvaluation,
    *,
    integrity_key: bytes,
) -> AgentProposalEvaluationCapsule:
    """Authenticate one exact, internally self-consistent proposal evaluation."""

    key = _validated_key(integrity_key)
    _require_exact_evaluation_types(evaluation)
    expected_evaluation_sha256 = compute_trusted_agent_proposal_evaluation_sha256(evaluation)
    if not hmac.compare_digest(expected_evaluation_sha256, evaluation.evaluation_sha256):
        raise AgentProposalEvaluationCapsuleError(
            "AGENT_PROPOSAL_HANDOFF_EVALUATION_INVALID"
        )

    provisional = AgentProposalEvaluationCapsule(
        evaluation=evaluation,
        evaluation_sha256=evaluation.evaluation_sha256,
        proposal_sha256=evaluation.proposal_sha256,
        goal_sha256=evaluation.goal_sha256,
        planning_context_sha256=evaluation.planning_context_sha256,
        source_snapshot_sha256=evaluation.source_snapshot_sha256,
        authorized_task_purpose_sha256=evaluation.authorized_task_purpose_sha256,
        subject_key_sha256=evaluation.subject_key_sha256,
        query_plan_sha256=evaluation.query_plan_sha256,
        governance_sha256=evaluation.governance_sha256,
        policy_input_sha256=evaluation.policy_input_sha256,
        policy_decision_sha256=evaluation.policy_decision_sha256,
        evidence_root_sha256=evaluation.evidence_bundle.evidence_root_sha256,
        evidence_expires_at=evaluation.evidence_bundle.expires_at,
        capsule_sha256="0" * 64,
        authority_hmac_sha256="0" * 64,
    )
    content_sha256 = compute_agent_proposal_evaluation_capsule_sha256(provisional)
    unsigned = provisional.model_copy(update={"capsule_sha256": content_sha256})
    return unsigned.model_copy(
        update={
            "authority_hmac_sha256": compute_agent_proposal_evaluation_capsule_hmac(
                unsigned,
                integrity_key=key,
            )
        }
    )


def require_agent_proposal_evaluation_capsule(
    capsule: AgentProposalEvaluationCapsule,
    *,
    integrity_key: bytes,
) -> TrustedAgentProposalEvaluation:
    """Return the proposal evaluation only after full authority authentication/alignment."""

    key = _validated_key(integrity_key)
    try:
        _require_exact_capsule_types(capsule)
        evaluation = capsule.evaluation
        expected_evaluation_sha256 = compute_trusted_agent_proposal_evaluation_sha256(evaluation)
        expected_content = compute_agent_proposal_evaluation_capsule_sha256(capsule)
        expected_hmac = compute_agent_proposal_evaluation_capsule_hmac(
            capsule,
            integrity_key=key,
        )
    except (TypeError, ValueError, AttributeError):
        raise AgentProposalEvaluationCapsuleError("AGENT_PROPOSAL_HANDOFF_INVALID") from None

    if not hmac.compare_digest(expected_evaluation_sha256, evaluation.evaluation_sha256):
        raise AgentProposalEvaluationCapsuleError("AGENT_PROPOSAL_HANDOFF_INVALID")
    if not hmac.compare_digest(expected_content, capsule.capsule_sha256):
        raise AgentProposalEvaluationCapsuleError("AGENT_PROPOSAL_HANDOFF_INVALID")
    if not hmac.compare_digest(expected_hmac, capsule.authority_hmac_sha256):
        raise AgentProposalEvaluationCapsuleError("AGENT_PROPOSAL_HANDOFF_UNTRUSTED")

    aligned = (
        capsule.evaluation_sha256 == evaluation.evaluation_sha256
        and capsule.proposal_sha256 == evaluation.proposal_sha256
        and capsule.goal_sha256 == evaluation.goal_sha256
        and capsule.planning_context_sha256 == evaluation.planning_context_sha256
        and capsule.source_snapshot_sha256 == evaluation.source_snapshot_sha256
        and capsule.authorized_task_purpose_sha256 == evaluation.authorized_task_purpose_sha256
        and capsule.subject_key_sha256 == evaluation.subject_key_sha256
        and capsule.query_plan_sha256 == evaluation.query_plan_sha256
        and capsule.governance_sha256 == evaluation.governance_sha256
        and capsule.policy_input_sha256 == evaluation.policy_input_sha256
        and capsule.policy_decision_sha256 == evaluation.policy_decision_sha256
        and capsule.evidence_root_sha256 == evaluation.evidence_bundle.evidence_root_sha256
        and capsule.evidence_expires_at == evaluation.evidence_bundle.expires_at
    )
    if not aligned:
        raise AgentProposalEvaluationCapsuleError("AGENT_PROPOSAL_HANDOFF_INVALID")
    return evaluation


def compute_agent_proposal_evaluation_capsule_sha256(
    capsule: AgentProposalEvaluationCapsule,
) -> str:
    """Commit exact capsule content without a hash/MAC cycle."""

    _require_exact_capsule_types(capsule)
    return _canonical_json_sha256(
        capsule.model_dump(
            mode="json",
            exclude={"capsule_sha256", "authority_hmac_sha256"},
        )
    )


def compute_agent_proposal_evaluation_capsule_hmac(
    capsule: AgentProposalEvaluationCapsule,
    *,
    integrity_key: bytes,
) -> str:
    """Authenticate the proposal handoff under its own Agent-provenance HMAC domain."""

    key = _validated_key(integrity_key)
    _require_exact_capsule_types(capsule)
    payload = capsule.model_dump(mode="json", exclude={"authority_hmac_sha256"})
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hmac.new(key, _HANDOFF_HMAC_DOMAIN + encoded, hashlib.sha256).hexdigest()


def _canonical_json_sha256(value) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_exact_capsule_types(capsule: AgentProposalEvaluationCapsule) -> None:
    if type(capsule) is not AgentProposalEvaluationCapsule:
        raise TypeError("Agent proposal handoff must use the exact capsule type")
    _require_exact_evaluation_types(capsule.evaluation)


def _require_exact_evaluation_types(evaluation: TrustedAgentProposalEvaluation) -> None:
    if type(evaluation) is not TrustedAgentProposalEvaluation:
        raise TypeError("Agent proposal handoff must use the exact evaluation type")
    exact_nested = (
        (evaluation.subject_key, ColumnRef, "subject key"),
        (evaluation.query_plan, QueryPlan, "query plan"),
        (evaluation.resolution, ContextResolution, "context resolution"),
        (evaluation.governance_binding, GovernanceContextBinding, "governance binding"),
        (evaluation.evidence_bundle, DataHubEvidenceBundle, "evidence bundle"),
        (evaluation.evidence_validation, DataHubDerivationValidation, "evidence validation"),
        (evaluation.policy_input, PolicyInput, "policy input"),
        (evaluation.policy_decision, PolicyDecision, "policy decision"),
    )
    for value, expected_type, label in exact_nested:
        if type(value) is not expected_type:
            raise TypeError(f"Agent proposal handoff must use the exact {label} type")


def _validated_key(integrity_key: bytes) -> bytes:
    if type(integrity_key) is not bytes or len(integrity_key) < _MIN_INTEGRITY_KEY_BYTES:
        raise ValueError("Agent proposal handoff integrity key must be at least 32 bytes")
    return bytes(integrity_key)


def _detach_exception(error: BaseException) -> None:
    error.__traceback__ = None
    error.__context__ = None
    error.__cause__ = None
    error.__suppress_context__ = True
