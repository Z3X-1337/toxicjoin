"""Authenticated handoff from the security-owned Agent PPMC authority into proof issuance.

The generic PPMC result and ``TrustedAgentPpmcEvaluation`` remain content-integrity artifacts. This
module adds the authority-authenticity boundary required before a downstream proof authority may
rely on a PPMC evaluation without re-running the bounded search itself.

The handoff uses the existing Agent-provenance trust root under a distinct HMAC domain. It is not an
execution capability and it does not give the planning Agent access to any key or authority.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime
from typing import Literal

from pydantic import Field

from toxicjoin.agent.f6_governance import F6GovernanceClearance
from toxicjoin.agent.governance_trust import GovernanceTrustBinding as DataHubGovernanceTrustBinding
from toxicjoin.agent.ppmc_authority import (
    AgentPpmcAuthorityError,
    DataHubAgentPpmcAuthority,
    TrustedAgentPpmcEvaluation,
)
from toxicjoin.agent.proposal_authority import TrustedAgentProposalEvaluation
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.models import StrictModel
from toxicjoin.prospective.forbidden import ForbiddenPredicatePolicy, GovernanceTrustBinding
from toxicjoin.prospective.grammar import FutureActionGrammar
from toxicjoin.prospective.ppmc import PpmcSearchConfig, PpmcSearchResult
from toxicjoin.prospective.twin import DisclosureState

_HANDOFF_HMAC_DOMAIN = b"toxicjoin:agent-ppmc-evaluation-handoff:v1\x00"
_MIN_INTEGRITY_KEY_BYTES = 32
_HASH_PATTERN = r"^[0-9a-f]{64}$"


class AgentPpmcEvaluationCapsule(StrictModel):
    """Authenticated security-owned handoff for one exact Agent PPMC evaluation."""

    schema_version: Literal["1.0"] = "1.0"
    evaluation: TrustedAgentPpmcEvaluation
    evaluation_sha256: str = Field(pattern=_HASH_PATTERN)
    ppmc_result_sha256: str = Field(pattern=_HASH_PATTERN)
    f6_clearance_sha256: str = Field(pattern=_HASH_PATTERN)
    evidence_expires_at: datetime
    capsule_sha256: str = Field(pattern=_HASH_PATTERN)
    authority_hmac_sha256: str = Field(pattern=_HASH_PATTERN)

    @property
    def ppmc_result(self) -> PpmcSearchResult:
        return self.evaluation.ppmc_result

    @property
    def disclosure_state_sha256(self) -> str:
        return self.evaluation.disclosure_state_sha256

    @property
    def governance_binding_sha256(self) -> str:
        return self.evaluation.governance_binding_sha256

    @property
    def agent_evaluation_sha256(self) -> str:
        return self.evaluation.agent_evaluation_sha256

    @property
    def ppmc_started_at(self) -> datetime:
        return self.evaluation.ppmc_started_at

    @property
    def f6_clearance(self) -> F6GovernanceClearance:
        return self.evaluation.f6_clearance


class AgentPpmcEvaluationCapsuleError(RuntimeError):
    """Stable fail-closed error for PPMC authority-handoff validation."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class DataHubAgentPpmcHandoffAuthority:
    """Run Agent PPMC inside the security boundary and return only an authenticated capsule."""

    def __init__(self, *, provenance_integrity_key: bytes, clock=None) -> None:
        stable_code = "AGENT_PPMC_HANDOFF_INTEGRITY_KEY_INVALID"
        key = None
        authority = None
        try:
            key = _validated_key(provenance_integrity_key)
            authority = DataHubAgentPpmcAuthority(clock=clock)
            self._integrity_key = key
            self._ppmc_authority = authority
            return
        except Exception as error:
            _detach_exception(error)

        provenance_integrity_key = None  # type: ignore[assignment]
        clock = None
        key = None
        authority = None
        self = None  # type: ignore[assignment]
        raise AgentPpmcEvaluationCapsuleError(stable_code) from None

    def check(
        self,
        *,
        evaluation: TrustedAgentProposalEvaluation,
        governance_trust: DataHubGovernanceTrustBinding,
        initial_state: DisclosureState,
        grammar: FutureActionGrammar,
        forbidden_policy: ForbiddenPredicatePolicy,
        config: PpmcSearchConfig | None = None,
    ) -> AgentPpmcEvaluationCapsule:
        """Run the existing security-owned PPMC authority and authenticate its exact output."""

        stable_code = "AGENT_PPMC_HANDOFF_INTERNAL_FAILED"
        ppmc_evaluation = None
        try:
            ppmc_evaluation = self._ppmc_authority.check(
                evaluation=evaluation,
                governance_trust=governance_trust,
                initial_state=initial_state,
                grammar=grammar,
                forbidden_policy=forbidden_policy,
                config=config,
            )
            return seal_agent_ppmc_evaluation_capsule(
                ppmc_evaluation,
                integrity_key=self._integrity_key,
            )
        except AgentPpmcAuthorityError as error:
            stable_code = error.code
            _detach_exception(error)
        except AgentPpmcEvaluationCapsuleError as error:
            stable_code = error.code
            _detach_exception(error)
        except Exception as error:
            _detach_exception(error)

        evaluation = None  # type: ignore[assignment]
        governance_trust = None  # type: ignore[assignment]
        initial_state = None  # type: ignore[assignment]
        grammar = None  # type: ignore[assignment]
        forbidden_policy = None  # type: ignore[assignment]
        config = None
        ppmc_evaluation = None
        self = None  # type: ignore[assignment]
        raise AgentPpmcEvaluationCapsuleError(stable_code) from None


def seal_agent_ppmc_evaluation_capsule(
    evaluation: TrustedAgentPpmcEvaluation,
    *,
    integrity_key: bytes,
) -> AgentPpmcEvaluationCapsule:
    """Authenticate one exact, internally self-consistent PPMC evaluation."""

    key = _validated_key(integrity_key)
    _require_exact_evaluation_types(evaluation)
    expected_evaluation_sha256 = canonical_json_sha256(
        evaluation.model_dump(mode="json", exclude={"evaluation_sha256"})
    )
    if not hmac.compare_digest(expected_evaluation_sha256, evaluation.evaluation_sha256):
        raise AgentPpmcEvaluationCapsuleError("AGENT_PPMC_HANDOFF_EVALUATION_INVALID")

    provisional = AgentPpmcEvaluationCapsule(
        evaluation=evaluation,
        evaluation_sha256=evaluation.evaluation_sha256,
        ppmc_result_sha256=evaluation.ppmc_result_sha256,
        f6_clearance_sha256=evaluation.f6_clearance_sha256,
        evidence_expires_at=evaluation.evidence_expires_at,
        capsule_sha256="0" * 64,
        authority_hmac_sha256="0" * 64,
    )
    content_sha256 = compute_agent_ppmc_evaluation_capsule_sha256(provisional)
    unsigned = provisional.model_copy(update={"capsule_sha256": content_sha256})
    return unsigned.model_copy(
        update={
            "authority_hmac_sha256": compute_agent_ppmc_evaluation_capsule_hmac(
                unsigned,
                integrity_key=key,
            )
        }
    )


def require_agent_ppmc_evaluation_capsule(
    capsule: AgentPpmcEvaluationCapsule,
    *,
    integrity_key: bytes,
) -> TrustedAgentPpmcEvaluation:
    """Return the exact PPMC evaluation only after full handoff authentication/alignment."""

    key = _validated_key(integrity_key)
    try:
        _require_exact_capsule_types(capsule)
        evaluation = capsule.evaluation
        expected_evaluation_sha256 = canonical_json_sha256(
            evaluation.model_dump(mode="json", exclude={"evaluation_sha256"})
        )
        expected_content = compute_agent_ppmc_evaluation_capsule_sha256(capsule)
        expected_hmac = compute_agent_ppmc_evaluation_capsule_hmac(
            capsule,
            integrity_key=key,
        )
    except (TypeError, ValueError, AttributeError):
        raise AgentPpmcEvaluationCapsuleError("AGENT_PPMC_HANDOFF_INVALID") from None

    if not hmac.compare_digest(expected_evaluation_sha256, evaluation.evaluation_sha256):
        raise AgentPpmcEvaluationCapsuleError("AGENT_PPMC_HANDOFF_INVALID")
    if not hmac.compare_digest(expected_content, capsule.capsule_sha256):
        raise AgentPpmcEvaluationCapsuleError("AGENT_PPMC_HANDOFF_INVALID")
    if not hmac.compare_digest(expected_hmac, capsule.authority_hmac_sha256):
        raise AgentPpmcEvaluationCapsuleError("AGENT_PPMC_HANDOFF_UNTRUSTED")
    if capsule.evaluation_sha256 != evaluation.evaluation_sha256:
        raise AgentPpmcEvaluationCapsuleError("AGENT_PPMC_HANDOFF_INVALID")
    if capsule.ppmc_result_sha256 != evaluation.ppmc_result_sha256:
        raise AgentPpmcEvaluationCapsuleError("AGENT_PPMC_HANDOFF_INVALID")
    if capsule.f6_clearance_sha256 != evaluation.f6_clearance_sha256:
        raise AgentPpmcEvaluationCapsuleError("AGENT_PPMC_HANDOFF_INVALID")
    if capsule.evidence_expires_at != evaluation.evidence_expires_at:
        raise AgentPpmcEvaluationCapsuleError("AGENT_PPMC_HANDOFF_INVALID")
    return evaluation


def compute_agent_ppmc_evaluation_capsule_sha256(capsule: AgentPpmcEvaluationCapsule) -> str:
    """Commit exact capsule content without a hash/MAC cycle."""

    _require_exact_capsule_types(capsule)
    return canonical_json_sha256(
        capsule.model_dump(
            mode="json",
            exclude={"capsule_sha256", "authority_hmac_sha256"},
        )
    )


def compute_agent_ppmc_evaluation_capsule_hmac(
    capsule: AgentPpmcEvaluationCapsule,
    *,
    integrity_key: bytes,
) -> str:
    """Authenticate the exact PPMC handoff under a distinct Agent-provenance HMAC domain."""

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


def _require_exact_capsule_types(capsule: AgentPpmcEvaluationCapsule) -> None:
    if type(capsule) is not AgentPpmcEvaluationCapsule:
        raise TypeError("Agent PPMC handoff must use the exact capsule type")
    _require_exact_evaluation_types(capsule.evaluation)


def _require_exact_evaluation_types(evaluation: TrustedAgentPpmcEvaluation) -> None:
    if type(evaluation) is not TrustedAgentPpmcEvaluation:
        raise TypeError("Agent PPMC handoff must use the exact evaluation type")
    if type(evaluation.f6_clearance) is not F6GovernanceClearance:
        raise TypeError("Agent PPMC handoff must use the exact F6 clearance type")
    if type(evaluation.f6_clearance.f6_binding) is not GovernanceTrustBinding:
        raise TypeError("Agent PPMC handoff must use the exact prospective governance binding type")
    if type(evaluation.ppmc_result) is not PpmcSearchResult:
        raise TypeError("Agent PPMC handoff must use the exact PPMC result type")


def _validated_key(integrity_key: bytes) -> bytes:
    if type(integrity_key) is not bytes or len(integrity_key) < _MIN_INTEGRITY_KEY_BYTES:
        raise ValueError("Agent PPMC handoff integrity key must be at least 32 bytes")
    return bytes(integrity_key)


def _detach_exception(error: BaseException) -> None:
    error.__traceback__ = None
    error.__context__ = None
    error.__cause__ = None
    error.__suppress_context__ = True
