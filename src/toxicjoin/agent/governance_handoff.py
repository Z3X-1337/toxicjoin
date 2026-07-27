"""Authenticated proposal-evaluation entry point into GovernanceTrust resolution.

The underlying ``DataHubGovernanceTrustAuthority`` remains the deterministic EvidenceTrust resolver.
This wrapper adds the missing authority-authenticity check on its proposal-evaluation input before
that resolver is allowed to treat the artifact as security-owned.
"""

from __future__ import annotations

from toxicjoin.agent.governance_trust import (
    DataHubGovernanceTrustAuthority,
    GovernanceTrustBinding,
    GovernanceTrustBindingError,
)
from toxicjoin.agent.proposal_handoff import (
    AgentProposalEvaluationCapsule,
    AgentProposalEvaluationCapsuleError,
    require_agent_proposal_evaluation_capsule,
)

_MIN_INTEGRITY_KEY_BYTES = 32


class AgentGovernanceTrustHandoffError(RuntimeError):
    """Stable fail-closed error for authenticated GovernanceTrust entry."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class DataHubAgentGovernanceTrustHandoffAuthority:
    """Resolve GovernanceTrust only from a proposal-authority-authenticated evaluation."""

    def __init__(self, *, provenance_integrity_key: bytes, clock=None) -> None:
        stable_code = "GOVERNANCE_TRUST_HANDOFF_INTEGRITY_KEY_INVALID"
        key = None
        authority = None
        try:
            key = _validated_key(provenance_integrity_key)
            authority = DataHubGovernanceTrustAuthority(clock=clock)
            self._integrity_key = key
            self._governance_authority = authority
            return
        except Exception as error:
            _detach_exception(error)

        provenance_integrity_key = None  # type: ignore[assignment]
        clock = None
        key = None
        authority = None
        self = None  # type: ignore[assignment]
        raise AgentGovernanceTrustHandoffError(stable_code) from None

    def bind(self, evaluation: AgentProposalEvaluationCapsule) -> GovernanceTrustBinding:
        """Authenticate the proposal evaluation, then resolve exact governance EvidenceTrust."""

        stable_code = "GOVERNANCE_TRUST_HANDOFF_INTERNAL_FAILED"
        trusted_evaluation = None
        try:
            trusted_evaluation = require_agent_proposal_evaluation_capsule(
                evaluation,
                integrity_key=self._integrity_key,
            )
            return self._governance_authority.bind(trusted_evaluation)
        except AgentProposalEvaluationCapsuleError as error:
            stable_code = "GOVERNANCE_TRUST_EVALUATION_UNTRUSTED"
            _detach_exception(error)
        except GovernanceTrustBindingError as error:
            stable_code = error.code
            _detach_exception(error)
        except Exception as error:
            _detach_exception(error)

        evaluation = None  # type: ignore[assignment]
        trusted_evaluation = None
        self = None  # type: ignore[assignment]
        raise AgentGovernanceTrustHandoffError(stable_code) from None


def _validated_key(value: bytes) -> bytes:
    if type(value) is not bytes or len(value) < _MIN_INTEGRITY_KEY_BYTES:
        raise ValueError("Agent governance handoff integrity key must be at least 32 bytes")
    return bytes(value)


def _detach_exception(error: BaseException) -> None:
    error.__traceback__ = None
    error.__context__ = None
    error.__cause__ = None
    error.__suppress_context__ = True
