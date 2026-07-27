"""Security-owned handoff authority for Governed-Agent pre-execution proofs.

This boundary intentionally exposes only ``issue``. The underlying generic proof object is built by
``DataHubAgentPreExecutionProofAuthority`` and immediately sealed into an authenticated handoff
capsule before leaving this authority. The capsule is still not execution authorization.
"""

from __future__ import annotations

from toxicjoin.agent.models import AgentProposal
from toxicjoin.agent.ppmc_authority import TrustedAgentPpmcEvaluation
from toxicjoin.agent.proof_authority import (
    AgentPreExecutionProofAuthorityError,
    DataHubAgentPreExecutionProofAuthority,
)
from toxicjoin.agent.proposal_authority import TrustedAgentProposalEvaluation
from toxicjoin.proofs.agent_handoff import (
    AgentPreExecutionProofCapsule,
    AgentPreExecutionProofCapsuleError,
    seal_agent_preexecution_proof_capsule,
)
from toxicjoin.prospective.grammar import FutureActionGrammar
from toxicjoin.prospective.twin import DisclosureState


class AgentProofHandoffAuthorityError(RuntimeError):
    """Stable fail-closed error for the security-owned proof handoff boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class DataHubAgentProofHandoffAuthority:
    """Issue authenticated capsules without exposing a raw-proof construction method."""

    def __init__(
        self,
        *,
        integrity_key: bytes,
        provenance_integrity_key: bytes,
        clock=None,
    ) -> None:
        try:
            self._proof_authority = DataHubAgentPreExecutionProofAuthority(
                integrity_key=integrity_key,
                provenance_integrity_key=provenance_integrity_key,
                clock=clock,
            )
            self._provenance_integrity_key = bytes(provenance_integrity_key)
        except AgentPreExecutionProofAuthorityError as error:
            code = error.code
            _detach_exception(error)
            raise AgentProofHandoffAuthorityError(code) from None
        except Exception as error:
            _detach_exception(error)
            raise AgentProofHandoffAuthorityError(
                "AGENT_PROOF_HANDOFF_INTEGRITY_KEY_INVALID"
            ) from None

    def issue(
        self,
        *,
        proposal: AgentProposal,
        evaluation: TrustedAgentProposalEvaluation,
        ppmc_evaluation: TrustedAgentPpmcEvaluation,
        sql: str,
        state: DisclosureState,
        grammar: FutureActionGrammar,
    ) -> AgentPreExecutionProofCapsule:
        """Build and authenticate one security-owned proof handoff capsule."""

        stable_code = "AGENT_PROOF_HANDOFF_INTERNAL_FAILED"
        proof = None
        try:
            proof = self._proof_authority.build(
                proposal=proposal,
                evaluation=evaluation,
                ppmc_evaluation=ppmc_evaluation,
                sql=sql,
                state=state,
                grammar=grammar,
            )
            return seal_agent_preexecution_proof_capsule(
                proof,
                integrity_key=self._provenance_integrity_key,
            )
        except AgentPreExecutionProofAuthorityError as error:
            stable_code = error.code
            _detach_exception(error)
        except AgentPreExecutionProofCapsuleError as error:
            stable_code = "AGENT_PROOF_HANDOFF_SEAL_FAILED"
            _detach_exception(error)
        except Exception as error:
            _detach_exception(error)

        proposal = None  # type: ignore[assignment]
        evaluation = None  # type: ignore[assignment]
        ppmc_evaluation = None  # type: ignore[assignment]
        sql = None  # type: ignore[assignment]
        state = None  # type: ignore[assignment]
        grammar = None  # type: ignore[assignment]
        proof = None
        self = None  # type: ignore[assignment]
        raise AgentProofHandoffAuthorityError(stable_code) from None


def _detach_exception(error: BaseException) -> None:
    error.__traceback__ = None
    error.__context__ = None
    error.__cause__ = None
    error.__suppress_context__ = True
