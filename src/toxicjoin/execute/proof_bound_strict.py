"""Public strict constructor for proof-bound execution authorization."""

from __future__ import annotations

import hmac
from collections.abc import Callable

from toxicjoin.execute.authorization import ExecutionAuthorizationError
from toxicjoin.execute.proof_bound_authorization import (
    ProofBoundExecutionAuthorizer as _ProofBoundExecutionAuthorizerBase,
)
from toxicjoin.proofs.agent_provenance import (
    AgentProofProvenanceError,
    require_agent_ppmc_provenance,
)


class ProofBoundExecutionAuthorizer(_ProofBoundExecutionAuthorizerBase):
    """Proof-bound authorizer with distinct keys and mandatory Governed-Agent provenance."""

    def __init__(
        self,
        *,
        context_resolver,
        policy_engine,
        privacy_proof_integrity_key: bytes,
        disclosure_ledger=None,
        require_disclosure_commitment: bool = False,
        secret_key: bytes | None = None,
        ttl_seconds: float = 5.0,
        clock: Callable[[], float],
    ) -> None:
        proof_key = bytes(privacy_proof_integrity_key)
        if secret_key is not None and hmac.compare_digest(proof_key, bytes(secret_key)):
            raise ValueError(
                "privacy proof integrity key must differ from execution authorization key"
            )
        super().__init__(
            context_resolver=context_resolver,
            policy_engine=policy_engine,
            privacy_proof_integrity_key=proof_key,
            disclosure_ledger=disclosure_ledger,
            require_disclosure_commitment=require_disclosure_commitment,
            secret_key=secret_key,
            ttl_seconds=ttl_seconds,
            clock=clock,
        )
        if hmac.compare_digest(proof_key, self._secret_key):
            raise ValueError(
                "privacy proof integrity key must differ from execution authorization key"
            )

    def _verify_bound_privacy_proof(self, proof, **kwargs):
        """Authenticate the proof first, then require the bound Agent provenance capability."""

        verified = super()._verify_bound_privacy_proof(proof, **kwargs)
        try:
            require_agent_ppmc_provenance(proof)
        except AgentProofProvenanceError as exc:
            raise ExecutionAuthorizationError(exc.code) from None
        return verified
