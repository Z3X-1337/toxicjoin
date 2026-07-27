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

_MIN_KEY_BYTES = 32


class ProofBoundExecutionAuthorizer(_ProofBoundExecutionAuthorizerBase):
    """Proof-bound authorizer with cryptographically separated authority keys."""

    def __init__(
        self,
        *,
        context_resolver,
        policy_engine,
        privacy_proof_integrity_key: bytes,
        agent_provenance_integrity_key: bytes,
        disclosure_ledger=None,
        require_disclosure_commitment: bool = False,
        secret_key: bytes | None = None,
        ttl_seconds: float = 5.0,
        clock: Callable[[], float],
    ) -> None:
        proof_key = _strict_key(
            privacy_proof_integrity_key,
            name="privacy proof integrity key",
        )
        provenance_key = _strict_key(
            agent_provenance_integrity_key,
            name="Agent provenance integrity key",
        )
        if hmac.compare_digest(proof_key, provenance_key):
            raise ValueError(
                "Agent provenance integrity key must differ from privacy proof integrity key"
            )
        if secret_key is not None:
            execution_key = bytes(secret_key)
            if hmac.compare_digest(proof_key, execution_key):
                raise ValueError(
                    "privacy proof integrity key must differ from execution authorization key"
                )
            if hmac.compare_digest(provenance_key, execution_key):
                raise ValueError(
                    "Agent provenance integrity key must differ from execution authorization key"
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
        if hmac.compare_digest(provenance_key, self._secret_key):
            raise ValueError(
                "Agent provenance integrity key must differ from execution authorization key"
            )
        self._agent_provenance_integrity_key = provenance_key

    def _verify_bound_privacy_proof(self, proof, **kwargs):
        """Authenticate the proof, then authenticate and align Agent provenance separately."""

        verified = super()._verify_bound_privacy_proof(proof, **kwargs)
        try:
            require_agent_ppmc_provenance(
                proof,
                integrity_key=self._agent_provenance_integrity_key,
            )
        except AgentProofProvenanceError as exc:
            raise ExecutionAuthorizationError(exc.code) from None
        return verified


def _strict_key(value: bytes, *, name: str) -> bytes:
    if type(value) is not bytes or len(value) < _MIN_KEY_BYTES:
        raise ValueError(f"{name} must be at least 32 bytes")
    return bytes(value)
