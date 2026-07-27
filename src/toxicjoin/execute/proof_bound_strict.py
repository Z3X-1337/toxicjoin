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
_HASH_CHARS = frozenset("0123456789abcdef")


class ProofBoundExecutionAuthorizer(_ProofBoundExecutionAuthorizerBase):
    """Proof-bound authorizer with separated keys and live warehouse-state rebinding."""

    def __init__(
        self,
        *,
        context_resolver,
        policy_engine,
        privacy_proof_integrity_key: bytes,
        agent_provenance_integrity_key: bytes,
        warehouse_snapshot_provider: Callable[[], str | None] | None = None,
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
        if warehouse_snapshot_provider is not None and not callable(warehouse_snapshot_provider):
            raise ValueError("warehouse snapshot provider must be callable")
        execution_key = (
            None
            if secret_key is None
            else _strict_key(secret_key, name="execution authorization key")
        )
        if hmac.compare_digest(proof_key, provenance_key):
            raise ValueError(
                "Agent provenance integrity key must differ from privacy proof integrity key"
            )
        if execution_key is not None:
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
            secret_key=execution_key,
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
        self._warehouse_snapshot_provider = warehouse_snapshot_provider

    def _verify_bound_privacy_proof(self, proof, **kwargs):
        """Authenticate proof/provenance and rebind it to the current warehouse snapshot."""

        verified = super()._verify_bound_privacy_proof(proof, **kwargs)
        try:
            require_agent_ppmc_provenance(
                proof,
                integrity_key=self._agent_provenance_integrity_key,
            )
        except AgentProofProvenanceError as exc:
            raise ExecutionAuthorizationError(exc.code) from None
        self._require_current_warehouse_snapshot(proof.warehouse_snapshot_sha256)
        return verified

    def _require_current_warehouse_snapshot(self, expected_snapshot_sha256: str | None) -> None:
        provider = self._warehouse_snapshot_provider
        if provider is None:
            raise ExecutionAuthorizationError("AUTH_WAREHOUSE_SNAPSHOT_UNAVAILABLE")
        try:
            current_snapshot_sha256 = provider()
        except Exception:
            raise ExecutionAuthorizationError("AUTH_WAREHOUSE_SNAPSHOT_UNAVAILABLE") from None

        if current_snapshot_sha256 is not None and not _valid_sha256(current_snapshot_sha256):
            raise ExecutionAuthorizationError("AUTH_WAREHOUSE_SNAPSHOT_UNAVAILABLE")
        if expected_snapshot_sha256 is not None and not _valid_sha256(expected_snapshot_sha256):
            raise ExecutionAuthorizationError("AUTH_PRIVACY_PROOF_WAREHOUSE_SNAPSHOT_INVALID")

        if current_snapshot_sha256 is None or expected_snapshot_sha256 is None:
            if current_snapshot_sha256 is expected_snapshot_sha256:
                return
            raise ExecutionAuthorizationError("AUTH_PRIVACY_PROOF_WAREHOUSE_SNAPSHOT_MISMATCH")

        if not hmac.compare_digest(current_snapshot_sha256, expected_snapshot_sha256):
            raise ExecutionAuthorizationError("AUTH_PRIVACY_PROOF_WAREHOUSE_SNAPSHOT_MISMATCH")


def _valid_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(char in _HASH_CHARS for char in value)
    )


def _strict_key(value: bytes, *, name: str) -> bytes:
    if type(value) is not bytes or len(value) < _MIN_KEY_BYTES:
        raise ValueError(f"{name} must be at least 32 bytes")
    return bytes(value)
