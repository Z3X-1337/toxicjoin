"""Public verifier wrapper that carries one privacy proof through authorization and execution."""

from __future__ import annotations

from typing import Any

from toxicjoin.execute import DuckDBExecutor
from toxicjoin.proofs import PreExecutionPrivacyProof
from toxicjoin.verify.engine import VerificationResult
from toxicjoin.verify.governance import verify_and_execute as _governance_verify_and_execute


class _PrivacyProofInjectingExecutor:
    """Inject one immutable proof into both capability issuance and consumption."""

    def __init__(
        self,
        *,
        executor: DuckDBExecutor,
        privacy_proof: PreExecutionPrivacyProof,
    ) -> None:
        self._executor = executor
        self._privacy_proof = PreExecutionPrivacyProof.model_validate(
            privacy_proof.model_dump(mode="json")
        )

    def require_authority(self, **kwargs: Any) -> None:
        self._executor.require_authority(**kwargs)

    def issue_authorization(self, sql: str, **kwargs: Any) -> Any:
        supplied = kwargs.get("privacy_proof")
        if supplied is not None and supplied != self._privacy_proof:
            raise ValueError("verifier attempted to substitute a different privacy proof")
        kwargs["privacy_proof"] = self._privacy_proof
        return self._executor.issue_authorization(sql, **kwargs)

    def execute_authorized(self, sql: str, **kwargs: Any) -> Any:
        supplied = kwargs.get("privacy_proof")
        if supplied is not None and supplied != self._privacy_proof:
            raise ValueError("verifier attempted to substitute a different privacy proof")
        kwargs["privacy_proof"] = self._privacy_proof
        return self._executor.execute_authorized(sql, **kwargs)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._executor, name)


def verify_and_execute(
    sql: str,
    *,
    privacy_proof: PreExecutionPrivacyProof | None = None,
    **kwargs: Any,
) -> VerificationResult:
    """Run the existing governance verifier while carrying one exact proof end-to-end.

    When no proof is supplied this is behaviorally identical to the existing governance wrapper.
    A pre-bound ``ProofBoundExecutionAuthorizer`` still fails closed because its issue method
    requires a proof. When a proof is supplied, the same immutable artifact is injected into both
    issue and consume calls under the governance wrapper's existing exact-snapshot pinning.
    """

    executor = kwargs.get("executor")
    if privacy_proof is None:
        return _governance_verify_and_execute(sql, **kwargs)
    if not isinstance(executor, DuckDBExecutor):
        raise TypeError(
            "privacy-proof verification requires a DuckDBExecutor execution boundary"
        )

    bound_executor = _PrivacyProofInjectingExecutor(
        executor=executor,
        privacy_proof=privacy_proof,
    )
    forwarded = dict(kwargs)
    forwarded["executor"] = bound_executor
    return _governance_verify_and_execute(sql, **forwarded)
