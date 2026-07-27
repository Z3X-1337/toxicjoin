"""Single-use execution capabilities cryptographically bound to a privacy proof.

This module deliberately extends the existing execution-authorization mechanism rather than
replacing it. The legacy ``ExecutionAuthorizer`` remains available for staged migration, while
``ProofBoundExecutionAuthorizer`` requires a valid ``PreExecutionPrivacyProof`` at both issuance
and consumption. The exact proof commitment is covered by the existing capability HMAC.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from typing import Callable

from pydantic import Field

from toxicjoin.auth import current_request_identity
from toxicjoin.context.governance import GovernanceContextBinding
from toxicjoin.disclosure import (
    DisclosureCommitment,
    DisclosureCommitmentReplay,
    DisclosureLedgerError,
)
from toxicjoin.execute.authorization import (
    SUPPORTED_EXECUTION_DIALECT,
    ExecutionAuthorization,
    ExecutionAuthorizationError,
    ExecutionAuthorizer,
    _hash_context,
    _hash_decision,
    _hash_identity,
    _hash_policy,
    _hash_query_plan,
    _sha256_text,
    _validate_execution_dialect,
)
from toxicjoin.execute.proof_binding import (
    ExecutionPrivacyProofBindingError,
    VerifiedExecutionPrivacyProof,
    verify_execution_privacy_proof,
)
from toxicjoin.models import ColumnRef, Decision, QueryPlan
from toxicjoin.proofs import PreExecutionPrivacyProof

_PROOF_BOUND_EXECUTION_HMAC_DOMAIN = b"toxicjoin:proof-bound-execution-authorization:v1\x00"


class ProofBoundExecutionAuthorization(ExecutionAuthorization):
    """Existing single-use capability plus the exact authenticated privacy-proof commitment."""

    privacy_proof_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ProofBoundExecutionAuthorizer(ExecutionAuthorizer):
    """Issue and consume capabilities only when the exact privacy proof remains valid.

    The proof integrity key is intentionally separate from the execution-authorization HMAC key.
    Possession of one key therefore does not let a caller forge the other artifact class. The
    proof-bound capability MAC also has a protocol domain distinct from legacy execution
    authorization, so accidental reuse of the execution key cannot downgrade a proof-bound
    capability into the legacy verifier protocol.
    """

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
        if len(proof_key) < 32:
            raise ValueError("privacy proof integrity key must be at least 32 bytes")
        if secret_key is not None and hmac.compare_digest(proof_key, bytes(secret_key)):
            raise ValueError(
                "privacy proof integrity key must differ from execution authorization key"
            )
        super().__init__(
            context_resolver=context_resolver,
            policy_engine=policy_engine,
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
        self._privacy_proof_integrity_key = proof_key

    def _mac(self, authorization: ExecutionAuthorization) -> str:
        """Authenticate proof-bound capabilities under their own protocol domain."""

        payload = authorization.model_dump(mode="json")
        payload["mac_sha256"] = ""
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return hmac.new(
            self._secret_key,
            _PROOF_BOUND_EXECUTION_HMAC_DOMAIN + canonical,
            hashlib.sha256,
        ).hexdigest()

    def issue(
        self,
        sql: str,
        *,
        task_purpose: str,
        subject_key: ColumnRef,
        privacy_proof: PreExecutionPrivacyProof | None = None,
        dialect: str = SUPPORTED_EXECUTION_DIALECT,
        rewrite_parent_sql: str | None = None,
        disclosure_commitment: DisclosureCommitment | None = None,
        expected_governance_binding: GovernanceContextBinding | None = None,
    ) -> ProofBoundExecutionAuthorization:
        """Issue only after the exact proof and independently recomputed state agree."""

        _validate_execution_dialect(dialect)
        if not task_purpose.strip():
            raise ExecutionAuthorizationError("AUTH_INVALID_TASK_PURPOSE")
        if privacy_proof is None:
            raise ExecutionAuthorizationError("AUTH_PRIVACY_PROOF_REQUIRED")

        query_plan = self._analyze(sql, dialect=dialect)
        resolution, governance_binding = self._resolve_with_binding(query_plan)
        self._require_expected_governance_binding(
            expected_governance_binding,
            governance_binding,
        )
        decision = self._evaluate(
            resolution,
            query_plan=query_plan,
            task_purpose=task_purpose,
            subject_key=subject_key,
        )
        if decision.decision != Decision.ALLOW or decision.rewrite_required:
            raise ExecutionAuthorizationError("AUTH_POLICY_NOT_ALLOW")

        identity = current_request_identity()
        self._verify_disclosure_commitment(
            disclosure_commitment,
            sql=sql,
            query_plan=query_plan,
            resolution=resolution,
            decision=decision,
            subject_key=subject_key,
            identity=identity,
            dialect=dialect,
        )
        self._revalidate_governance_binding(governance_binding)

        now = float(self._clock())
        proof_binding = self._verify_bound_privacy_proof(
            privacy_proof,
            now=now,
            sql=sql,
            query_plan=query_plan,
            resolution=resolution,
            governance_binding=governance_binding,
            decision=decision,
            task_purpose=task_purpose,
            identity=identity,
            subject_key=subject_key,
        )

        authorization_id = f"tj_auth_{secrets.token_hex(16)}"
        if disclosure_commitment is not None:
            assert self._disclosure_ledger is not None
            try:
                self._disclosure_ledger.claim_commitment(
                    disclosure_commitment,
                    authorization_id,
                )
            except DisclosureCommitmentReplay as exc:
                raise ExecutionAuthorizationError(
                    "AUTH_DISCLOSURE_COMMITMENT_REPLAYED"
                ) from exc
            except (DisclosureLedgerError, ValueError) as exc:
                raise ExecutionAuthorizationError(
                    "AUTH_DISCLOSURE_COMMITMENT_INVALID"
                ) from exc

        expires_at = min(now + self._ttl_seconds, proof_binding.expires_at)
        if expires_at <= now:
            raise ExecutionAuthorizationError("AUTH_PRIVACY_PROOF_EXPIRED")

        unsigned = ProofBoundExecutionAuthorization(
            authorization_id=authorization_id,
            issued_at=now,
            expires_at=expires_at,
            dialect=dialect,
            sql_sha256=_sha256_text(sql),
            query_plan_sha256=_hash_query_plan(query_plan),
            context_sha256=_hash_context(resolution),
            governance_binding=governance_binding,
            policy_sha256=_hash_policy(self._policy_engine),
            policy_decision_sha256=_hash_decision(decision),
            task_purpose_sha256=_sha256_text(task_purpose),
            request_identity_sha256=_hash_identity(identity),
            subject_key=subject_key,
            rewrite_parent_sha256=(
                _sha256_text(rewrite_parent_sql)
                if rewrite_parent_sql is not None
                else None
            ),
            disclosure_commitment=disclosure_commitment,
            privacy_proof_sha256=proof_binding.privacy_proof_sha256,
            mac_sha256="0" * 64,
        )
        return unsigned.model_copy(update={"mac_sha256": self._mac(unsigned)})

    def verify_and_consume(
        self,
        authorization: ExecutionAuthorization,
        sql: str,
        *,
        task_purpose: str,
        subject_key: ColumnRef,
        privacy_proof: PreExecutionPrivacyProof | None = None,
        dialect: str = SUPPORTED_EXECUTION_DIALECT,
        rewrite_parent_sql: str | None = None,
    ) -> QueryPlan:
        """Revalidate proof + current governed state, then consume the capability once."""

        _validate_execution_dialect(dialect)
        if not isinstance(authorization, ProofBoundExecutionAuthorization):
            raise ExecutionAuthorizationError("AUTH_PRIVACY_PROOF_BINDING_REQUIRED")
        if privacy_proof is None:
            raise ExecutionAuthorizationError("AUTH_PRIVACY_PROOF_REQUIRED")

        expected_mac = self._mac(
            authorization.model_copy(update={"mac_sha256": "0" * 64})
        )
        if not hmac.compare_digest(expected_mac, authorization.mac_sha256):
            raise ExecutionAuthorizationError("AUTH_INVALID_MAC")

        now = float(self._clock())
        if authorization.issued_at > now + 1.0:
            raise ExecutionAuthorizationError("AUTH_NOT_YET_VALID")
        if now >= authorization.expires_at:
            raise ExecutionAuthorizationError("AUTH_EXPIRED")
        if authorization.expires_at - authorization.issued_at > self._ttl_seconds + 1e-9:
            raise ExecutionAuthorizationError("AUTH_INVALID_TTL")

        if authorization.dialect != dialect:
            raise ExecutionAuthorizationError("AUTH_DIALECT_MISMATCH")
        if authorization.subject_key != subject_key:
            raise ExecutionAuthorizationError("AUTH_SUBJECT_MISMATCH")
        identity = current_request_identity()
        if authorization.request_identity_sha256 != _hash_identity(identity):
            raise ExecutionAuthorizationError("AUTH_IDENTITY_MISMATCH")
        expected_parent = (
            _sha256_text(rewrite_parent_sql) if rewrite_parent_sql is not None else None
        )
        if authorization.rewrite_parent_sha256 != expected_parent:
            raise ExecutionAuthorizationError("AUTH_REWRITE_PARENT_MISMATCH")
        if authorization.task_purpose_sha256 != _sha256_text(task_purpose):
            raise ExecutionAuthorizationError("AUTH_TASK_MISMATCH")
        if authorization.sql_sha256 != _sha256_text(sql):
            raise ExecutionAuthorizationError("AUTH_SQL_MISMATCH")

        query_plan = self._analyze(sql, dialect=dialect)
        if authorization.query_plan_sha256 != _hash_query_plan(query_plan):
            raise ExecutionAuthorizationError("AUTH_QUERY_PLAN_MISMATCH")

        resolution, governance_binding = self._resolve_with_binding(query_plan)
        self._require_expected_governance_binding(
            authorization.governance_binding,
            governance_binding,
        )
        if authorization.context_sha256 != _hash_context(resolution):
            raise ExecutionAuthorizationError("AUTH_CONTEXT_MISMATCH")
        if authorization.policy_sha256 != _hash_policy(self._policy_engine):
            raise ExecutionAuthorizationError("AUTH_POLICY_MISMATCH")

        decision = self._evaluate(
            resolution,
            query_plan=query_plan,
            task_purpose=task_purpose,
            subject_key=subject_key,
        )
        if decision.decision != Decision.ALLOW or decision.rewrite_required:
            raise ExecutionAuthorizationError("AUTH_POLICY_NOT_ALLOW")
        if authorization.policy_decision_sha256 != _hash_decision(decision):
            raise ExecutionAuthorizationError("AUTH_DECISION_MISMATCH")

        proof_binding = self._verify_bound_privacy_proof(
            privacy_proof,
            now=now,
            sql=sql,
            query_plan=query_plan,
            resolution=resolution,
            governance_binding=governance_binding,
            decision=decision,
            task_purpose=task_purpose,
            identity=identity,
            subject_key=subject_key,
        )
        if authorization.privacy_proof_sha256 != proof_binding.privacy_proof_sha256:
            raise ExecutionAuthorizationError("AUTH_PRIVACY_PROOF_BINDING_MISMATCH")
        if authorization.expires_at > proof_binding.expires_at + 1e-9:
            raise ExecutionAuthorizationError("AUTH_PRIVACY_PROOF_TTL_MISMATCH")

        self._verify_disclosure_commitment(
            authorization.disclosure_commitment,
            sql=sql,
            query_plan=query_plan,
            resolution=resolution,
            decision=decision,
            subject_key=subject_key,
            identity=identity,
            dialect=dialect,
        )
        self._revalidate_governance_binding(authorization.governance_binding)
        if authorization.disclosure_commitment is not None:
            assert self._disclosure_ledger is not None
            try:
                self._disclosure_ledger.verify_authorization_claim(
                    authorization.disclosure_commitment,
                    authorization.authorization_id,
                )
            except (DisclosureLedgerError, ValueError) as exc:
                raise ExecutionAuthorizationError(
                    "AUTH_DISCLOSURE_COMMITMENT_INVALID"
                ) from exc

        with self._consume_lock:
            self._consumed_ids = {
                auth_id: expiry
                for auth_id, expiry in self._consumed_ids.items()
                if expiry > now
            }
            if authorization.authorization_id in self._consumed_ids:
                raise ExecutionAuthorizationError("AUTH_REPLAYED")
            self._consumed_ids[authorization.authorization_id] = authorization.expires_at

        return query_plan

    def _verify_bound_privacy_proof(
        self,
        proof: PreExecutionPrivacyProof,
        *,
        now: float,
        sql: str,
        query_plan: QueryPlan,
        resolution,
        governance_binding: GovernanceContextBinding | None,
        decision,
        task_purpose: str,
        identity,
        subject_key: ColumnRef,
    ) -> VerifiedExecutionPrivacyProof:
        try:
            return verify_execution_privacy_proof(
                proof,
                integrity_key=self._privacy_proof_integrity_key,
                now_epoch_seconds=now,
                sql=sql,
                query_plan=query_plan,
                resolution=resolution,
                governance_binding=governance_binding,
                policy_engine=self._policy_engine,
                policy_decision=decision,
                task_purpose=task_purpose,
                identity=identity,
                subject_key=subject_key,
            )
        except ExecutionPrivacyProofBindingError as exc:
            raise ExecutionAuthorizationError(exc.code) from exc
