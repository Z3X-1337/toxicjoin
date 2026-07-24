"""Short-lived execution capabilities bound to exact governed query state.

An execution authorization is not a reusable policy decision. It is a single-use,
HMAC-authenticated capability tied to the exact SQL text, analyzed query plan,
resolved governance context, policy configuration, resulting ALLOW decision,
subject key, task purpose, SQL dialect, optional rewrite parent, and expiry.

The authorizer is bound at construction time to one ContextResolver and one
PolicyEngine. Callers therefore cannot substitute a weaker policy or alternate
metadata resolver at execution time.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
from collections.abc import Callable
from typing import Any, Protocol

from pydantic import Field

from toxicjoin.context.models import ContextResolution
from toxicjoin.models import (
    ColumnRef,
    Decision,
    PolicyDecision,
    QueryPlan,
    StrictModel,
)
from toxicjoin.policy import PolicyEngine
from toxicjoin.sql import SqlAnalysisError, analyze_sql


SUPPORTED_EXECUTION_DIALECT = "duckdb"


class ContextResolver(Protocol):
    def resolve(self, query_plan: QueryPlan) -> ContextResolution: ...


class ExecutionAuthorizationError(RuntimeError):
    """Raised when an execution capability cannot be issued or verified."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class ExecutionAuthorization(StrictModel):
    """Single-use capability for one exact governed SQL execution."""

    authorization_id: str = Field(pattern=r"^tj_auth_[0-9a-f]{32}$")
    issued_at: float
    expires_at: float
    dialect: str = Field(pattern=r"^duckdb$")
    sql_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    query_plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    context_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_decision_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    task_purpose_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    subject_key: ColumnRef
    rewrite_parent_sha256: str | None = Field(
        default=None,
        pattern=r"^[0-9a-f]{64}$",
    )
    mac_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ExecutionAuthorizer:
    """Issue and consume exact-query execution capabilities."""

    def __init__(
        self,
        *,
        context_resolver: ContextResolver,
        policy_engine: PolicyEngine,
        secret_key: bytes | None = None,
        ttl_seconds: float = 5.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if ttl_seconds <= 0 or ttl_seconds > 60:
            raise ValueError("execution authorization ttl must be in (0, 60] seconds")
        key = secrets.token_bytes(32) if secret_key is None else bytes(secret_key)
        if len(key) < 32:
            raise ValueError("execution authorization key must be at least 32 bytes")

        self._context_resolver = context_resolver
        self._policy_engine = policy_engine
        self._secret_key = key
        self._ttl_seconds = float(ttl_seconds)
        self._clock = clock
        self._consumed_ids: dict[str, float] = {}
        self._consume_lock = threading.Lock()

    @property
    def context_resolver(self) -> ContextResolver:
        return self._context_resolver

    @property
    def policy_engine(self) -> PolicyEngine:
        return self._policy_engine

    def issue(
        self,
        sql: str,
        *,
        task_purpose: str,
        subject_key: ColumnRef,
        dialect: str = SUPPORTED_EXECUTION_DIALECT,
        rewrite_parent_sql: str | None = None,
    ) -> ExecutionAuthorization:
        """Independently re-evaluate the exact SQL and issue only for ALLOW."""

        _validate_execution_dialect(dialect)
        if not task_purpose.strip():
            raise ExecutionAuthorizationError("AUTH_INVALID_TASK_PURPOSE")

        query_plan = self._analyze(sql, dialect=dialect)
        resolution = self._resolve(query_plan)
        decision = self._evaluate(
            resolution,
            query_plan=query_plan,
            task_purpose=task_purpose,
            subject_key=subject_key,
        )
        if decision.decision != Decision.ALLOW or decision.rewrite_required:
            raise ExecutionAuthorizationError("AUTH_POLICY_NOT_ALLOW")

        now = float(self._clock())
        unsigned = ExecutionAuthorization(
            authorization_id=f"tj_auth_{secrets.token_hex(16)}",
            issued_at=now,
            expires_at=now + self._ttl_seconds,
            dialect=dialect,
            sql_sha256=_sha256_text(sql),
            query_plan_sha256=_hash_query_plan(query_plan),
            context_sha256=_hash_context(resolution),
            policy_sha256=_hash_policy(self._policy_engine),
            policy_decision_sha256=_hash_decision(decision),
            task_purpose_sha256=_sha256_text(task_purpose),
            subject_key=subject_key,
            rewrite_parent_sha256=(
                _sha256_text(rewrite_parent_sql)
                if rewrite_parent_sql is not None
                else None
            ),
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
        dialect: str = SUPPORTED_EXECUTION_DIALECT,
        rewrite_parent_sql: str | None = None,
    ) -> QueryPlan:
        """Verify current state, atomically consume the capability, and return its plan."""

        _validate_execution_dialect(dialect)
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

        resolution = self._resolve(query_plan)
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

    def _analyze(self, sql: str, *, dialect: str) -> QueryPlan:
        try:
            return analyze_sql(sql, dialect=dialect)
        except SqlAnalysisError as exc:
            raise ExecutionAuthorizationError("AUTH_SQL_ANALYSIS_FAILED") from exc

    def _resolve(self, query_plan: QueryPlan) -> ContextResolution:
        try:
            return self._context_resolver.resolve(query_plan)
        except Exception as exc:
            raise ExecutionAuthorizationError("AUTH_CONTEXT_RESOLUTION_FAILED") from exc

    def _evaluate(
        self,
        resolution: ContextResolution,
        *,
        query_plan: QueryPlan,
        task_purpose: str,
        subject_key: ColumnRef,
    ) -> PolicyDecision:
        policy_input = resolution.to_policy_input(
            task_purpose=task_purpose,
            query_plan=query_plan,
            subject_key=subject_key,
        )
        return self._policy_engine.evaluate(policy_input)

    def _mac(self, authorization: ExecutionAuthorization) -> str:
        payload = authorization.model_dump(mode="json")
        payload["mac_sha256"] = ""
        canonical = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return hmac.new(self._secret_key, canonical, hashlib.sha256).hexdigest()


def _validate_execution_dialect(dialect: str) -> None:
    if dialect != SUPPORTED_EXECUTION_DIALECT:
        raise ExecutionAuthorizationError("AUTH_UNSUPPORTED_DIALECT")


def _hash_query_plan(query_plan: QueryPlan) -> str:
    return _hash_json(query_plan.model_dump(mode="json"))


def _hash_decision(decision: PolicyDecision) -> str:
    return _hash_json(decision.model_dump(mode="json"))


def _hash_policy(policy_engine: PolicyEngine) -> str:
    return _hash_json(policy_engine.config.model_dump(mode="json"))


def _hash_context(resolution: ContextResolution) -> str:
    return _hash_json(_normalized_context(resolution))


def _normalized_context(resolution: ContextResolution) -> dict[str, Any]:
    all_context = sorted(
        (
            {
                "key": item.ref.key,
                "category": item.category.value,
                "datahub_urn": item.datahub_urn,
                "tags": sorted(item.tags),
                "glossary_terms": sorted(item.glossary_terms),
                "resolved": item.resolved,
            }
            for item in resolution.all_referenced_context
        ),
        key=lambda item: item["key"],
    )
    projected_context = sorted(item.ref.key for item in resolution.projected_context)
    return {
        "all_referenced_context": all_context,
        "projected_context_keys": projected_context,
        "failures": sorted(reason.value for reason in resolution.failures),
    }


def _hash_json(value: Any) -> str:
    canonical = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
