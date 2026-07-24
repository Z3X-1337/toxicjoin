"""Experimental proof-carrying execution authorization.

This module is intentionally isolated under ``research/``. It explores a stronger
execution boundary than passing an in-memory ``PolicyDecision`` into the executor.

An authorization is content-addressed and HMAC-bound to the exact SQL, parsed plan,
resolved governance snapshot, policy configuration, task, subject key, and expiry.
The executor re-derives those inputs immediately before execution. Any mismatch is a
fail-closed authorization error.

HMAC is used here because it is available in the Python standard library and cleanly
models a trust-kernel secret that is not available to the proposing agent. A future
production design may replace it with asymmetric signing or a KMS-backed primitive.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from typing import Any, Protocol
from uuid import uuid4

from pydantic import Field, field_validator

from toxicjoin.context.models import ContextResolution
from toxicjoin.execute import DuckDBExecutor, ExecutionResult
from toxicjoin.models import ColumnRef, Decision, PolicyDecision, QueryPlan, StrictModel
from toxicjoin.policy import PolicyConfig, PolicyEngine
from toxicjoin.sql import analyze_sql


class ContextResolver(Protocol):
    def resolve(self, query_plan: QueryPlan) -> ContextResolution: ...


class AuthorizationError(RuntimeError):
    """Raised when proof-carrying authorization cannot be issued or verified."""


class ExecutionAuthorization(StrictModel):
    schema_version: str = "1.0"
    authorization_id: str = Field(pattern=r"^auth_[0-9a-f]{32}$")
    issued_at: datetime
    expires_at: datetime
    dialect: str = Field(pattern=r"^[a-zA-Z0-9_-]+$")
    task_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    sql_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    query_plan_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    subject_key_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    context_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_decision_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_version: str = Field(min_length=1)
    effective_decision: Decision
    rewrite_parent_sql_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    authorization_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    mac_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("issued_at", "expires_at")
    @classmethod
    def normalize_datetime(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("authorization timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)


class AuthorizationVerification(StrictModel):
    passed: bool
    failed_checks: tuple[str, ...] = ()
    policy_decision: PolicyDecision | None = None
    recomputed_context_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )


def issue_execution_authorization(
    *,
    sql: str,
    task_purpose: str,
    subject_key: ColumnRef,
    context_resolver: ContextResolver,
    policy_engine: PolicyEngine,
    secret_key: bytes,
    dialect: str = "duckdb",
    ttl_seconds: int = 60,
    rewrite_parent_sql: str | None = None,
    now: datetime | None = None,
) -> ExecutionAuthorization:
    """Issue an authorization only after a fresh deterministic ALLOW evaluation."""

    _validate_secret_key(secret_key)
    if ttl_seconds < 1 or ttl_seconds > 3600:
        raise ValueError("ttl_seconds must be between 1 and 3600")

    issued_at = _utc_now(now)
    query_plan = analyze_sql(sql, dialect=dialect)
    context = context_resolver.resolve(query_plan)
    policy_input = context.to_policy_input(
        task_purpose=task_purpose,
        query_plan=query_plan,
        subject_key=subject_key,
    )
    decision = policy_engine.evaluate(policy_input)
    if decision.decision != Decision.ALLOW or decision.rewrite_required:
        raise AuthorizationError(
            "execution authorization requires a fresh deterministic ALLOW; "
            f"received {decision.decision.value}"
        )

    unsigned: dict[str, Any] = {
        "schema_version": "1.0",
        "authorization_id": f"auth_{uuid4().hex}",
        "issued_at": _datetime_json(issued_at),
        "expires_at": _datetime_json(issued_at + timedelta(seconds=ttl_seconds)),
        "dialect": dialect,
        "task_sha256": _sha256_text(task_purpose),
        "sql_sha256": _sha256_text(sql),
        "query_plan_sha256": _model_sha256(query_plan),
        "subject_key_sha256": _model_sha256(subject_key),
        "context_sha256": _context_sha256(context, context_resolver),
        "policy_sha256": _policy_sha256(policy_engine.config),
        "policy_decision_sha256": _model_sha256(decision),
        "policy_version": decision.policy_version,
        "effective_decision": decision.decision.value,
        "rewrite_parent_sql_sha256": (
            _sha256_text(rewrite_parent_sql) if rewrite_parent_sql is not None else None
        ),
    }
    canonical = _canonical_bytes(unsigned)
    payload = {
        **unsigned,
        "authorization_sha256": hashlib.sha256(canonical).hexdigest(),
        "mac_sha256": hmac.new(secret_key, canonical, hashlib.sha256).hexdigest(),
    }
    return ExecutionAuthorization.model_validate(payload)


def verify_execution_authorization(
    *,
    authorization: ExecutionAuthorization,
    sql: str,
    task_purpose: str,
    subject_key: ColumnRef,
    context_resolver: ContextResolver,
    policy_engine: PolicyEngine,
    secret_key: bytes,
    dialect: str = "duckdb",
    rewrite_parent_sql: str | None = None,
    now: datetime | None = None,
) -> AuthorizationVerification:
    """Re-derive authorization inputs immediately before protected execution."""

    _validate_secret_key(secret_key)
    current_time = _utc_now(now)
    failed: list[str] = []

    unsigned = _unsigned_payload(authorization)
    canonical = _canonical_bytes(unsigned)
    expected_content_hash = hashlib.sha256(canonical).hexdigest()
    expected_mac = hmac.new(secret_key, canonical, hashlib.sha256).hexdigest()

    if not hmac.compare_digest(authorization.authorization_sha256, expected_content_hash):
        failed.append("authorization_content_hash")
    if not hmac.compare_digest(authorization.mac_sha256, expected_mac):
        failed.append("authorization_mac")
    if current_time < authorization.issued_at:
        failed.append("authorization_not_yet_valid")
    if current_time >= authorization.expires_at:
        failed.append("authorization_expired")
    if authorization.dialect != dialect:
        failed.append("dialect")
    if not hmac.compare_digest(authorization.task_sha256, _sha256_text(task_purpose)):
        failed.append("task_purpose")
    if not hmac.compare_digest(authorization.sql_sha256, _sha256_text(sql)):
        failed.append("sql")
    if not hmac.compare_digest(
        authorization.subject_key_sha256, _model_sha256(subject_key)
    ):
        failed.append("subject_key")

    expected_parent = (
        _sha256_text(rewrite_parent_sql) if rewrite_parent_sql is not None else None
    )
    if authorization.rewrite_parent_sql_sha256 != expected_parent:
        failed.append("rewrite_parent")

    query_plan: QueryPlan | None = None
    context: ContextResolution | None = None
    decision: PolicyDecision | None = None
    context_hash: str | None = None

    try:
        query_plan = analyze_sql(sql, dialect=dialect)
    except Exception:
        failed.append("sql_reanalysis")

    if query_plan is not None:
        if not hmac.compare_digest(
            authorization.query_plan_sha256, _model_sha256(query_plan)
        ):
            failed.append("query_plan")
        try:
            context = context_resolver.resolve(query_plan)
        except Exception:
            failed.append("context_resolution")

    if context is not None and query_plan is not None:
        context_hash = _context_sha256(context, context_resolver)
        if not hmac.compare_digest(authorization.context_sha256, context_hash):
            failed.append("governance_context")

        try:
            decision = policy_engine.evaluate(
                context.to_policy_input(
                    task_purpose=task_purpose,
                    query_plan=query_plan,
                    subject_key=subject_key,
                )
            )
        except Exception:
            failed.append("policy_evaluation")

    policy_hash = _policy_sha256(policy_engine.config)
    if not hmac.compare_digest(authorization.policy_sha256, policy_hash):
        failed.append("policy_config")

    if decision is not None:
        if decision.decision != Decision.ALLOW or decision.rewrite_required:
            failed.append("fresh_policy_allow")
        if authorization.policy_version != decision.policy_version:
            failed.append("policy_version")
        if authorization.effective_decision != decision.decision:
            failed.append("effective_decision")
        if not hmac.compare_digest(
            authorization.policy_decision_sha256, _model_sha256(decision)
        ):
            failed.append("policy_decision")

    return AuthorizationVerification(
        passed=not failed,
        failed_checks=tuple(dict.fromkeys(failed)),
        policy_decision=decision,
        recomputed_context_sha256=context_hash,
    )


class AuthorizationBoundDuckDBExecutor:
    """DuckDB executor that rejects work without a fresh matching authorization."""

    def __init__(self, executor: DuckDBExecutor, *, secret_key: bytes) -> None:
        _validate_secret_key(secret_key)
        self.executor = executor
        self._secret_key = bytes(secret_key)

    def execute_authorized(
        self,
        *,
        authorization: ExecutionAuthorization,
        sql: str,
        task_purpose: str,
        subject_key: ColumnRef,
        context_resolver: ContextResolver,
        policy_engine: PolicyEngine,
        dialect: str = "duckdb",
        rewrite_parent_sql: str | None = None,
        now: datetime | None = None,
    ) -> ExecutionResult:
        verification = verify_execution_authorization(
            authorization=authorization,
            sql=sql,
            task_purpose=task_purpose,
            subject_key=subject_key,
            context_resolver=context_resolver,
            policy_engine=policy_engine,
            secret_key=self._secret_key,
            dialect=dialect,
            rewrite_parent_sql=rewrite_parent_sql,
            now=now,
        )
        if not verification.passed or verification.policy_decision is None:
            rendered = ",".join(verification.failed_checks) or "unknown"
            raise AuthorizationError(f"execution authorization rejected: {rendered}")
        return self.executor.execute_allowed(
            sql,
            policy_decision=verification.policy_decision,
            dialect=dialect,
        )


def _unsigned_payload(authorization: ExecutionAuthorization) -> dict[str, Any]:
    payload = authorization.model_dump(mode="json")
    payload.pop("authorization_sha256", None)
    payload.pop("mac_sha256", None)
    return payload


def _context_sha256(
    context: ContextResolution,
    resolver: ContextResolver,
) -> str:
    payload: dict[str, Any] = {
        "resolution": context.model_dump(mode="json"),
    }
    catalog = getattr(resolver, "catalog", None)
    if catalog is not None and hasattr(catalog, "model_dump"):
        payload["catalog"] = catalog.model_dump(mode="json")
    snapshot = getattr(resolver, "snapshot", None)
    if snapshot is not None and hasattr(snapshot, "model_dump"):
        payload["snapshot"] = snapshot.model_dump(mode="json")
    return _sha256_value(payload)


def _policy_sha256(config: PolicyConfig) -> str:
    return _sha256_value(config.model_dump(mode="json"))


def _model_sha256(model: Any) -> str:
    if not hasattr(model, "model_dump"):
        raise TypeError("value is not a Pydantic model")
    return _sha256_value(model.model_dump(mode="json"))


def _sha256_value(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _datetime_json(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _utc_now(value: datetime | None) -> datetime:
    result = value or datetime.now(timezone.utc)
    if result.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    return result.astimezone(timezone.utc)


def _validate_secret_key(secret_key: bytes) -> None:
    if not isinstance(secret_key, bytes) or len(secret_key) < 32:
        raise ValueError("secret_key must contain at least 32 bytes")
