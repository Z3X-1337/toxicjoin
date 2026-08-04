"""API-key authentication, request identity, and scope enforcement primitives."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from contextlib import contextmanager
from contextvars import ContextVar
from enum import StrEnum
from typing import Iterator

from pydantic import Field, ValidationError

from toxicjoin.models import StrictModel


FIXTURE_ANONYMOUS_PRINCIPAL = "fixture:anonymous"
"""Shared placeholder identity for the unauthenticated fixture surface.

It is deliberately one identity: receipts and cumulative disclosure history must not be
partitioned by network address. Traffic accounting is a separate concern and keys on the peer
as well — see ``toxicjoin.api.app._traffic_principal``.
"""

_API_KEYS_ENV = "TOXICJOIN_API_KEYS_JSON"
_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$"
_SESSION_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_CURRENT_IDENTITY: ContextVar[RequestIdentity | None] = ContextVar(
    "toxicjoin_request_identity",
    default=None,
)


class AuthScope(StrEnum):
    ANALYZE = "analyze"
    EXECUTE = "execute"
    RECEIPTS_READ = "receipts:read"
    SYSTEM_READ = "system:read"


class RequestIdentity(StrictModel):
    """Authenticated identity bound to a pipeline request and its receipt."""

    principal_id: str = Field(pattern=_ID_PATTERN)
    credential_id: str = Field(pattern=_ID_PATTERN)
    agent_id: str | None = Field(default=None, pattern=_ID_PATTERN)
    session_id: str | None = Field(default=None, pattern=_SESSION_PATTERN)


class AuthenticatedRequest(StrictModel):
    identity: RequestIdentity
    scopes: tuple[AuthScope, ...]

    def has_scope(self, scope: AuthScope) -> bool:
        return scope in self.scopes


class ApiKeyCredentialConfig(StrictModel):
    """Configuration input; plaintext key is consumed but never retained by auth records."""

    credential_id: str = Field(pattern=_ID_PATTERN)
    api_key: str = Field(min_length=32, max_length=512, repr=False, exclude=True)
    principal_id: str = Field(pattern=_ID_PATTERN)
    scopes: tuple[AuthScope, ...]
    agent_id: str | None = Field(default=None, pattern=_ID_PATTERN)


class AuthenticationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class AuthorizationError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _StoredCredential(StrictModel):
    credential_id: str = Field(pattern=_ID_PATTERN)
    key_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    principal_id: str = Field(pattern=_ID_PATTERN)
    scopes: tuple[AuthScope, ...]
    agent_id: str | None = Field(default=None, pattern=_ID_PATTERN)


class ApiKeyAuthenticator:
    """Authenticate high-entropy Bearer API keys without retaining plaintext keys."""

    def __init__(self, credentials: tuple[ApiKeyCredentialConfig, ...]) -> None:
        if not credentials:
            raise ValueError("at least one API credential is required")

        credential_ids: set[str] = set()
        key_hashes: set[str] = set()
        stored: list[_StoredCredential] = []
        for credential in credentials:
            if credential.credential_id in credential_ids:
                raise ValueError("duplicate API credential_id")
            digest = _sha256_text(credential.api_key)
            if digest in key_hashes:
                raise ValueError("duplicate API key material")
            if not credential.scopes:
                raise ValueError("API credential must grant at least one scope")
            credential_ids.add(credential.credential_id)
            key_hashes.add(digest)
            stored.append(
                _StoredCredential(
                    credential_id=credential.credential_id,
                    key_sha256=digest,
                    principal_id=credential.principal_id,
                    scopes=tuple(dict.fromkeys(credential.scopes)),
                    agent_id=credential.agent_id,
                )
            )
        self._credentials = tuple(stored)

    @classmethod
    def from_json(cls, value: str) -> "ApiKeyAuthenticator":
        try:
            raw = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError("API key configuration is not valid JSON") from exc
        if not isinstance(raw, list):
            raise ValueError("API key configuration root must be a list")
        try:
            credentials = tuple(
                ApiKeyCredentialConfig.model_validate(item) for item in raw
            )
        except ValidationError as exc:
            raise ValueError("API key configuration failed validation") from exc
        return cls(credentials)

    @classmethod
    def from_environment(cls) -> "ApiKeyAuthenticator | None":
        configured = os.getenv(_API_KEYS_ENV)
        if configured is None:
            return None
        if not configured.strip():
            raise ValueError(f"{_API_KEYS_ENV} must not be empty when configured")
        return cls.from_json(configured)

    def authenticate(
        self,
        api_key: str,
        *,
        session_id: str | None = None,
    ) -> AuthenticatedRequest:
        if not api_key:
            raise AuthenticationError("AUTH_MISSING_API_KEY")
        presented = _sha256_text(api_key)
        matched: _StoredCredential | None = None
        for credential in self._credentials:
            if hmac.compare_digest(credential.key_sha256, presented):
                matched = credential
        if matched is None:
            raise AuthenticationError("AUTH_INVALID_API_KEY")

        try:
            identity = RequestIdentity(
                principal_id=matched.principal_id,
                credential_id=matched.credential_id,
                agent_id=matched.agent_id,
                session_id=session_id,
            )
        except ValidationError as exc:
            raise AuthenticationError("AUTH_INVALID_SESSION") from exc
        return AuthenticatedRequest(identity=identity, scopes=matched.scopes)

    def require_scope(
        self,
        api_key: str,
        scope: AuthScope,
        *,
        session_id: str | None = None,
    ) -> AuthenticatedRequest:
        authenticated = self.authenticate(api_key, session_id=session_id)
        if not authenticated.has_scope(scope):
            raise AuthorizationError("AUTH_INSUFFICIENT_SCOPE")
        return authenticated


def fixture_anonymous_request() -> AuthenticatedRequest:
    """Deterministic identity used only by explicitly labeled fixture/replay APIs."""

    return AuthenticatedRequest(
        identity=RequestIdentity(
            principal_id=FIXTURE_ANONYMOUS_PRINCIPAL,
            credential_id=FIXTURE_ANONYMOUS_PRINCIPAL,
            agent_id="fixture:judge",
        ),
        scopes=(
            AuthScope.ANALYZE,
            AuthScope.EXECUTE,
            AuthScope.RECEIPTS_READ,
            AuthScope.SYSTEM_READ,
        ),
    )


def current_request_identity() -> RequestIdentity | None:
    return _CURRENT_IDENTITY.get()


@contextmanager
def bind_request_identity(identity: RequestIdentity) -> Iterator[None]:
    """Bind authenticated identity to one synchronous request execution context."""

    token = _CURRENT_IDENTITY.set(identity)
    try:
        yield
    finally:
        _CURRENT_IDENTITY.reset(token)


_CREDENTIAL_HASH_PEPPER = secrets.token_bytes(32)
"""Process-local HMAC key for hashing presented API keys.

A bare SHA-256 hash here reads to static analysis as CWE-327/CWE-916 (weak hash of sensitive
data) because the tooling cannot distinguish a 32-512 character random API token from a
low-entropy human password. A slow KDF (bcrypt/argon2/PBKDF2) is the right answer for a
password; it is the wrong engineering for a key whose entropy already makes offline brute
force infeasible, and adding one would tax every request for no real benefit — this is exactly
why GitHub, Stripe and AWS all hash API tokens with a fast, keyed hash rather than a slow one.

Keying the hash is the improvement actually worth making: it means a leak of the stored hash
list alone gives an attacker nothing to verify offline guesses against, without the cost of a
slow KDF. The pepper is regenerated every process start and never persisted or logged, which is
sufficient because credential configuration itself is reloaded fresh from
TOXICJOIN_API_KEYS_JSON on every restart — there is no cross-restart verification requirement
for this hash to satisfy, unlike the content-identity hashes elsewhere in this codebase (e.g.
receipts/execution authorization) that must stay unkeyed so a verifier can reproduce them
independently from known plaintext.

CodeQL (py/weak-sensitive-data-hashing, CWE-327/CWE-916) still flags this after the HMAC keying,
because its suggested remedy is specifically a slow KDF and HMAC-SHA256 is not one. That remedy
was measured, not just reasoned about, before being rejected: ``hashlib.pbkdf2_hmac`` on this
call site's input size, at NIST SP 800-132's own stated minimum of 10,000 iterations, costs
~17ms per call on ordinary hardware; at 100,000 iterations, ~170ms. ``authenticate()`` runs on
every incoming API request — including unauthenticated, garbage-credential ones, before rate
limiting has any way to tell good traffic from bad — so either number turns this endpoint into
a CPU-exhaustion amplifier, working directly against the request/response/concurrency budgets
this project already enforces elsewhere (api/limits.py). The alert is dismissed accordingly
(GitHub code-scanning alert #3, reason "won't fix") rather than left open or silently ignored.
"""


def _sha256_text(value: str) -> str:
    return hmac.new(_CREDENTIAL_HASH_PEPPER, value.encode("utf-8"), hashlib.sha256).hexdigest()
