"""API-key authentication, request identity, and scope enforcement primitives."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
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


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
