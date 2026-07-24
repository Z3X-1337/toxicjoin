"""Minimal API-key authentication and scope enforcement primitives.

Configuration accepts SHA-256 digests only. Raw API keys are presented only in the
HTTP Authorization header and are never persisted in ToxicJoin configuration or
receipts.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from enum import StrEnum
from typing import Any

from pydantic import Field, field_validator

from toxicjoin.models import StrictModel


AUTH_CONFIG_ENV = "TOXICJOIN_API_KEYS_JSON"


class AuthScope(StrEnum):
    ANALYZE = "analyze"
    EXECUTE = "execute"
    RECEIPTS_READ = "receipts:read"
    RECEIPTS_READ_ANY = "receipts:read:any"


class ApiKeyRecord(StrictModel):
    principal_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$",
    )
    key_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    scopes: tuple[AuthScope, ...]

    @field_validator("scopes")
    @classmethod
    def require_scopes(cls, value: tuple[AuthScope, ...]) -> tuple[AuthScope, ...]:
        if not value:
            raise ValueError("API key record must grant at least one scope")
        if len(value) != len(set(value)):
            raise ValueError("API key record scopes must be unique")
        return value


class AuthenticatedPrincipal(StrictModel):
    principal_id: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$",
    )
    scopes: tuple[AuthScope, ...]

    def has_scope(self, scope: AuthScope) -> bool:
        return scope in self.scopes


class ApiKeyAuthenticator:
    """Authenticate bearer API keys against configured SHA-256 digests."""

    def __init__(self, records: tuple[ApiKeyRecord, ...]) -> None:
        if not records:
            raise ValueError("at least one API key record is required")
        digests = tuple(record.key_sha256 for record in records)
        if len(digests) != len(set(digests)):
            raise ValueError("duplicate API key digests are not allowed")
        self._records = records

    @classmethod
    def from_json(cls, raw: str) -> "ApiKeyAuthenticator":
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("API key configuration must be valid JSON") from exc
        if not isinstance(payload, list):
            raise ValueError("API key configuration must be a JSON array")
        try:
            records = tuple(ApiKeyRecord.model_validate(item) for item in payload)
        except Exception as exc:
            raise ValueError("API key configuration is invalid") from exc
        return cls(records)

    def authenticate(self, raw_key: str) -> AuthenticatedPrincipal | None:
        if not raw_key:
            return None
        presented = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
        matched: ApiKeyRecord | None = None
        for record in self._records:
            if hmac.compare_digest(presented, record.key_sha256):
                matched = record
        if matched is None:
            return None
        return AuthenticatedPrincipal(
            principal_id=matched.principal_id,
            scopes=matched.scopes,
        )


def load_authenticator_from_env(
    environ: dict[str, str] | None = None,
) -> ApiKeyAuthenticator | None:
    source: Any = os.environ if environ is None else environ
    raw = source.get(AUTH_CONFIG_ENV)
    if raw is None or not str(raw).strip():
        return None
    return ApiKeyAuthenticator.from_json(str(raw))


def hash_api_key(raw_key: str) -> str:
    """Return the configuration digest for an API key without storing the raw key."""

    if not raw_key:
        raise ValueError("API key must not be empty")
    return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()
