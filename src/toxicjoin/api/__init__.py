"""FastAPI surface for ToxicJoin."""

from toxicjoin.api.app import app, create_app, create_default_pipeline
from toxicjoin.api.auth import (
    AUTH_CONFIG_ENV,
    ApiKeyAuthenticator,
    ApiKeyRecord,
    AuthenticatedPrincipal,
    AuthScope,
    hash_api_key,
    load_authenticator_from_env,
)

__all__ = [
    "AUTH_CONFIG_ENV",
    "ApiKeyAuthenticator",
    "ApiKeyRecord",
    "AuthenticatedPrincipal",
    "AuthScope",
    "app",
    "create_app",
    "create_default_pipeline",
    "hash_api_key",
    "load_authenticator_from_env",
]
