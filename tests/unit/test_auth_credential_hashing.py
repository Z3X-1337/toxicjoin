"""API-key credential hashing must be keyed, not a bare general-purpose hash.

CodeQL (py/weak-sensitive-data-hashing, CWE-327/CWE-916) flagged auth.py's credential hash as
insecure because it classifies the presented value as password-like. It is not: API keys here
are 32-512 character random tokens (see ApiKeyCredentialConfig.api_key), and a slow KDF would
tax every request for no real benefit against that entropy. The actual gap worth closing was
that the hash was unkeyed, so a leak of the stored hash list alone was enough to attempt
offline verification of guesses. These tests pin the fix: the stored/compared digest is HMAC'd
with a process-local pepper, not the bare hash, while authentication behaviour is unchanged.
"""

from __future__ import annotations

import hashlib

import pytest

from toxicjoin.auth import (
    ApiKeyAuthenticator,
    ApiKeyCredentialConfig,
    AuthenticationError,
    AuthScope,
    _CREDENTIAL_HASH_PEPPER,
    _sha256_text,
)


KEY = "k" * 48


def _authenticator() -> ApiKeyAuthenticator:
    return ApiKeyAuthenticator(
        (
            ApiKeyCredentialConfig(
                credential_id="cred-1",
                api_key=KEY,
                principal_id="analyst-1",
                scopes=(AuthScope.SYSTEM_READ,),
            ),
        )
    )


def test_stored_digest_is_not_the_bare_sha256_of_the_key() -> None:
    """The security property CodeQL's finding actually calls for: keying, not slow-hashing."""

    bare = hashlib.sha256(KEY.encode("utf-8")).hexdigest()
    keyed = _sha256_text(KEY)

    assert keyed != bare


def test_hash_is_keyed_with_the_process_local_pepper() -> None:
    import hmac as hmac_module

    expected = hmac_module.new(
        _CREDENTIAL_HASH_PEPPER,
        KEY.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    assert _sha256_text(KEY) == expected


def test_authentication_still_succeeds_for_the_correct_key() -> None:
    authenticated = _authenticator().authenticate(KEY)

    assert authenticated.identity.principal_id == "analyst-1"
    assert authenticated.has_scope(AuthScope.SYSTEM_READ)


def test_authentication_still_rejects_the_wrong_key() -> None:
    with pytest.raises(AuthenticationError):
        _authenticator().authenticate("wrong-key-of-sufficient-length-000000000")


def test_leaked_stored_hash_alone_cannot_be_matched_without_the_pepper() -> None:
    """The property that actually matters: a hash-list leak alone verifies nothing offline."""

    stored_digest = _sha256_text(KEY)
    attacker_guess_without_pepper = hashlib.sha256(KEY.encode("utf-8")).hexdigest()

    assert attacker_guess_without_pepper != stored_digest
