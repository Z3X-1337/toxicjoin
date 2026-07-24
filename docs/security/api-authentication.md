# API Authentication and Scopes

ToxicJoin accepts bearer API keys for protected HTTP operations. Configuration stores only SHA-256 digests of those keys.

## Configuration

Set `TOXICJOIN_API_KEYS_JSON` to a JSON array. Each record contains:

- `principal_id`: stable audit identity.
- `key_sha256`: lowercase SHA-256 digest of a high-entropy API key.
- `scopes`: explicit permissions.

Example:

```json
[
  {
    "principal_id": "agent-prod-01",
    "key_sha256": "<64 lowercase hex characters>",
    "scopes": ["analyze", "execute", "receipts:read"]
  },
  {
    "principal_id": "security-admin",
    "key_sha256": "<64 lowercase hex characters>",
    "scopes": ["receipts:read", "receipts:read:any"]
  }
]
```

Do not place raw API keys in this configuration. Generate high-entropy raw keys outside ToxicJoin, calculate their SHA-256 digests, store only the digests in `TOXICJOIN_API_KEYS_JSON`, and distribute the raw bearer tokens through your secret-management system.

## Request format

Protected endpoints use:

```text
Authorization: Bearer <raw-api-key>
```

Scopes:

- `analyze` — call `POST /api/analyze`.
- `execute` — call `POST /api/execute-safe`.
- `receipts:read` — read receipts owned by the authenticated principal.
- `receipts:read:any` — administrative cross-principal receipt access; requires `receipts:read` as well.

Health, benchmark summary, and curated fixture scenarios remain public.

## Runtime-mode behavior

- Fixture mode may run without auth for the local/judge demo. Requests use the fixed audit identity `fixture-anonymous`.
- When an authenticator is configured, fixture endpoints are protected exactly like other deployments.
- LIVE and REPLAY HTTP deployments fail closed during application construction if no authenticator is configured.
- Direct Python library calls do not use HTTP authentication and default receipts to principal `local-library` unless a caller explicitly supplies another principal ID.

## Receipt ownership

New receipts use schema version `1.1` and include `principal_id` inside the immutable receipt content hash. An ordinary `receipts:read` caller can retrieve only receipts whose `principal_id` matches the authenticated principal. Cross-owner access returns the same 404 surface as a missing receipt unless the caller also has `receipts:read:any`.

Legacy schema `1.0` receipts without a principal can still be parsed for compatibility but are not owner-readable through ordinary scoped receipt access.
