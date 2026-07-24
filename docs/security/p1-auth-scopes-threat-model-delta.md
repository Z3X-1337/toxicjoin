# Threat-Model Delta — P1-A Authentication, Scopes, and Receipt Ownership

Date: 2026-07-24

## Change

The public API security boundary now authenticates Bearer API keys and authorizes explicit scopes before protected operations. Authenticated request identity is propagated with a request-local `ContextVar` and cryptographically included in immutable receipt content. LIVE APIs cannot be created without an authenticator.

Protected operations:

- `POST /api/analyze` requires `analyze`.
- `POST /api/execute-safe` requires `execute`.
- `GET /api/receipts/{receipt_id}` requires `receipts:read` and receipt ownership by principal.

Health, benchmark evidence, and deterministic demo-scenario discovery remain public.

## Assets added or newly protected

- Bearer API-key material supplied through deployment configuration.
- API credential identifiers and scope assignments.
- Authenticated principal, agent, and session identity.
- Receipt ownership metadata.

## Trust-boundary changes

1. Unauthenticated HTTP clients no longer cross into LIVE analysis/execution/receipt access.
2. Authentication and scope evaluation occurs before pipeline invocation.
3. Request identity crosses from FastAPI into receipt construction through request-local context, not through caller-controlled JSON fields.
4. Receipt retrieval checks authenticated principal ownership and returns 404 for cross-principal access to reduce identifier enumeration signal.

## Threats reduced

- **Unauthenticated LIVE execution:** a LIVE app without configured authentication fails at app construction.
- **Credential misuse across capabilities:** analyze, execute, and receipt-read permissions are independent scopes.
- **Receipt horizontal access:** a principal cannot read a receipt owned by another principal even when it knows the receipt ID.
- **Identity forgery through request body:** identity is not part of `PipelineRequest`; it is derived only after Bearer authentication.
- **API-key disclosure through receipts/responses:** plaintext key material is consumed into SHA-256 digests and is excluded from serialized credential configuration, receipts, and responses.
- **Session-label injection:** session identifiers are syntax constrained before being accepted into immutable receipt identity.
- **Fixture-to-LIVE auth bypass:** anonymous fixture identity is available only when no authenticator is configured and the pipeline is not LIVE.

## New attack surface

- Bearer-token parsing and `Authorization` header handling.
- Deployment credential configuration through `TOXICJOIN_API_KEYS_JSON`.
- In-memory API-key digest table.
- Scope checks and principal ownership checks.
- Request-local identity propagation via `ContextVar`.
- New receipt identity fields and receipt schema version 1.1.

## Controls

- Configured API keys must be at least 32 characters.
- Only SHA-256 key digests are retained in authenticator records; comparisons use `hmac.compare_digest`.
- Duplicate credential IDs and duplicate key material are rejected at configuration time.
- Credentials with zero scopes are rejected.
- Malformed or empty configured authentication fails closed rather than silently disabling auth.
- Missing/invalid Bearer token returns 401 with `WWW-Authenticate: Bearer`.
- Insufficient scope returns 403.
- Cross-principal receipt access returns 404.
- LIVE `DecisionReceipt` requires authenticated identity.
- Receipt identity participates in `content_sha256`; changing owner changes the receipt hash.
- Legacy fixture/replay receipts without identity remain readable only when the API itself is running without an authenticator.

## Negative security tests

Coverage includes:

- LIVE app construction without authenticator.
- Missing and invalid Bearer keys.
- Analyze-only credential attempting execution.
- Cross-principal receipt retrieval.
- Malformed session identifier.
- API-key absence from response, receipt, model serialization, and authenticator storage.
- Environment credential parsing and validation.
- Fixture judge operation without Bearer auth, with explicit `fixture:anonymous` ownership.
- Receipt content-hash change after principal tampering.

## Residual risk and explicit non-goals

- API keys are bearer credentials; possession is sufficient for the configured scopes. Key issuance, rotation, revocation APIs, and KMS-backed secret distribution are not implemented in P1-A.
- Transport termination is deployment responsibility; production LIVE deployments must use TLS. P1-A does not add mTLS.
- Rate limiting, per-principal concurrency controls, request-size budgets, and AST-complexity budgets are deliberately deferred to P1-B and must not be claimed as present.
- Authentication is an HTTP/API trust boundary. Process-internal Python callers are treated as trusted application code; they do not gain a separate cryptographic principal proof merely by calling `ToxicJoinPipeline` directly.
- Receipt ownership is principal-level. Multiple credentials belonging to the same principal intentionally share access to that principal's receipts.
- Agent identity is fixed by credential configuration; session identity is caller-supplied metadata validated under the authenticated principal. Fine-grained per-session authorization is not implemented in P1-A.
