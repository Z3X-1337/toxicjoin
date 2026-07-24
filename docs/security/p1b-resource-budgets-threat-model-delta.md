# Threat-Model Delta — P1-B Resource Budgets

Date: 2026-07-24

## Change

ToxicJoin now applies deterministic resource budgets at four layers:

1. API request bodies are bounded before FastAPI JSON/Pydantic parsing.
2. SQL text and parsed AST complexity are bounded before semantic lineage analysis.
3. Authenticated protected operations are rate limited per principal.
4. Concurrent protected operations are capped per principal.

The controls do not change privacy-policy semantics. A query that fits the budgets is evaluated by the same deterministic Policy v0.2 and verification pipeline.

## Default budgets

- API request body: 128 KiB.
- Protected operations: 60 requests per 60 seconds per principal.
- Concurrent protected operations: 2 per principal.
- SQL text: 100,000 UTF-8 bytes.
- SQL AST: 2,000 expression nodes.
- SQL AST depth: 64 levels.

HTTP limits are configurable through:

- `TOXICJOIN_MAX_REQUEST_BYTES`
- `TOXICJOIN_RATE_LIMIT_REQUESTS`
- `TOXICJOIN_RATE_LIMIT_WINDOW_SECONDS`
- `TOXICJOIN_MAX_CONCURRENT_PER_PRINCIPAL`

SQL text/AST budgets are fixed security limits in the current release.

## Threats reduced

- **Oversized JSON/body memory pressure:** the body is capped before framework parsing; both declared `Content-Length` and actual streamed/chunked bytes are enforced.
- **SQL structural complexity abuse:** wide predicate trees, excessive nesting, and oversized SQL are rejected before governance lineage analysis.
- **Authenticated request flooding:** credentials belonging to one principal share a sliding-window rate budget, preventing quota bypass through multiple credentials for the same principal.
- **Per-principal concurrency exhaustion:** a second operation beyond the configured active-operation cap receives 429 before entering the resolver, policy engine, executor, or receipt store.
- **Receipt enumeration pressure:** protected receipt reads use the same principal traffic budget as analyze/execute operations.

## Trust-boundary changes

- The request-body budget sits outside authentication because it must protect the parser before credentials can be evaluated.
- Rate/concurrency checks occur only after successful authentication/scope resolution and are keyed by authenticated `principal_id`, never caller-supplied JSON.
- SQL complexity checks are part of the public `toxicjoin.sql.analyze_sql` path used by pipeline, verifier, executor authorization, and rewrite verification.

## Negative security tests

Coverage includes:

- oversized declared body rejected with HTTP 413 before authentication/persistence;
- chunked body cannot bypass the actual-byte counter;
- SQL byte budget rejection;
- wide AST node-budget rejection;
- deep AST depth-budget rejection;
- two different credentials for one principal share the same rate limit;
- sliding-window recovery after expiry;
- concurrent same-principal request rejected before a second resolver invocation;
- invalid environment budget configuration fails closed.

## Residual risk and explicit non-goals

- The rate/concurrency limiter is in-process. A multi-worker or horizontally scaled deployment must provide a shared/distributed limiter at the deployment layer if a global tenant quota is required.
- Public health, benchmark-summary, and curated demo-scenario endpoints are not principal-metered because they do not cross the governed execution boundary; reverse proxies should still apply network-level abuse protection.
- SQLGlot must tokenize/parse SQL that is already within the 100,000-byte text cap before AST node/depth counts can be measured. Reverse-proxy CPU/time limits remain useful for hostile parsing workloads.
- Resource budgets reduce denial-of-service exposure; they are not billing quotas and do not replace infrastructure-level connection, bandwidth, or process memory limits.
