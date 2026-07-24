# Threat-Model Delta — P1-D Secure API Surface

Date: 2026-07-24

## Change

ToxicJoin now separates process liveness from dependency readiness and reduces the externally visible application surface for authenticated and LIVE deployments.

### Public liveness

`GET /api/health` is intentionally minimal and does not touch the database, receipt store, policy engine, or DataHub context:

```json
{"status":"ok"}
```

It does not expose the package version, runtime mode, policy version, database state, or receipt-store state.

### Protected readiness

`GET /api/ready` performs dependency readiness checks and returns the existing detailed readiness contract. It requires the explicit `system:read` scope whenever authentication is configured. The zero-configuration fixture judge receives `system:read` through its fixed `fixture:anonymous` identity.

A degraded readiness result returns HTTP 503 while process liveness remains HTTP 200. This prevents an orchestrator from confusing a live process with a temporarily unavailable dependency and removes dependency topology from the public liveness endpoint.

### Auxiliary surface

When an authenticator is configured, or when the pipeline runs in LIVE mode:

- `/docs` is not registered;
- `/redoc` is not registered;
- `/openapi.json` is not registered;
- `/api/demo/scenarios` is not registered;
- `/api/benchmark/summary` is not registered;
- the service root returns only the product name and does not disclose package version or documentation location.

The unauthenticated fixture/judge deployment intentionally retains docs, demo scenarios, and benchmark evidence for evaluation UX.

### Browser policy

The CSP no longer permits external script/style origins. The bundled judge interface uses same-origin application assets, so the policy is reduced to:

- `script-src 'self'`;
- `style-src 'self' 'unsafe-inline'`;
- same-origin connection policy;
- no frames, objects, or forms.

The remaining inline-style allowance is a frontend compatibility decision and is not widened to any external origin.

### Host boundary

Authenticated or LIVE surfaces install Starlette `TrustedHostMiddleware`.

`TOXICJOIN_ALLOWED_HOSTS` may contain a comma-separated allowlist. Wildcard `*`, URLs, paths, whitespace-bearing patterns, empty lists, and excessively large lists are rejected. The secure default allows only:

- `localhost`;
- `127.0.0.1`;
- `testserver` for deterministic test execution.

A real externally addressed LIVE deployment must explicitly configure its expected hostnames.

### TLS boundary

ToxicJoin does **not** become a TLS terminator in this phase.

When the ASGI request scheme is HTTPS, the application emits:

```text
Strict-Transport-Security: max-age=31536000; includeSubDomains
```

Production deployments must terminate TLS at a trusted ingress/reverse proxy or ASGI server and must configure proxy/forwarded-header trust so the application cannot be tricked into treating untrusted HTTP as trusted HTTPS. HSTS is therefore conditional on the scheme that reaches the application.

## Threats reduced

- **Public topology disclosure:** liveness no longer reveals mode, policy version, database state, receipt-store state, or package version.
- **Readiness enumeration:** detailed dependency state requires `system:read` when authentication is configured.
- **Documentation/schema enumeration:** authenticated/LIVE deployments do not expose OpenAPI or interactive documentation routes.
- **Demo/evidence exposure:** curated demo scenarios and benchmark evidence are absent from authenticated/LIVE surfaces.
- **Host-header abuse:** restricted surfaces reject hosts outside an explicit allowlist.
- **Unnecessary browser supply-chain origin:** unused jsDelivr origins are removed from CSP.
- **Exception-shape disclosure:** pipeline failures expose only the stable `PIPELINE_PERSISTENCE_FAILURE` code, not Python exception type or message.

## Negative security tests

Coverage includes:

- liveness stays HTTP 200 and minimal while readiness is degraded and returns HTTP 503;
- authenticated surfaces return 404 for docs, OpenAPI, demo, and benchmark routes;
- LIVE surfaces independently prove the same restricted route set;
- missing/wrong readiness scope returns stable 401/403 responses;
- `system:read` returns detailed readiness;
- fixture judge retains docs/demo/benchmark without authentication;
- untrusted Host is rejected;
- wildcard Host configuration fails closed;
- HTTPS requests emit HSTS;
- CSP contains no external script/style origin;
- pipeline failures do not expose exception type, message, or internal marker;
- restricted service root does not disclose version or documentation path.

## Residual risk and explicit non-goals

- Host validation is an application control, not a network ACL. Firewall, ingress routing, and private-service exposure remain deployment controls.
- TLS termination, certificate lifecycle, cipher policy, and trusted proxy-header configuration remain deployment responsibilities.
- `style-src 'unsafe-inline'` remains for the current bundled frontend; future frontend hardening may remove it with nonces/hashes or fully externalized styles.
- Public liveness remains intentionally unauthenticated so infrastructure can determine process health. Network-layer rate limiting and access control should protect that endpoint when required by the deployment environment.
- This phase reduces surface disclosure; it does not implement the P2 cumulative-disclosure ledger or cross-query privacy accounting.
