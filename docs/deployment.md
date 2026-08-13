# ToxicJoin Deployment

Deployment claims are subordinate to the normative product architecture in [`architecture.md`](architecture.md). A deployment procedure does not establish current product identity unless its exact source revision and evidence are recorded.

## Deployment modes and claim boundaries

| Surface | Status | Executes DuckDB? | Uses live DataHub? | Claim boundary |
|---|---|---:|---:|---|
| Render public demo | Current public fixture path | Yes, read-only | No | Synthetic data, temporary state, real policy and verification pipeline |
| Local fixture container | Canonical executable judge path | Yes, read-only | No | Deterministic BLOCK / REWRITE / ALLOW, verification, state, and receipts |
| Live DataHub environment | Stable integration path | Yes, read-only | Yes | Exact-revision metadata, lineage, Decision write, and fresh read-back evidence |
| PostgreSQL disclosure backend | Off-main draft PR #118 | Not wired into canonical API | No | Staged implementation only; not a current-main or production capability |

The UI obtains its scenarios and results from the same-origin API. If the API is unavailable, the
interface reports the failure and offers reconnection; it never substitutes static results.

## Current public Render demo

The only supported public browser URL is:

```text
https://toxicjoin-public-demo.onrender.com/
```

The repository defines exactly one free Docker Web Service in `render.yaml`, sourced from `main`
with automatic deployment disabled. The deployment uses fixture mode, contains no organization
data or credentials, and has no database, disk, add-on, or paid resource.

Before claiming an exact deployed revision, verify the commit shown in Render and run:

```bash
python scripts/verify_deployment.py --base-url https://toxicjoin-public-demo.onrender.com
```

## Building the web interface

Build locally with the committed application lock:

```bash
cd apps/web
npm ci --no-audit --no-fund
npm run check
npm test -- --run
npm run build
```

A public rollout must record the exact source commit, Render deployment event, health/readiness
responses, protected execution verification, browser paths, security headers, and resource cost.

## Full fixture execution with Docker

Build and run the combined React, FastAPI, and DuckDB image:

```bash
docker compose up --build
```

Open:

```text
http://127.0.0.1:8000
```

The container:

- runs as UID/GID `10001:10001`;
- uses a read-only root filesystem in Compose and CI;
- drops all Linux capabilities;
- enables `no-new-privileges`;
- stores DuckDB, disclosure state, and receipts in the runtime volume;
- uses a bounded `/tmp` tmpfs;
- exposes the same-origin API and prebuilt judge interface;
- has an application-level health check.

The fixture path uses deterministic synthetic governance and is not represented as a live external DataHub deployment.

CI black-box evidence must verify at least:

1. non-root identity and read-only root filesystem;
2. page delivery and security headers;
3. health and fixture-mode disclosure;
4. benchmark summary and zero false allows;
5. the flagship `REWRITE → ALLOW` path;
6. real DuckDB output under the bounded fixture;
7. a persisted receipt without raw rows.

## Full live DataHub environment

Follow [`datahub-live-integration.md`](datahub-live-integration.md).

Install the committed profile:

```bash
python -m pip install --disable-pip-version-check 'uv==0.8.4'
uv sync --frozen --extra datahub
```

The retained tested MCP launcher is:

```text
uvx --from mcp-server-datahub==0.6.0 mcp-server-datahub
```

The verification sequence is:

```bash
toxicjoin-datahub-seed --yes
toxicjoin-datahub-spike --verify
```

The environment is not verified unless the spike:

- reads configured datasets;
- reads governed fields and lineage;
- uses role-separated read and write processes;
- writes one sanitized DataHub `Decision`;
- closes the writer;
- opens a fresh read-only MCP process;
- independently reads back the unique marker;
- exits zero and writes the sanitized report.

### Live-evidence revision boundary

The repository retains exact-revision Live DataHub evidence, but the live gate was not rerun on final `main` `1aead67c339c218f5858a9eb9de05868cdc3a0e5`.

An applicability argument that DataHub source and dependencies did not change is useful provenance, but it is not equivalent to exact-final-SHA live execution evidence.

## DataHub credentials

Use distinct variables:

```text
DATAHUB_GMS_URL=http://localhost:8080
DATAHUB_GMS_TOKEN=replace-with-sdk-token
DATAHUB_GMS_READ_TOKEN=replace-with-read-scoped-token
DATAHUB_GMS_WRITE_TOKEN=replace-with-document-write-scoped-token
DATAHUB_MCP_COMMAND=uvx
DATAHUB_MCP_ARGS=--from mcp-server-datahub==0.6.0 mcp-server-datahub
DATAHUB_MCP_TIMEOUT_SECONDS=90
```

- `DATAHUB_GMS_TOKEN` is the SDK or seeding credential.
- `DATAHUB_GMS_READ_TOKEN` is used by read and fresh-read-back MCP processes.
- `DATAHUB_GMS_WRITE_TOKEN` is used only by the isolated writer.
- ToxicJoin does not silently fall back from either MCP role to the SDK token.
- An authentication-disabled local Quickstart may use explicit non-secret placeholders.
- Never commit a populated `.env` file.

## Fixture environment variables

```text
TOXICJOIN_HOST=0.0.0.0
TOXICJOIN_PORT=8000
TOXICJOIN_RUNTIME_DIR=/var/lib/toxicjoin
TOXICJOIN_WEB_DIST=/app/apps/web/dist
```

## PostgreSQL staged boundary

Draft PR #118 contains a shared-authoritative PostgreSQL disclosure ledger and dedicated evidence workflow.

It is not present on current `main`, not selected by the canonical HTTP runtime, and not production-supported. It does not establish distributed receipts, keys, replay prevention, rate limiting, or cross-service transactions.

The current public disclosure authority remains local SQLite and explicitly single-node.

## Security headers

The same-origin FastAPI deployment sets:

- `Content-Security-Policy`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Resource-Policy: same-origin`
- restrictive `Permissions-Policy`

API responses use `no-store`. Fingerprinted Vite assets use immutable caching. HTML uses no-cache.

## Failure disclosure

- If the API is unavailable, the interface may enter replay only when that state is explicitly labeled.
- If the fixture container is unavailable, do not claim execution evidence from a replay.
- If DataHub is unavailable or write-back cannot be independently read, the live integration is not verified.
- A failed benchmark, CI run, receipt-integrity check, browser check, or live spike must not be used as release or submission evidence.
