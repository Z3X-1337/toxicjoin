# ToxicJoin Deployment

ToxicJoin deliberately separates the public judge replay from the full execution environment.

## Deployment modes

| Mode | Purpose | Executes DuckDB? | Uses live DataHub? | Publicly claimable evidence |
|---|---|---:|---:|---|
| Hosted replay | Fast judge access and product walkthrough | No | No | UI flow, declared benchmark evidence, receipt structure |
| Fixture container | Full deterministic product execution | Yes, read-only | No | BLOCK / REWRITE / ALLOW behavior, verification, immutable receipts |
| Live DataHub environment | Final integration proof | Yes, read-only | Yes | Metadata reads, lineage reads, Decision write, fresh-session read-back |

The interface displays its mode in the header. A replay must never be presented as a live execution or DataHub write.

## Hosted replay on Vercel

The repository includes `vercel.json`. Vercel builds `apps/web` and serves the static interface. Because no API is deployed with this target, the frontend automatically enters the deterministic replay mode and displays:

```text
API unavailable. Showing a clearly labeled deterministic replay; no live execution or DataHub write is being claimed.
```

The replay includes the three curated outcomes and the committed CI benchmark evidence. It is designed to remain useful even if the full demo environment is temporarily unavailable.

Build locally:

```bash
cd apps/web
npm install --no-audit --no-fund
npm run check
npm run build
```

Vercel project settings, when imported manually:

- Repository: `Z3X-1337/toxicjoin`
- Framework preset: Other
- Root directory: repository root
- Build command: read from `vercel.json`
- Output directory: read from `vercel.json`

## Full fixture execution with Docker

Build and run the combined React + FastAPI + DuckDB image:

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
- stores DuckDB and receipts only in the `toxicjoin-runtime` volume;
- uses a bounded `/tmp` tmpfs;
- exposes the same-origin API and prebuilt judge interface;
- has an application-level health check.

CI performs an external container smoke test. It verifies:

1. non-root identity and read-only root filesystem;
2. page delivery and security headers;
3. health and fixture-mode disclosure;
4. benchmark summary and zero false allows;
5. the flagship `REWRITE → ALLOW` path;
6. three real DuckDB output groups with 40 subjects each;
7. a persisted receipt without raw rows.

## Full live DataHub environment

Follow [`datahub-live-integration.md`](datahub-live-integration.md).

The final evidence gate is:

```bash
toxicjoin-datahub-seed --yes
toxicjoin-datahub-spike --verify
```

The live environment is not considered verified unless the second command:

- reads the configured datasets;
- reads governed fields and lineage;
- writes a DataHub `Decision` document;
- closes the first MCP process;
- opens a new MCP process;
- reads back and verifies the unique marker;
- exits zero and writes the sanitized report.

## Production environment variables

Fixture container:

```text
TOXICJOIN_HOST=0.0.0.0
TOXICJOIN_PORT=8000
TOXICJOIN_RUNTIME_DIR=/var/lib/toxicjoin
TOXICJOIN_WEB_DIST=/app/apps/web/dist
```

Live DataHub variables are documented in `.env.example`. Never commit a populated `.env` file.

## Security headers

The same-origin FastAPI deployment sets:

- `Content-Security-Policy`
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: no-referrer`
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Resource-Policy: same-origin`
- restrictive `Permissions-Policy`

API responses use `no-store`. Fingerprinted Vite assets use immutable one-year caching. HTML uses no-cache.

The Vercel replay applies the equivalent static security and caching policy through `vercel.json`.

## Failure disclosure

- If the API is unavailable, the hosted interface switches to replay and labels it.
- If the full fixture container is unavailable, do not claim execution evidence from the replay.
- If DataHub is unavailable or write-back cannot be independently read, checklist item 9 remains incomplete.
- A failed benchmark, CI run, receipt integrity check, or live spike must not be used as submission evidence.
