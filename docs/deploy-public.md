# Deploying a public judge URL

Two deployments are described here and they are **not** interchangeable.

| | Public demo | Live DataHub |
| --- | --- | --- |
| Governance | deterministic synthetic catalog | real DataHub over MCP |
| Warehouse | synthetic, seeded on first request | your governed DuckDB file |
| Auth | open | API keys required, enforced at startup |
| Data | contains no real people | real |
| Purpose | a reviewer clicks a link and it works | production |

Everything below the governance source is identical in both: the same parser, policy engine,
read-only DuckDB execution, independent verification and authenticated receipts. The public
demo is not a mock — it is the real pipeline over data that cannot harm anyone.

---

## 1. Public demo (recommended for judging)

### Current Public Demo

[**https://toxicjoin-public-demo.onrender.com/**](https://toxicjoin-public-demo.onrender.com/)
is the current public judge link. It was externally verified on **2026-08-13** with health and
readiness checks, the deployment verifier, ALLOW/BLOCK browser scenarios, and an idle cold-start.
It runs a deterministic synthetic fixture through the real ToxicJoin execution path; it is neither
a mock nor a Live DataHub service, and it has no organization data or credentials.

The retained Vercel URL, https://toxicjoin-replay.vercel.app/, remains a **Historical
Deterministic Replay** only. It is not the current public demo and must not be described as live
execution.

### Render Free (this public-demo branch only)

This branch's `render.yaml` defines exactly one Docker **Web Service** with `plan: free`. It
defines no Render Postgres database, persistent disk, add-on, secret, paid instance, or
keep-alive process. Create the Blueprint from this branch only after the Render creation screen
shows a total of **$0.00** and asks for no payment method. Keep manual deploys enabled; the
service must not deploy automatically on subsequent pushes.

The service explicitly runs `TOXICJOIN_MODE=fixture`, so it initializes the deterministic
synthetic judge warehouse using the real parser, policy engine, read-only executor, independent
verification, and authenticated receipt code path. It cannot start the Live DataHub path because
this deployment has no DataHub endpoint, token, warehouse, or write-back authority.

Render Free services sleep after 15 idle minutes. The first incoming request after sleep is
therefore expected to cold-start the service; no keep-alive or periodic ping is configured. The
runtime directory is intentionally `/tmp/toxicjoin`, so the synthetic DuckDB file, receipts, and
fixture disclosure ledger are recreated after a restart, redeploy, or idle spin-down. This is
temporary demo state only, not persistent audit evidence and not a substitute for a Live DataHub
deployment.

### Verify the deployment, do not assume it

```bash
curl -fsS https://<your-host>/api/health
curl -fsS https://<your-host>/api/ready | jq '{status, mode, policy_version, database_ready}'
```

Then open the URL and run the two `Attack —` presets in the live console. If they return
**BLOCK** with `UNTRUSTED_SUBJECT_KEY` and `REWRITE_FAILED`, the deployment is serving the
hardened engine and not a stale image.

---

## 2. Why the public demo stays open

The synthetic warehouse contains no real people and no direct identifiers, so handing out a
credential would add friction without adding protection. Fixture mode is labelled as such in
`/api/ready` and in every receipt (`mode: fixture`), so nothing about it is ambiguous.

Two settings are still raised from their defaults, because the defaults assume a credentialed
API rather than a public audience:

| Variable | Default | Public demo | Why |
| --- | --- | --- | --- |
| `TOXICJOIN_RATE_LIMIT_REQUESTS` | 60 | 240 | reviewers arrive in bursts |
| `TOXICJOIN_MAX_CONCURRENT_PER_PRINCIPAL` | 2 | 8 | several presets clicked at once |

Traffic budgets for unauthenticated callers are keyed per peer address, so one visitor cannot
exhaust the deployment for everyone. The shared `fixture:anonymous` *identity* is unchanged —
receipts and cumulative disclosure history must not be partitioned by network address.

---

## 3. Live DataHub deployment

Live mode refuses to start unless it can acquire a governed snapshot, and refuses to exist
without authentication. Both are deliberate: a server that came up anyway would be advertising
governance it cannot supply.

### Prerequisites

1. **A reachable DataHub GMS** from the container network.
2. **Role-separated tokens.** `DATAHUB_GMS_READ_TOKEN` is the only one on the request path.
3. **Tagged assets.** Categories are read from DataHub tags and glossary terms through a fixed
   map. An untagged field resolves to `UNCLASSIFIED` and **blocks** — correct fail-closed
   behaviour, and the most common reason a first live run refuses everything.

   | Tag or glossary term | Category |
   | --- | --- |
   | `toxicjoinDirectIdentifier`, `directIdentifier` | `DIRECT_IDENTIFIER` |
   | `toxicjoinStablePseudonym`, `stablePseudonym`, `stableCustomerIdentifier` | `STABLE_PSEUDONYM` |
   | `toxicjoinQuasiIdentifier`, `quasiIdentifier` | `QUASI_IDENTIFIER` |
   | `toxicjoinSensitiveAttribute`, `toxicjoinFinancial`, `toxicjoinSensitiveSupport`, `toxicjoinSensitivityLevel`, `toxicjoinModelOutput` | `SENSITIVE_ATTRIBUTE` |
   | `toxicjoinPublicOrLowRisk`, `publicOrLowRisk` | `PUBLIC_OR_LOW_RISK` |

   Matching ignores case, colons and dashes, so `toxicjoin:stable-pseudonym` works too.
   Conflicting categories on one field fail closed rather than picking a winner.

4. **A URN manifest** at `config/datahub-assets.json` mapping logical table names to dataset
   URNs, with a flagship dataset and column whose upstream lineage must resolve.
5. **A governed DuckDB warehouse.** Live mode will not seed one — it refuses to start rather
   than put synthetic rows under real governance.

### Configuration

```bash
TOXICJOIN_MODE=live
TOXICJOIN_DATABASE=/var/lib/toxicjoin/warehouse.duckdb
TOXICJOIN_DATAHUB_ASSET_MAP=config/datahub-assets.json
TOXICJOIN_DATAHUB_SNAPSHOT_MAX_AGE_SECONDS=300

DATAHUB_GMS_URL=https://datahub.internal:8080
DATAHUB_GMS_READ_TOKEN=<read-scoped token>
DATAHUB_MCP_COMMAND=uvx
DATAHUB_MCP_ARGS=--from mcp-server-datahub==0.6.0 mcp-server-datahub

TOXICJOIN_API_KEYS_JSON=<see below>
TOXICJOIN_ALLOWED_HOSTS=your-host.example
TOXICJOIN_RECEIPT_HMAC_KEY=<at least 32 random bytes>
TOXICJOIN_TRUSTED_PROXY_IPS=<see Operating notes - only if you sit behind a reverse proxy>
```

`TOXICJOIN_API_KEYS_JSON` is a JSON array; keys are 32–512 characters and are never stored in
plaintext by the authenticator:

```json
[{"credential_id":"analyst-1","api_key":"<32+ chars>","principal_id":"analyst-1","scopes":["analyze","execute","receipts:read","system:read"]}]
```

Set it as a secret (`fly secrets set`, Render secret env var), never in a committed file.

### Operating notes

- **Snapshot freshness.** A background refresher reinstalls the snapshot at half the freshness
  window. A failed refresh deliberately leaves the previous snapshot in place — installing a
  degraded one would turn an outage into silent governance drift. The old snapshot then
  expires on schedule and requests fail closed with `DATAHUB_CONTEXT_STALE`.
- **Readiness covers the refresher.** `/api/ready` reports degraded if the refresh loop has
  died, even while the current snapshot is still valid, because that deployment is minutes
  away from refusing everything.
- **Persist the runtime directory.** Receipts are audit evidence and the disclosure ledger is
  cumulative privacy state; losing the volume resets every principal's budget.
- **The disclosure budget is active.** Authenticated deployments enforce stateful privacy, so a
  principal gets `TOXICJOIN_DISCLOSURE_MAX_PROTECTED_RELEASES` protected releases (default 5)
  per `TOXICJOIN_DISCLOSURE_BUDGET_WINDOW_SECONDS` (default 24h). Raise it before a live demo
  or a reviewer's sixth query will return `CUMULATIVE_BUDGET_EXHAUSTED` and look like a fault.
- **Set `TOXICJOIN_TRUSTED_PROXY_IPS` if a reverse proxy or load balancer sits in front of
  this service.** The pre-auth failure limiter keys on `request.client.host`; left unset
  (the default), X-Forwarded-* headers are never trusted and that value is always the direct
  TCP peer — correct only when nothing sits between the caller and this process. Behind any
  proxy that is *not* on `127.0.0.1` in the same network namespace, every caller collapses
  onto the proxy's own address and one bad credential from anyone throttles everyone
  (`AUTH_FAILURE_LIMIT_EXCEEDED`) for the whole fleet. Set it to the proxy's address or CIDR
  (comma-separated for more than one hop) once you've confirmed that proxy itself sets
  `X-Forwarded-For` from the real client and does not pass through a caller-supplied one —
  trusting a proxy that forwards an attacker's own header verbatim defeats the throttle
  instead of fixing it.

### What live mode does not do

The executor is DuckDB-only and its dialect is pinned in three places, with external access
and extensions disabled. Snowflake, BigQuery and Postgres cannot be queried directly; their
data must be materialized into a DuckDB file first. Adding another warehouse means a new
executor and a fresh security review of it, because the containment guarantees rest on
DuckDB's read-only connection.
