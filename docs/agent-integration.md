# Integrating ToxicJoin in an AI Data Agent Workflow

ToxicJoin belongs on the **execution boundary**, not inside an agent's free-form reasoning loop.

```text
agent proposes analytical SQL
        ↓
ToxicJoin resolves governed context and evaluates policy
        ↓
only effective ALLOW may release accepted data
```

The agent's model output, tool-selection reasoning, or confidence score is never authorization.

## Recommended HTTP boundary

| Endpoint | Purpose | Database execution |
|---|---|---:|
| `GET /api/health` | Minimal process liveness only | No |
| `GET /api/ready` | Detailed enforcement readiness | No |
| `POST /api/analyze` | Preview deterministic policy and any supported rewrite | No |
| `POST /api/execute-safe` | Full policy → rewrite → re-evaluate → authorize → execute → verify path | Only after effective `ALLOW` |
| `GET /api/receipts/{receipt_id}` | Retrieve and integrity-check an owned decision receipt | No |

`/api/health` intentionally returns only:

```json
{"status":"ok"}
```

Do not use liveness as proof that the database, receipt store, governance snapshot, or stateful privacy ledger is ready.

Use `/api/ready` for that. In authenticated/LIVE deployments it requires the `system:read` scope; the zero-auth fixture judge can call it directly.

## Request contract

`/api/analyze` and `/api/execute-safe` accept the same strict request model:

```json
{
  "task_purpose": "Find regions with elevated churn risk",
  "sql": "SELECT ...",
  "subject_key": {
    "dataset": "customers",
    "field_path": "customer_id",
    "alias": "c"
  },
  "dialect": "duckdb"
}
```

Important semantics:

- `sql` is untrusted input;
- governed execution is DuckDB-only;
- `subject_key` identifies the governed subject namespace used by threshold and cumulative-disclosure controls;
- the subject key must bind to the query's physical source domain; ambiguity fails closed;
- unknown request fields are rejected.

## Preferred one-call pattern

For an autonomous agent, prefer `/api/execute-safe` rather than `analyze → execute elsewhere`.

```bash
curl --fail-with-body \
  -H 'Content-Type: application/json' \
  -X POST http://127.0.0.1:8000/api/execute-safe \
  -d '{
    "task_purpose": "Find regions with elevated churn risk",
    "sql": "SELECT c.coarse_region, AVG(r.churn_score) AS average_churn, COUNT(DISTINCT c.customer_id) AS subject_count FROM customers c JOIN retention_scores r ON c.customer_id = r.customer_id GROUP BY c.coarse_region",
    "subject_key": {
      "dataset": "customers",
      "field_path": "customer_id",
      "alias": "c"
    },
    "dialect": "duckdb"
  }'
```

Branch on `effective_decision`:

```text
ALLOW   → consume data only when the ToxicJoin-controlled execution and verification path succeeded.
BLOCK   → stop; never retry the original SQL through another warehouse tool.
REWRITE → do not execute externally; ToxicJoin must reparse, reground, reevaluate, and reach effective ALLOW itself.
```

A `safe_sql` string alone is not authority.

## Authentication and scope separation

When API authentication is configured, ToxicJoin separates:

- `analyze`;
- `execute`;
- `receipts:read`;
- `system:read`.

Receipts are principal-owned. Cross-principal lookup returns the same `404 RECEIPT_NOT_FOUND` surface as a nonexistent receipt.

Authenticated execution also activates persistent cumulative-disclosure state. Credential or session rotation cannot be used to reset the governed privacy history for the same principal/agent/subject scope.

## Response authority

`POST /api/analyze` and `POST /api/execute-safe` return a `PipelineResponse` containing deterministic decision evidence, parsed plans, optional safe SQL, verification evidence, and a sanitized receipt.

The controlling conditions are:

1. final `effective_decision == ALLOW`;
2. if execution occurred, independent verification passed;
3. the returned/persisted receipt passed integrity validation.

Do not infer success from HTTP 200 alone; controlled BLOCK responses intentionally use a normal response body.

## Critical anti-bypass rule

This integration is unsafe:

```text
ToxicJoin BLOCK
      ↓
agent retries the same SQL with another warehouse credential/tool
```

All protected analytical execution must be routed through the guarded boundary. In a real deployment, identity, network, and warehouse permissions should prevent the autonomous agent from bypassing ToxicJoin.

## Governance boundary

The packaged fixture judge uses deterministic local governance for repeatability. It is never presented as live DataHub.

The stable live path is proven separately against DataHub OSS and the official MCP Server. Production integrations should preserve these invariants:

1. parse SQL before governance lookup;
2. resolve referenced physical datasets and fields;
3. acquire governed tags, terms, and lineage from a bounded snapshot;
4. fail closed on missing, conflicting, incomplete, stale, or ambiguous context;
5. bind governance provenance through authorization and execution;
6. never send raw sensitive warehouse rows to an LLM;
7. keep deterministic policy outside model control;
8. write only sanitized institutional memory back to DataHub;
9. verify write-back from a fresh read-only process.

See:

- [`architecture.md`](architecture.md)
- [`evidence/datahub-live.md`](evidence/datahub-live.md)
- [`evidence/governance-dependency.md`](evidence/governance-dependency.md)
- [`evidence/release-candidate.md`](evidence/release-candidate.md)
- [`../skills/compositional-risk-review/SKILL.md`](../skills/compositional-risk-review/SKILL.md)

## Receipt handling

Retrieve an owned receipt with:

```bash
curl --fail-with-body http://127.0.0.1:8000/api/receipts/<receipt_id>
```

The receipt store verifies the content hash on read. Missing/invisible receipts return 404; integrity failure returns 409. Returned warehouse rows are deliberately excluded from persisted receipts.

## Operational readiness

Use both endpoints for different purposes:

```bash
curl --fail-with-body http://127.0.0.1:8000/api/health
curl --fail-with-body http://127.0.0.1:8000/api/ready
```

- `/api/health` answers only whether the process is alive.
- `/api/ready` verifies the configured database, receipt store, stateful privacy state when required, and live-governance freshness when in LIVE mode.

A degraded enforcement service must be treated as unavailable rather than bypassed.

## Explicit boundaries

The reference implementation does not claim:

- universal SQL support;
- universal re-identification detection;
- arbitrary SQL repair;
- differential privacy;
- a hosted multi-tenant production control plane;
- that a static browser artifact is live execution;
- that organization-specific IAM, network, or warehouse authorization is solved by the demo package.

The final exact-head validation record is in [`evidence/release-candidate.md`](evidence/release-candidate.md).
