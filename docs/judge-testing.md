# ToxicJoin Judge Testing Guide

This guide is designed for a reviewer who has not seen ToxicJoin before. The primary path takes about 90 seconds after the API is running.

## What ToxicJoin proves

Individually acceptable datasets can become sensitive when an AI data agent combines them. ToxicJoin inspects the SQL before execution, grounds the decision in governed column context, and returns one of three deterministic outcomes:

- `ALLOW`: execute through the hardened read-only path.
- `REWRITE`: create a constrained safe query, analyze it again, then execute only after a final `ALLOW`.
- `BLOCK`: stop before the database executor is called.

The LLM has no decision authority. The demo uses only synthetic data.

## Start the deterministic demo

Requirements: Python 3.11 or 3.12.

Linux or macOS:

```bash
bash run.sh
```

Windows PowerShell:

```powershell
.\run.ps1
```

Open:

```text
http://127.0.0.1:8000/docs
```

The health endpoint must disclose `mode: fixture`. Fixture mode is intentional for repeatable judge access and is not represented as a live DataHub run.

## 90-second verification path

### 0:00–0:10 — Confirm the service and mode

Call:

```text
GET /api/health
```

Expected evidence:

- `status: ok`
- `mode: fixture`
- `database_ready: true`
- `receipt_store_ready: true`
- policy version `0.1.0`

### 0:10–0:20 — Load the three curated scenarios

Call:

```text
GET /api/demo/scenarios
```

The response contains exact request payloads for:

1. `block-sensitive-export`
2. `rewrite-churn-regions`
3. `allow-public-order-counts`

Copy a scenario's `request` object into the next endpoint.

### 0:20–0:35 — Prove unsafe individual data never executes

Use `block-sensitive-export` with:

```text
POST /api/execute-safe
```

Expected evidence:

- initial and effective decision: `BLOCK`
- reason includes `COMPOSITIONAL_REIDENTIFICATION_RISK`
- projected combination includes a stable pseudonym, two quasi-identifiers, and a sensitive support attribute
- `verification` is null
- receipt `execution` is null

This is the key negative guarantee: the unsafe SQL never reaches DuckDB.

### 0:35–1:05 — Prove real remediation and execution

Use `rewrite-churn-regions` with:

```text
POST /api/execute-safe
```

Expected evidence:

- initial decision: `REWRITE`
- reason: `SMALL_GROUP_RISK`
- `safe_sql` contains:

```sql
HAVING COUNT(DISTINCT c.customer_id) >= 20
```

- final decision: `ALLOW`
- verification passes
- the real DuckDB result contains three coarse-region groups
- every observed `subject_count` is 40
- the receipt contains execution metadata but no result rows

The rewritten SQL is reparsed, re-grounded, reevaluated, executed read-only, and independently verified. It is not trusted merely because ToxicJoin generated it.

### 1:05–1:20 — Prove benign work is not unnecessarily blocked

Use `allow-public-order-counts` with:

```text
POST /api/execute-safe
```

Expected evidence:

- initial and effective decision: `ALLOW`
- reason: `NO_COMPOSITIONAL_RISK`
- no rewrite
- real bounded result rows returned

### 1:20–1:30 — Verify receipt integrity

Copy the `receipt_id` from any response and call:

```text
GET /api/receipts/{receipt_id}
```

Expected evidence:

- the receipt loads successfully;
- SQL literals are redacted in display text;
- the receipt stores hashes, governed columns, reason codes, verification checks, and execution summary;
- there is no `rows` property in the persisted receipt;
- the content SHA-256 is checked on every read.

## Benchmark evidence

Read:

- [`docs/evidence/benchmark.md`](evidence/benchmark.md)
- [`docs/evidence/benchmark-summary.json`](evidence/benchmark-summary.json)

Or reproduce it:

```bash
toxicjoin-benchmark --output-dir artifacts/benchmark
```

The current CI-generated result is:

- 30 cases: 10 `ALLOW`, 10 `REWRITE`, 10 `BLOCK`;
- 100% initial decision accuracy on the declared corpus;
- 100% effective outcome accuracy;
- 100% expected reason-code coverage;
- zero false allows;
- zero unsafe effective allows;
- six rewrites remediated and executed;
- four rewrite paths failed closed;
- 16 verified executions.

The benchmark is a regression corpus for the declared supported profile, not a claim of universal privacy detection.

## Live DataHub verification

The deterministic demo above can run without Docker. The final submission environment should also include the live DataHub proof described in:

[`docs/datahub-live-integration.md`](datahub-live-integration.md)

The live verification commands are:

```bash
toxicjoin-datahub-seed --yes
toxicjoin-datahub-spike --verify
```

A valid live run must prove:

1. configured DataHub assets were read;
2. governed schema fields and sensitivity labels were read;
3. upstream column lineage was read;
4. a DataHub `Decision` document was written;
5. the first MCP process was closed;
6. a fresh MCP process read the document back and found the unique marker.

Until that live report exists, the repository intentionally leaves checklist item 9 unchecked.

## Security checks reviewers can inspect

- SQL boundary: `src/toxicjoin/sql/`
- deterministic policy: `src/toxicjoin/policy/`
- safe rewrite: `src/toxicjoin/rewrite/`
- read-only execution: `src/toxicjoin/execute/`
- independent verification: `src/toxicjoin/verify/`
- immutable receipts: `src/toxicjoin/receipts/`
- DataHub SDK/MCP integration: `src/toxicjoin/integrations/`
- threat model: [`docs/threat-model.md`](threat-model.md)
- build evidence: [`docs/hackathon-build/build-notes.md`](hackathon-build/build-notes.md)

## Known limitations

- The rewrite engine intentionally supports a narrow, auditable transformation: adding or strengthening a subject-bound minimum-group threshold on an already-grouped query.
- ToxicJoin does not claim general SQL repair, differential privacy, universal re-identification detection, or automatic policy discovery.
- Unsupported or ambiguous SQL fails closed.
- Real organizations must supply their own governed classifications, subject keys, policies, and validation corpus.
