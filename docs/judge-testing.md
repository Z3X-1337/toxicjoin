# ToxicJoin Judge Testing Guide

This guide is for a reviewer who has not seen ToxicJoin before. The primary fixture-mode path takes about 90 seconds after the service starts.

## What to verify

ToxicJoin evaluates untrusted analytical SQL before execution, grounds the request in governed context, and returns one deterministic outcome:

- `ALLOW` — execute through the hardened read-only path.
- `REWRITE` — generate a constrained safer query, then parse, ground, and evaluate it again.
- `BLOCK` — stop before DuckDB is called.

The model has no authorization authority. Fixture mode uses synthetic data.

Final audited runtime candidate:

```text
e139fa99bd666505ed83a18188423722405695a2
```

Policy version: `0.2.0`.

## Start the deterministic fixture demo

Requirements: Python 3.11 or 3.12.

Linux/macOS:

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

The launchers are convenience paths. CI and Docker are the release-reproducible paths and consume the committed `uv.lock` with `uv sync --frozen`.

## 90-second path

### 0:00–0:10 — Separate liveness from readiness

Call:

```text
GET /api/health
```

Expected response:

```json
{"status":"ok"}
```

This endpoint is intentionally process-liveness only. It does not disclose runtime mode, package version, database state, policy version, receipt state, or DataHub state.

Then call:

```text
GET /api/ready
```

In the zero-auth fixture demo, expected evidence includes:

- `status: ok`;
- `mode: fixture`;
- `policy_version: 0.2.0`;
- `database_ready: true`;
- `receipt_store_ready: true`;
- `governance_ready: true`.

Authenticated/LIVE deployments require `system:read` for detailed readiness.

### 0:10–0:20 — Confirm the benchmark identity and curated cases

Call:

```text
GET /api/benchmark/summary
```

Expected key evidence:

- `policy_version: 0.2.0`;
- 30 cases: 10 ALLOW / 10 REWRITE / 10 BLOCK;
- zero false allows;
- zero unsafe effective allows;
- report SHA-256 `3aadc0b357db50641c8ffdc0525dde0e3d9159f933abf62a31a6a74b777d1b08`.

This endpoint is the judge-facing path corrected during final repository hygiene; CI keeps it synchronized with the committed benchmark summary.

Then call:

```text
GET /api/demo/scenarios
```

Use the returned request payloads for:

1. `block-sensitive-export`;
2. `rewrite-churn-regions`;
3. `allow-public-order-counts`.

### 0:20–0:35 — Prove unsafe individual data never executes

Run `block-sensitive-export` through:

```text
POST /api/execute-safe
```

Expected evidence:

- initial `BLOCK`;
- effective `BLOCK`;
- reason includes `COMPOSITIONAL_REIDENTIFICATION_RISK`;
- exposure combines a stable pseudonym, quasi-identifiers, and a governed sensitive attribute;
- no successful verification object;
- receipt execution summary is null;
- DuckDB is not reached.

The guarantee is not merely a BLOCK label; the execution path is absent.

### 0:35–1:05 — Prove remediation is re-evaluated

Run `rewrite-churn-regions` through:

```text
POST /api/execute-safe
```

Expected evidence:

- initial `REWRITE`;
- reason includes `SMALL_GROUP_RISK`;
- `safe_sql` contains:

```sql
HAVING COUNT(DISTINCT c.customer_id) >= 20
```

- final `ALLOW`;
- independent verification passes;
- three coarse-region result groups;
- every observed `subject_count` is 40;
- the receipt contains execution metadata but not result rows.

The generated SQL is reparsed, regrounded, reevaluated, authorized, executed read-only, and independently verified.

### 1:05–1:20 — Prove benign work remains usable

Run `allow-public-order-counts` through:

```text
POST /api/execute-safe
```

Expected evidence:

- initial `ALLOW`;
- effective `ALLOW`;
- reason includes `NO_COMPOSITIONAL_RISK`;
- no rewrite;
- bounded result rows returned.

This is the utility counterexample to blanket deny.

### 1:20–1:30 — Verify receipt integrity

Copy a returned `receipt_id` and call:

```text
GET /api/receipts/{receipt_id}
```

Expected evidence:

- receipt loads successfully;
- SQL literals are redacted from display text;
- hashes, governed evidence, decisions, verification checks, and execution summary remain;
- no raw `rows` property is persisted;
- content SHA-256 is verified on read.

Receipt visibility is principal-scoped in authenticated deployments.

## Final benchmark and adversarial evidence

The final runtime candidate `e139fa99…` passed exact-head CI and regenerated the 30-case benchmark under policy `0.2.0`:

- 30/30 expected initial decisions;
- 30/30 expected effective outcomes;
- 30/30 expected reason codes;
- zero false allows;
- zero unsafe effective allows;
- six rewrites remediated to verified ALLOW;
- four rewrite paths failed closed;
- 16 verified executions.

It also passed the exact-head 144-case mutation gate:

- 144/144 initial BLOCK;
- 144/144 effective BLOCK;
- 144/144 intended compositional-risk reason;
- zero database executions;
- zero unsafe allows.

Read:

- [`evidence/benchmark.md`](evidence/benchmark.md)
- [`evidence/adversarial-mutations.md`](evidence/adversarial-mutations.md)
- [`evidence/governance-dependency.md`](evidence/governance-dependency.md)
- [`evidence/compositional-ablation.md`](evidence/compositional-ablation.md)
- [`evidence/release-candidate.md`](evidence/release-candidate.md)

Reproduce the benchmark with:

```bash
toxicjoin-benchmark --output-dir artifacts/benchmark
```

## Live DataHub verification

Fixture mode is not represented as live DataHub.

The real DataHub OSS + official MCP evidence was collected on deep-security baseline:

```text
fe4f8da2579e09bdbfb1d998b92dfea86549733b
```

The only later runtime-source correction is the fixture judge's packaged benchmark evidence constant; no DataHub integration code changed. See [`evidence/release-candidate.md`](evidence/release-candidate.md) for applicability and exact provenance.

For the reproducible stable DataHub dependency profile:

```bash
python -m pip install --disable-pip-version-check 'uv==0.8.4'
uv sync --frozen --extra datahub
```

Then follow [`datahub-live-integration.md`](datahub-live-integration.md).

The retained live evidence proves:

- 5 datasets;
- 19 governed fields;
- 10 controlled tags;
- 7 glossary terms;
- 4 lineage writes;
- spike schema `1.3`;
- 3 upstream lineage relationships;
- 2 lineage-bound fields;
- 6 normalized lineage sources;
- zero unclassified lineage sources;
- role-separated read-only context → isolated effective `save_document` writer → fresh read-only read-back;
- independent Decision persistence verification.

See [`evidence/datahub-live.md`](evidence/datahub-live.md).

## Independent deep validation

Before the benchmark-summary correction, the otherwise identical runtime baseline also passed:

- unchanged frozen external 24-task v2 replay;
- exact-image black-box pentest: 24/24 PASS;
- Disclosure Sequence Evidence for cumulative cross-query privacy;
- Live DataHub OSS/MCP;
- Hosted Replay verification.

The corrected runtime candidate then reran the checks that cover its actual changed surface: CI/Python consistency, Web tests/build, hardened Container, CodeQL, Supply Chain, Governance, Adversarial, and Ablation. All passed.

The authoritative run IDs, artifact IDs/digests, report hashes, and applicability explanation are in [`evidence/release-candidate.md`](evidence/release-candidate.md).

## Security surfaces reviewers can inspect

- SQL and semantic lineage: `src/toxicjoin/sql/`
- deterministic policy: `src/toxicjoin/policy/`
- safe rewrite: `src/toxicjoin/rewrite/`
- execution authorization/read-only DuckDB: `src/toxicjoin/execute/`
- cumulative disclosure state: `src/toxicjoin/disclosure/`
- independent verification: `src/toxicjoin/verify/`
- integrity-checked receipts: `src/toxicjoin/receipts/`
- DataHub integration: `src/toxicjoin/integrations/`
- benchmark summary served to judge UI: `src/toxicjoin/benchmark/evidence.py`
- threat model: [`threat-model.md`](threat-model.md)

## Known boundaries

- Rewrite supports a narrow, auditable subject-threshold remediation rather than arbitrary SQL repair.
- ToxicJoin does not claim differential privacy, universal re-identification detection, or legal-compliance certification.
- Unsupported or ambiguous SQL fails closed.
- Real organizations must provide their own governed classifications, subject keys, policies, identity/network controls, and validation corpus.