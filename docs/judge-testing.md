# ToxicJoin Judge Testing Guide

This guide is for a reviewer who has not seen ToxicJoin before. The primary fixture-mode path takes about 90 seconds after the service is running.

## What to verify

ToxicJoin evaluates untrusted analytical SQL before execution, grounds the request in governed context, and returns one deterministic outcome:

- `ALLOW` — execute through the hardened read-only path.
- `REWRITE` — generate a constrained safer query, then parse, ground, and evaluate it again.
- `BLOCK` — stop before DuckDB is called.

The model has no authorization authority. The fixture demo uses only synthetic data.

Current policy version: `0.2.0`.

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

## 90-second verification path

### 0:00–0:10 — Separate liveness from readiness

Call:

```text
GET /api/health
```

Expected response:

```json
{"status":"ok"}
```

This endpoint is intentionally process-liveness only. It does not disclose the runtime mode, package version, database state, policy version, receipt state, or DataHub state.

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

In authenticated/LIVE deployments, detailed readiness requires the `system:read` scope.

### 0:10–0:20 — Load the three curated scenarios

Call:

```text
GET /api/demo/scenarios
```

The fixture response contains request payloads for:

1. `block-sensitive-export`;
2. `rewrite-churn-regions`;
3. `allow-public-order-counts`.

Copy a scenario's `request` object into `POST /api/execute-safe`.

### 0:20–0:35 — Prove unsafe individual data never executes

Run `block-sensitive-export` through:

```text
POST /api/execute-safe
```

Expected evidence:

- initial decision `BLOCK`;
- effective decision `BLOCK`;
- reason includes `COMPOSITIONAL_REIDENTIFICATION_RISK`;
- the exposure combines a stable pseudonym, quasi-identifiers, and a governed sensitive attribute;
- no successful verification object;
- receipt execution summary is null;
- DuckDB is not reached.

The important guarantee is not merely that the response says BLOCK; the execution path is absent.

### 0:35–1:05 — Prove remediation is re-evaluated

Run `rewrite-churn-regions` through:

```text
POST /api/execute-safe
```

Expected evidence:

- initial decision `REWRITE`;
- initial reason includes `SMALL_GROUP_RISK`;
- `safe_sql` contains:

```sql
HAVING COUNT(DISTINCT c.customer_id) >= 20
```

- final decision `ALLOW`;
- independent verification passes;
- three coarse-region result groups are observed;
- each observed `subject_count` is 40;
- the receipt contains execution metadata but not result rows.

The generated SQL is reparsed, regrounded, reevaluated, authorized, executed read-only, and independently verified. ToxicJoin never trusts a rewrite merely because it generated it.

### 1:05–1:20 — Prove benign work remains usable

Run `allow-public-order-counts` through:

```text
POST /api/execute-safe
```

Expected evidence:

- initial decision `ALLOW`;
- effective decision `ALLOW`;
- reason includes `NO_COMPOSITIONAL_RISK`;
- no rewrite;
- bounded result rows are returned.

This is the utility counterexample to a blanket-deny firewall.

### 1:20–1:30 — Verify receipt integrity

Copy a returned `receipt_id` and call:

```text
GET /api/receipts/{receipt_id}
```

Expected evidence:

- the receipt loads successfully;
- SQL literals are redacted from display text;
- hashes, governed evidence, decisions, verification checks, and execution summary are retained;
- there is no raw `rows` property in the persisted receipt;
- the content SHA-256 is verified on read.

Receipt ownership is principal-scoped in authenticated deployments; another principal receives the same 404 surface as a missing receipt.

## Final benchmark evidence

The exact release candidate `fe4f8da2579e09bdbfb1d998b92dfea86549733b` ran the checked-in 30-case benchmark in CI under policy `0.2.0`.

Result:

- 30 cases: 10 ALLOW / 10 REWRITE / 10 BLOCK;
- 30/30 expected initial decisions;
- 30/30 expected effective outcomes;
- 30/30 expected reason codes;
- zero false allows;
- zero unsafe effective allows;
- six rewrites remediated to verified ALLOW;
- four rewrite paths failed closed;
- 16 verified executions.

Read:

- [`evidence/benchmark.md`](evidence/benchmark.md)
- [`evidence/benchmark-summary.json`](evidence/benchmark-summary.json)
- [`evidence/release-candidate.md`](evidence/release-candidate.md)

Reproduce:

```bash
toxicjoin-benchmark --output-dir artifacts/benchmark
```

## Final adversarial evidence

The exact release candidate also passed the 144-case metamorphic mutation gate:

- 144/144 initial BLOCK;
- 144/144 effective BLOCK;
- 144/144 intended compositional-risk reason;
- zero database executions;
- zero unsafe allows.

See [`evidence/adversarial-mutations.md`](evidence/adversarial-mutations.md).

## Live DataHub verification

Fixture mode is not represented as live DataHub. The final release separately passed a real DataHub OSS + official MCP gate.

For the reproducible live dependency profile:

```bash
python -m pip install --disable-pip-version-check 'uv==0.8.4'
uv sync --frozen --extra datahub
```

Then follow [`datahub-live-integration.md`](datahub-live-integration.md).

The live flow must prove:

1. five configured DataHub assets and all governed schema fields are read;
2. governance tags/terms and upstream column lineage are acquired;
3. the read process exposes no mutation tools;
4. a separate writer is restricted by ToxicJoin to `save_document` only;
5. a DataHub `Decision` is written;
6. the writer process is closed;
7. a fresh read-only MCP process independently reads the persisted marker back.

The final exact-head evidence reports:

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
- effective writer inventory exactly `save_document`;
- independent read-back verified.

See [`evidence/datahub-live.md`](evidence/datahub-live.md).

## Independent release validation

The release was not frozen on CI alone.

The exact candidate also passed:

- the unchanged frozen external 24-task v2 replay;
- an exact-image black-box pentest with 24/24 probes passing;
- disclosure-sequence evidence for cumulative cross-query privacy;
- CodeQL, Bandit, dependency audits, SBOM generation, immutable Action pins, and digest-pinned Docker bases.

The authoritative run IDs, artifact IDs/digests, and report hashes are in [`evidence/release-candidate.md`](evidence/release-candidate.md).

## Security surfaces reviewers can inspect

- SQL and semantic lineage: `src/toxicjoin/sql/`
- deterministic policy: `src/toxicjoin/policy/`
- safe rewrite: `src/toxicjoin/rewrite/`
- execution authorization/read-only DuckDB: `src/toxicjoin/execute/`
- cumulative disclosure state: `src/toxicjoin/disclosure/`
- independent verification: `src/toxicjoin/verify/`
- integrity-checked receipts: `src/toxicjoin/receipts/`
- DataHub integration: `src/toxicjoin/integrations/`
- threat model: [`threat-model.md`](threat-model.md)

## Known boundaries

- The rewrite engine intentionally supports a narrow, auditable subject-threshold remediation rather than arbitrary SQL repair.
- ToxicJoin does not claim differential privacy, universal re-identification detection, or legal-compliance certification.
- Unsupported or ambiguous SQL fails closed.
- Real organizations must provide their own governed classifications, subject keys, policies, identity/network controls, and validation corpus.