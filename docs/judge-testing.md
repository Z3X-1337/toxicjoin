# ToxicJoin Judge Testing Guide

This guide is for a reviewer who has not seen ToxicJoin before. The primary deterministic fixture path takes about 90 seconds after the service starts.

## Release identity

Landed `main` merge commit:

```text
ee4991a93070c148e41dd158c952d5f1e9a6ed2c
```

Exact final security-remediation head validated before landing:

```text
536c37c34de7b36495d33f63095585f72e5f4b46
```

PR #68 merged that exact validated head. The merge commit contains it and introduces no file-tree difference relative to it.

Policy version: `0.2.0`.

## What to verify

ToxicJoin evaluates untrusted analytical SQL before execution, grounds the request in governed context, and returns one deterministic outcome:

- `ALLOW` — execute through the hardened read-only path.
- `REWRITE` — generate a constrained safer query, then parse, ground, and evaluate it again.
- `BLOCK` — stop before DuckDB is called.

The model has no authorization authority. Fixture mode uses deterministic synthetic data.

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

### 0:10–0:20 — Confirm benchmark identity and curated cases

Call:

```text
GET /api/benchmark/summary
```

Expected key evidence:

- `policy_version: 0.2.0`;
- 30 cases: 10 ALLOW / 10 REWRITE / 10 BLOCK;
- zero false allows;
- zero unsafe effective allows;
- committed canonical benchmark evidence SHA-256 `3aadc0b357db50641c8ffdc0525dde0e3d9159f933abf62a31a6a74b777d1b08`.

The API deliberately serves the package-owned committed benchmark summary rather than rerunning 30 scenarios on every page load. The final exact security-head CI reran the corpus and reproduced the same decisions, outcomes, reason codes, execution counts, and data fingerprint. Its full report hash is different because receipt identities are intentionally run-specific; see [`evidence/benchmark.md`](evidence/benchmark.md).

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

The guarantee is not merely a BLOCK label: the execution path is absent.

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

The generated SQL is reparsed, regrounded, reevaluated, authorized, executed read-only, and independently verified. A rewrite is not trusted merely because ToxicJoin produced it.

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

This is the utility counterexample to blanket denial.

### 1:20–1:30 — Verify receipt integrity and authenticity

Copy a returned `receipt_id` and call:

```text
GET /api/receipts/{receipt_id}
```

Expected evidence:

- receipt loads successfully;
- SQL literals are redacted from display text;
- governed evidence, decisions, verification checks, and execution summary remain;
- no raw `rows` property is persisted;
- `content_sha256` binds receipt content including identity/timestamp;
- `integrity_hmac_sha256` authenticates the persisted receipt with a secret not stored in the receipt JSON;
- reads fail closed on content/HMAC/filename identity mismatch.

Receipt visibility is principal-scoped in authenticated deployments.

## Final exact-head validation

The final security-remediation head `536c37c…` passed:

| Gate | Run | Result |
|---|---:|---:|
| CI — Python 3.11 / 3.12, Web, benchmark, hardened Container | `30143510873` | PASS |
| CodeQL | `30143510868` | PASS |
| Supply Chain Security | `30143510883` | PASS |
| Governance Dependency Evidence | `30143510866` | PASS |
| Adversarial Mutation Evidence | `30143510877` | PASS |
| Compositional Ablation Evidence | `30143510871` | PASS |
| Disclosure Sequence Evidence | `30143510867` | PASS |
| Live DataHub Evidence | `30143510876` | PASS |
| Independent production-image black-box pentest | `30145592349` | **24/24 PASS** |

Python 3.12 pytest artifact: **309 passed**, with one upstream framework deprecation warning only.

## Final benchmark evidence

The exact final security-head CI rerun produced:

- 30/30 expected initial decisions;
- 30/30 expected effective outcomes;
- 30/30 expected reason codes;
- zero false allows;
- zero unsafe effective allows;
- six rewrites remediated to verified ALLOW;
- four rewrite paths failed closed;
- 16 verified executions;
- data fingerprint `bfeae85c4b238e38012aadc6f4c95d24c7a28bcb1da1c35e8eeef5be28be7d16`;
- exact-run report SHA-256 `3e8ea32a802a6b512be42ddc81b774b34ec0234e7f4ca43ca9be65cc1f398a64`.

The report hash is not expected to be stable across reruns because receipt IDs/timestamps are intentionally unique. The semantic regression contract is the decisions, effective outcomes, reason codes, execution behavior, and declared data fingerprint.

It also passed the 144-mutation adversarial gate with zero unsafe executions.

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

## Final Live DataHub verification

Fixture mode is not represented as live DataHub.

The **exact final security head** passed a real DataHub OSS + official MCP gate in run `30143510876`.

The retained evidence proves:

- 5 datasets;
- 19 governed fields;
- 10 controlled tags;
- 7 glossary terms;
- 4 lineage writes;
- official `mcp-server-datahub==0.6.0`;
- spike schema `1.3`;
- 3 upstream lineage relationships;
- 2 lineage-bound fields;
- 6 normalized lineage sources;
- zero unclassified lineage sources;
- role-separated read-only context -> isolated writer -> fresh read-only read-back;
- raw upstream writer inventory retained honestly;
- mandatory ToxicJoin writer allowlist exposing only `save_document` effectively;
- independent Decision persistence verification.

Final exact-head seed report SHA-256:

```text
538eef1abc7a02d1a0bcc939a51195831e78e8e6cb161400fbc3abf223f5f3b1
```

Final exact-head spike report SHA-256:

```text
6f295f0c399474834d66413353b5218af5c098fdb6f9875088b43011bcd6f292
```

See [`evidence/datahub-live.md`](evidence/datahub-live.md).

For a reproducible stable DataHub dependency profile:

```bash
python -m pip install --disable-pip-version-check 'uv==0.8.4'
uv sync --frozen --extra datahub
```

Then follow [`datahub-live-integration.md`](datahub-live-integration.md).

## Final production-image black-box validation

Validation-only PR #69 built the Docker image from the exact final security head `536c37c…`. The harness lived on an isolated validation branch, resolved PR #68's head at runtime, failed closed if it moved, and was closed without merge after evidence collection.

Run `30145592349`: **24/24 PASS**.

Coverage includes:

- non-root UID and read-only root filesystem;
- dropped Linux capabilities and `no-new-privileges`;
- loopback-only publication in the validation container;
- minimal unauthenticated liveness/security headers;
- restricted production API surface;
- TrustedHost enforcement;
- bearer/session validation and scope separation;
- request-body budget;
- mutating SQL fail-closed with no execution;
- compositional sensitive export blocked before execution;
- legitimate low-risk aggregate execution;
- principal-scoped receipt ownership;
- receipt file mode `0600`;
- persisted-receipt tamper detection;
- malformed/unknown receipt handling;
- rate limiting;
- no test credentials, traceback, or internal source path in observed responses/logs.

See [`evidence/final-security-blackbox.md`](evidence/final-security-blackbox.md) and [`evidence/final-security-blackbox.json`](evidence/final-security-blackbox.json).

## Historical frozen external validation

A separate validation-only run used the unchanged frozen 24-task external workload against the earlier deep-security baseline. It produced one safe ALLOW execution, 23 BLOCK outcomes, zero unsafe MUST_NOT_EXECUTE executions, zero unsafe grouped-sensitive executions, and no patient rows in sanitized evidence.

This remains useful independent workload evidence, but it is intentionally labelled historical. It is **not** relabeled as if it were regenerated on PR #68. The final security head instead has its own exact-head CI, semantic/security regressions, Live DataHub gate, and production-image black-box rerun described above.

## Security surfaces reviewers can inspect

- SQL and semantic lineage: `src/toxicjoin/sql/`
- deterministic policy: `src/toxicjoin/policy/`
- safe rewrite: `src/toxicjoin/rewrite/`
- execution authorization/read-only DuckDB: `src/toxicjoin/execute/`
- cumulative disclosure state: `src/toxicjoin/disclosure/`
- independent verification: `src/toxicjoin/verify/`
- SHA + HMAC authenticated receipts: `src/toxicjoin/receipts/`
- DataHub integration: `src/toxicjoin/integrations/`
- judge benchmark summary: `src/toxicjoin/benchmark/evidence.py`
- threat model: [`threat-model.md`](threat-model.md)

## Known boundaries

- Rewrite supports a narrow, auditable subject-threshold remediation rather than arbitrary SQL repair.
- Without a trusted warehouse snapshot identity, a second new protected release in the same privacy scope fails closed; same-receipt idempotency is separate.
- ToxicJoin does not claim differential privacy, universal re-identification detection, formal verification, or legal-compliance certification.
- Unsupported or ambiguous SQL fails closed.
- Real organizations must provide their own governed classifications, subject keys, policies, identities/network controls, snapshot/version strategy, and validation corpus.
