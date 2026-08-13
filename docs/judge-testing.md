# ToxicJoin Judge Testing Guide

This guide is for a reviewer who has not seen ToxicJoin before. The primary deterministic fixture path takes about 90 seconds after the service starts.

## Release / evidence identity

The last engineering baseline before the submission-only freeze is Phase 16.

```text
Phase 16 merge on main:
5d297778a9a9caaae0732e7dfb7401a5f380f089

Exact Phase 16 candidate head validated before squash merge:
826881acdb1256a8dd1b1f97fba6dae00369dd0c
```

The exact candidate head completed CI, Python 3.11/3.12, benchmark evidence, PPMC hard-gate evidence, hardened production-container execution, Ground Truth Baseline, CodeQL, Supply Chain Security, Governance Dependency Evidence, Adversarial Mutation Evidence, Compositional Ablation Evidence, and Disclosure Sequence Evidence.

The repository's generated release workflow remains the revision-level release authority. The SHAs above identify the last engineering baseline; later submission-only documentation commits do not imply new runtime behavior.

See [`evidence/submission-freeze.md`](evidence/submission-freeze.md).

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

CI and Docker consume the committed `uv.lock` with `uv sync --frozen` and are the release-reproducible paths.

## 90-second path

### 0:00–0:10 — Liveness and readiness

Call:

```text
GET /api/health
```

Expected:

```json
{"status":"ok"}
```

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

### 0:10–0:20 — Benchmark identity and curated cases

Call:

```text
GET /api/benchmark/summary
```

Expected semantic contract:

- 30 cases: 10 ALLOW / 10 REWRITE / 10 BLOCK;
- zero false allows;
- zero unsafe effective allows.

Then call:

```text
GET /api/demo/scenarios
```

Use the returned request payloads for:

1. `block-sensitive-export`;
2. `rewrite-churn-regions`;
3. `allow-public-order-counts`.

### 0:20–0:35 — Unsafe individual data never executes

Run `block-sensitive-export` through:

```text
POST /api/execute-safe
```

Expected:

- initial `BLOCK`;
- effective `BLOCK`;
- reason includes `COMPOSITIONAL_REIDENTIFICATION_RISK`;
- no successful verification object;
- receipt execution summary is null;
- DuckDB is not reached.

The guarantee is not merely a BLOCK label: the execution path is absent.

### 0:35–1:05 — Rewrite is re-evaluated

Run `rewrite-churn-regions` through:

```text
POST /api/execute-safe
```

Expected:

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
- the receipt contains execution metadata but not raw result rows.

The generated SQL is reparsed, regrounded, reevaluated, authorized, executed read-only, and independently verified. A rewrite is not trusted merely because ToxicJoin produced it.

### 1:05–1:20 — Benign work remains usable

Run `allow-public-order-counts` through:

```text
POST /api/execute-safe
```

Expected:

- initial `ALLOW`;
- effective `ALLOW`;
- reason includes `NO_COMPOSITIONAL_RISK`;
- no rewrite;
- bounded result rows returned.

This is the utility counterexample to blanket denial.

### 1:20–1:30 — Receipt integrity

Copy a returned `receipt_id` and call:

```text
GET /api/receipts/{receipt_id}
```

Expected:

- receipt loads successfully;
- SQL literals are redacted from display text;
- governed evidence, decisions, verification checks, and execution summary remain;
- no raw `rows` property is persisted;
- `content_sha256` binds receipt content;
- `integrity_hmac_sha256` authenticates persisted content;
- reads fail closed on content/HMAC/filename identity mismatch.

Receipt visibility is principal-scoped in authenticated deployments.

## DataHub proof path

Fixture mode is not represented as live DataHub.

For the real DataHub OSS + official MCP path, follow:

[`datahub-live-integration.md`](datahub-live-integration.md)

The retained live evidence demonstrates role-separated DataHub reads, governed schema/lineage context, isolated decision write-back, and fresh read-only persistence verification. It is retained as exact historical integration evidence and must not be relabeled as current-source execution evidence after unrelated vNext changes.

See [`evidence/datahub-live.md`](evidence/datahub-live.md).

## Current staged vNext security architecture

`docs/vnext/**` contains the hardening work developed after the original submission candidate, including:

- proposal-only Governed Agent boundaries;
- authority-authenticated proposal and PPMC handoffs;
- bounded prospective privacy model checking (PPMC);
- pre-execution proof generation and provenance;
- proof-bound single-use execution authorization;
- warehouse-snapshot revalidation between proof and execution;
- protocol-level HMAC domain separation;
- explicit disclosure-state topology verification.

These are real tested components. They are **not** presented as proof that the canonical HTTP runtime has fully migrated to the entire vNext proof chain. The stable runtime and staged vNext architecture remain intentionally separated.

## Cross-query topology boundary

The public SQLite disclosure ledger is supported as `SINGLE_NODE` authoritative state only.

Phase 16 demonstrated that two replicas with separate SQLite files can each make locally correct decisions from incomplete cumulative histories. ToxicJoin therefore rejects a deployment that declares more than one application replica while using the local SQLite disclosure authority.

ToxicJoin does not currently claim a PostgreSQL/shared-authoritative disclosure backend, distributed transactions, Redis-backed global rate limiting, cross-node replay state, or shared receipt/key custody.

## Evidence index

Current submission/freeze boundary:

- [`evidence/submission-freeze.md`](evidence/submission-freeze.md)

Measured and integration evidence:

- [`evidence/benchmark.md`](evidence/benchmark.md)
- [`evidence/adversarial-mutations.md`](evidence/adversarial-mutations.md)
- [`evidence/governance-dependency.md`](evidence/governance-dependency.md)
- [`evidence/compositional-ablation.md`](evidence/compositional-ablation.md)
- [`evidence/datahub-live.md`](evidence/datahub-live.md)

Historical release evidence:

- [`evidence/release-candidate.md`](evidence/release-candidate.md)
- [`evidence/final-security-blackbox.md`](evidence/final-security-blackbox.md)
- [`deploy-public.md`](deploy-public.md)

## Security surfaces reviewers can inspect

- SQL and semantic lineage: `src/toxicjoin/sql/`
- deterministic policy: `src/toxicjoin/policy/`
- safe rewrite: `src/toxicjoin/rewrite/`
- execution authorization/read-only DuckDB: `src/toxicjoin/execute/`
- cumulative disclosure state: `src/toxicjoin/disclosure/`
- independent verification: `src/toxicjoin/verify/`
- SHA + HMAC authenticated receipts: `src/toxicjoin/receipts/`
- DataHub integration: `src/toxicjoin/integrations/`
- governed Agent / PPMC / proof components: `src/toxicjoin/agent/`, `src/toxicjoin/prospective/`, `src/toxicjoin/proofs/`
- threat model: [`threat-model.md`](threat-model.md)

## Known boundaries

- Rewrite supports a narrow, auditable subject-threshold remediation rather than arbitrary SQL repair.
- The public SQLite disclosure state is single-node only; declared multi-replica use fails closed.
- The Render public demo uses a temporary synthetic fixture and is not a Live DataHub environment.
- The complete vNext proof chain is staged architecture, not a claim about the canonical HTTP runtime.
- ToxicJoin does not claim differential privacy, universal SQL repair, universal re-identification detection, formal verification, or legal-compliance certification.
- Unsupported or ambiguous SQL fails closed.
- Real organizations must provide their own governed classifications, subject keys, policies, identities/network controls, snapshot/version strategy, and validation corpus.
