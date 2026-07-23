# ToxicJoin Governance Dependency Evidence

## Result

The governance-dependency gate passed in GitHub Actions on **July 23, 2026**.

- Workflow: `Governance Dependency Evidence`
- GitHub Actions run: https://github.com/Z3X-1337/toxicjoin/actions/runs/30046357658
- Tested branch commit: `6b08319a52127f68894728ebb605041d5f153a4f`
- Artifact: `toxicjoin-governance-dependency`
- Artifact ID: `8579270246`
- Artifact digest: `sha256:f0348e427a7134b8f5710d80e020d42163100194514886339ef2b67166e73fab`
- Retained machine-readable report: [`governance-dependency.json`](governance-dependency.json)
- Report SHA-256: `5466c06f7ff926eafb897ab18c121ef241a4bc539bd2cf037c4437637ea414a5`

## What this proves

The evaluation holds the following constant across every case:

- the exact SQL request;
- the deterministic synthetic warehouse and data fingerprint;
- the subject key;
- the ToxicJoin policy;
- the SQL parser and rewriter;
- the DuckDB executor;
- independent verification.

Only the **normalized governance state** changes.

| Governance state | Initial decision | Effective decision | Database executed? | Gate |
|---|---:|---:|---:|---:|
| Complete governed context | `REWRITE` | `ALLOW` | Yes, after verification | PASS |
| `retention_scores.churn_score` unclassified | `BLOCK` | `BLOCK` | No | PASS |
| `retention_scores.churn_score` missing from governed schema | `BLOCK` | `BLOCK` | No | PASS |
| `retention_scores` missing from governed datasets | `BLOCK` | `BLOCK` | No | PASS |

Measured unsafe effective allows under degraded governance: **0**.

With complete governance, the flagship query was rewritten, reevaluated, independently verified, and then executed. The execution returned three coarse-region groups with observed distinct-subject counts of **40, 40, and 40**.

With incomplete governance, ToxicJoin failed closed before database execution using `UNCLASSIFIED_COLUMN`, `UNRESOLVED_COLUMN`, or `UNRESOLVED_DATASET` evidence as appropriate.

## Why this is DataHub-relevant

This gate is deliberately a deterministic **causality test**, not a second live DataHub deployment. ToxicJoin's live DataHub MCP adapter normalizes DataHub entities, schema fields, tags, glossary terms, ownership, and lineage into the same `FixtureCatalog` governance contract consumed by this policy path.

The separate [live DataHub evidence](datahub-live.md) proves that a real DataHub OSS deployment was read through the official MCP Server, normalized, used for lineage/context inspection, written back with a real DataHub `Decision`, and independently read back from a fresh MCP process.

Together, the two evidence sets establish different properties:

1. **Live integration proof:** ToxicJoin really reads and writes DataHub.
2. **Governance dependency proof:** changing only governed context changes whether the same request is rewritten and executed or blocked before execution.

This is stronger than demonstrating metadata lookup alone: governed context is on the authorization path.

## Scope and limitation

This evaluation proves fail-closed behavior when required governance is absent or unclassified. It does **not** claim ToxicJoin can independently determine that a confidently but incorrectly governed sensitivity label is wrong; that would require an additional source of truth or separate governance-quality controls.

The test contains no real personal data. It uses the same deterministic synthetic warehouse as the main benchmark.

## Reproduce

```bash
python -m pip install -e '.[dev]'
toxicjoin-governance-proof --output-dir artifacts/governance-dependency
```

The command exits non-zero if any required case regresses or if degraded governance produces an unsafe effective `ALLOW`.
