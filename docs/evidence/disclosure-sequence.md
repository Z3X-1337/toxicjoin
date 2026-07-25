# ToxicJoin Disclosure Sequence Evidence

**Gate:** PASS  
**Exact final security head:** `536c37c34de7b36495d33f63095585f72e5f4b46`  
**Landed main merge commit:** `ee4991a93070c148e41dd158c952d5f1e9a6ed2c`  
**Policy version:** `0.2.0`  
**Model:** `single-protected-release cumulative composition`

Exact-head provenance:

- workflow run `30143510867`;
- artifact ID `8615254770`;
- artifact digest `sha256:a2b837d01400f85921c9383e4a36786013c677b8b11f107598fe92d7b7498d8b`;
- artifact-level disclosure regression subset: **23 passed**.

The machine-readable report records:

```json
{
  "schema_version": "1.1",
  "policy_version": "0.2.0",
  "model": "single-protected-release cumulative composition",
  "release_candidate_sha": "536c37c34de7b36495d33f63095585f72e5f4b46",
  "passed": true
}
```

## What this gate protects

The final policy treats privacy as stateful across requests rather than assuming each query can be judged independently.

Without a trusted warehouse snapshot/version identity:

- the first new protected release in a privacy scope may proceed when all other policy conditions are satisfied;
- a later new protected release in the same scope fails closed, including a superficially identical release, because the underlying data may have changed and enabled temporal differencing;
- a changed protected release fails closed before execution;
- replay of the same receipt identity is handled separately as idempotency rather than consuming a new release;
- privacy scope is bound to stable principal/agent/subject identity rather than being reset by credential or session rotation.

PR #68 also introduced append-only two-phase release state:

```text
PENDING -> RELEASED
        -> ABORTED
```

`PENDING` participates immediately in composition checks so concurrent requests cannot race around the gate. Failed executions become auditable `ABORTED` records and are excluded from future composition decisions, avoiding permanent privacy-state poisoning. A crash that leaves an outcome unknowable remains fail-closed rather than being automatically expired.

## Scope

This is a deliberately conservative composition model, not differential privacy or general set-relation inference. A future production evolution can bind disclosure history to a trusted warehouse snapshot identity so safe same-snapshot replays can be distinguished from releases against changed data.

For the complete final release chain, see [`release-candidate.md`](release-candidate.md).
