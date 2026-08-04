# Hardening Progress Log

Working branch: `fix/p0-privacy-soundness`
Base commit: `5d38ffc` (`ci: make candidate manifest trigger unconditional (#138)`)

This log records every substantive decision made while taking ToxicJoin from "analysis
complete" to "submission ready". It is append-only; entries are not rewritten after the fact.

---

## Phase 1 — Critical privacy-soundness fixes (P0)

### Root cause

Two independently exploitable bypasses released aggregates over cohorts as small as four
distinct customers, with every verification check passing and a signed receipt issued. Both
shared one cause: **the k-anonymity witness was taken from caller-controlled input** instead
of being derived from governed metadata and proven output lineage.

| Attack | Mechanism | Worst observed impact |
| --- | --- | --- |
| Fabricated subject count | `999 AS subject_count` + `HAVING NOT (COUNT(DISTINCT id) >= 20)` | 15 rows released, all checks PASS, on the authenticated + stateful surface |
| Attacker-chosen subject | caller declares `orders.order_id` as `subject_key` | 11 rows released in fixture mode; `ALLOW` from `/api/analyze` even when authenticated |

### Decisions

**D1 — Put the shared subject-category rule in `models.py`, not `disclosure/`.**
The correct check already existed at `disclosure/semantic.py:65` but only ran when the
disclosure ledger was active. `policy/` importing from `disclosure/` would invert the layering
(disclosure depends on policy inputs). The authority now lives in `toxicjoin/models.py` as
`SUBJECT_IDENTIFIER_CATEGORIES`; `disclosure/semantic.py` re-exports `_SUBJECT_CATEGORIES`
from it so existing callers are unaffected.

**D2 — `BLOCK` rather than `REWRITE` for a non-identifier subject.**
The first implementation left the attack as `REWRITE`, which fails closed but is misleading:
it implies generated SQL could repair the request. No rewrite can, because the fault is the
caller's *declaration*, not the query. A new `ReasonCode.UNTRUSTED_SUBJECT_KEY` names the real
fault. Adding an enum member is backward compatible for persisted receipts.

**D3 — Trust only a conjunctive AND spine in `HAVING`.**
The old rule rejected `OR` and nothing else, so `NOT (...)` and
`CASE WHEN ... THEN FALSE ELSE TRUE END` read as satisfied thresholds. Rather than enumerate
hostile constructs, the parser now flattens `HAVING` through `AND`/parentheses only and treats
any threshold comparison found elsewhere as untrusted. This is allowlist-shaped: new SQL
syntax cannot silently become trusted. A threshold that is a genuine top-level conjunct stays
trusted even when other predicates are ANDed beside it, so legitimate queries are unaffected.

**D4 — The rewriter refuses boolean-guarded thresholds.**
Conjoining `COUNT(DISTINCT id) >= 20` onto `NOT (COUNT(DISTINCT id) >= 20)` yields a
contradiction that returns zero groups. That is safe but reports "query returned no groups"
instead of the real cause, so `enforce_minimum_group_size` now raises on the new warning.

**D5 — Verify `subject_count` by lineage, not by name.**
`ProjectionExposure` already recorded, per root output, which governed columns produced it and
how. The verifier ignored it and matched the column *name* from the DuckDB result. It now
requires exactly one exposure named `subject_count` with `kind == AGGREGATE_VALUE` and a
single source column equal to the subject key. A literal produces no exposure at all, so the
attack cannot satisfy it.

**D6 — Fixed the unit fixture rather than the assertion.**
Three `test_policy_engine.py` tests began failing because `build_input` never modeled the
subject column in `all_referenced_context`, so the subject read as unresolved. The helper now
injects a governed subject by default (with a `subject_category` override). Each test's
original intent is preserved; the fixture is simply realistic now.

### Changes

| File | Change |
| --- | --- |
| `src/toxicjoin/models.py` | Added `SUBJECT_IDENTIFIER_CATEGORIES` and `ReasonCode.UNTRUSTED_SUBJECT_KEY` |
| `src/toxicjoin/disclosure/semantic.py` | `_SUBJECT_CATEGORIES` now re-exports the shared authority |
| `src/toxicjoin/policy/engine.py` | Subject category gates threshold trust; `BLOCK` + `UNTRUSTED_SUBJECT_KEY`; `_subject_governed_category`, `_threshold_evidence` |
| `src/toxicjoin/sql/parser.py` | `_conjunctive_terms`, `_threshold_comparison`; boolean-context-aware extraction |
| `src/toxicjoin/rewrite/engine.py` | Refuses `UNTRUSTED_GROUP_THRESHOLD_NON_CONJUNCTIVE` |
| `src/toxicjoin/verify/engine.py` | `_subject_count_is_governed`; lineage-bound `subject_count_output` |
| `tests/conftest.py` | **New.** Session-scoped golden warehouse + per-test copy |
| `tests/security/test_subject_threshold_trust.py` | **New.** 9 regressions for both attacks and the legitimate paths |
| `tests/unit/test_policy_engine.py` | Realistic subject fixture + 2 new tests |

### Verification

- New regressions: **6 fail** against unfixed `src/` (verified via `git stash`), **9 pass** after.
- Adversarial sweep (`probe6`): both bypasses now `BLOCK`, 0 rows released; all six
  previously-blocked compositional attacks still blocked.
- Authenticated end-to-end (`probe9`): `/api/analyze` and `/api/execute-safe` both `BLOCK`.
- Legitimate paths unchanged: flagship `REWRITE -> ALLOW` releases 3 rows; honest threshold
  `ALLOW` releases 3 rows.
- Unit suite: 465 passed (was 463).

---

## Phase 2 — Product hardening (P1)

### D7 — Fix `seed_database` rather than work around it in tests

`seed_database` took ~22s for 840 rows and was called by 28 test modules, which is why the
suite took ~57 minutes. The cost was not the data: `duckdb.executemany` binds parameters row
by row at roughly ten milliseconds per row. Staging each table as CSV and letting DuckDB's
vectorized reader ingest it takes 0.35s for the whole warehouse — and it fixes cold start for
anyone running `run.sh`, not only CI. Row values travel through a file rather than SQL text
and the staging path is a bound parameter, so nothing is interpolated into a statement.

The generated data is unchanged: `data_fingerprint` still equals
`bfeae85c4b238e38012aadc6f4c95d24c7a28bcb1da1c35e8eeef5be28be7d16`, byte-identical to the
committed CI evidence. Only the load path changed.

`tests/conftest.py` additionally builds the warehouse once per session and copies the file
per test (~10ms), so new tests do not pay even the 0.35s.

### D8 — Explicit `web_dist` must not silently fall back

`_resolve_web_dist` tried the explicit argument, then the environment variable, then
`apps/web/dist`. A configured-but-missing directory therefore served whatever build happened
to be in the working tree. That is a deployment hazard (a typo or half-finished deploy serves
a stale UI), and it also made a test pass or fail depending on whether the frontend had been
built. The most explicit source now wins outright; only the unconfigured case probes the
development default.

### D9 — Throttle authentication *failures*, not all pre-auth traffic

The per-principal limiter keys on an identity that does not exist until authentication
succeeds, so credential probing was unmetered. The first implementation metered every
pre-auth request against the peer address, but behind a proxy every client shares one address
and would have throttled its own legitimate traffic. `AuthFailureLimiter` counts only
failures: a valid credential costs nothing. Default 10 failures per 60s, env-configurable,
with a bounded key table so a spoofed-address flood cannot grow memory.

### D10 — The subject namespace already spans datasets

Stateful mode rejected the README's own `allow-public-order-counts` scenario with an opaque
"could not be validated safely". Root cause: `resolve_governed_subject_domain` required the
*declared* subject dataset to be a query source, while the namespace it computes is
`(field_path, category)` — deliberately dataset-independent. The check was stricter than the
model needs. Removing it fixes ordinary queries that reach the same subjects through another
governed table; the scan that follows still fails closed when no source carries the
identifier, which is now covered by its own test.

### D11 — Replace "one protected release, forever" with a bounded budget

`evaluate_composition_history` allowed exactly one protected release per scope for the life of
the ledger, and treats every aggregate as protected. Stateful mode was therefore single-shot:
the second analytical query a principal ever ran was refused. `DisclosureBudget` caps
protected releases inside a rolling window (default 5 per 24h, env-configurable).

This is deliberately a bound, not a proof, and the code says so: ToxicJoin does not claim
differential privacy, and two aggregates over overlapping populations can always be
differenced. The budget makes the residual risk an explicit number instead of an unstated
one. Rules `PROTECTED_RELEASE_WITHIN_BUDGET` and `CUMULATIVE_BUDGET_EXHAUSTED` keep the
decision visible in receipts. `LEGACY_HISTORY_BLOCK` is unchanged — history predating
composition metadata still fails closed regardless of budget.

Eight existing regressions encoded the old limit. Their intent is "the release that exceeds
the allowance is refused", so they are pinned to `DisclosureBudget(max_protected_releases=1)`
and still test that boundary. The behaviour change is recorded here rather than absorbed
silently into a passing suite.

### Verification

| Metric | Before | After |
| --- | --- | --- |
| Full suite | 889 passed / 1 skipped, **57 min** | 916 passed / 1 skipped, **72 s** |
| `seed_database` | 22.0 s | 0.35 s |
| Integration + root | 23 min | 35 s |
