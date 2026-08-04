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

---

## Phase 3 — Resolving the unwired 40%

`agent/`, `prospective/`, `proofs/` and `repair/` were ~11,900 lines with no request path
reaching them. Leaving that ambiguous was itself a defect: a reader could not tell which code
was live, and nothing prevented drift in either direction.

### D12 — Wire `agent/`, because it is the product, not research

`GovernedAgent` is a proposal boundary: it converts untrusted planner output into a canonical
proposal and holds no policy engine, authorizer, executor, ledger or DataHub authority. That is
precisely the hackathon's subject and it was sitting unreachable. Two pieces were missing, both
small: a way to build `AgentDataContext` from the resolver the runtime actually uses, and
something to drive propose → decide → feedback → adapt against real verdicts.

`agent/runtime.py` adds both, plus `POST /api/agent/run`. The loop terminates on the
pipeline's decision, never the planner's opinion; an agent that keeps proposing unsafe SQL
just exhausts its budget, which `test_agent_that_never_remediates_exhausts_its_budget_without_releasing`
pins.

`RemediatingTemplatePlanner` is deterministic rather than an LLM on purpose. The property under
test is that *no* planner can widen its own authority, so a model would make the demo
irreproducible while proving nothing extra. Swapping in a real model means implementing
`TrustedPlannerAdapter`; the wrapper revalidates every field either way.

### D13 — Mark the rest experimental, and make the mark machine-checked

Physically moving `prospective/` and `repair/` would break the benchmark hard-gate evidence and
rewrite history across 137 branches for no safety gain. Instead each package states its status
in its module docstring, and `tests/security/test_runtime_module_boundary.py` verifies the
split in both directions: declared-runtime packages must actually be imported by the API, and
experimental packages must declare themselves and must never export an `ExecutionAuthorizer`
subclass.

`proofs/` is a third case and is labelled honestly as **partially wired**: `DuckDBExecutor`
accepts an optional privacy proof and refuses one unless the authority is the strict
proof-bound authorizer, but the shipped pipeline never supplies one. A test asserts the default
authority is *not* proof-bound, so migrating that path forces the claim boundary to be updated
with it.

| Package | Lines | Decision |
| --- | --- | --- |
| `agent/` | ~4,300 | **Wired** — `/api/agent/run`, GUI panel, 7 integration tests |
| `proofs/` | ~1,300 | **Partially wired** — models only; strict path inactive and pinned |
| `prospective/` | ~3,300 | **Experimental** — declared + boundary-tested |
| `repair/` | ~1,600 | **Experimental** — declared + boundary-tested |

---

## Phase 4 — Interactive GUI

The public link was a static replay. Two live panels now sit at the top of the interface:

**Live console** (`QueryConsole.tsx`) — SQL textarea, task purpose, subject dataset/field,
analyze-vs-execute toggle, and five one-click presets. Renders the decision, reason codes,
generated safe SQL, every verification check, released rows, and the receipt id.

**Governed Agent loop** (`AgentLoop.tsx`) — a goal box and three preset goals; renders the
attempt chain with per-attempt verdict, reason codes, SQL and receipt.

### D14 — The console must never fall back to replay

`lib/api.ts` silently answers from the replay bundle when the API is down, which is defensible
for a scripted scenario rail and indefensible for a console: it would present a dead backend as
a working privacy firewall. `lib/console.ts` is a separate transport that always surfaces the
failure, and `console.test.ts` pins that behaviour.

Two presets are the closed bypasses, so a reviewer watches the firewall refuse them live rather
than trusting a changelog. Verified in-browser against the running API:

| Preset | Result | Rows |
| --- | --- | --- |
| Allow — low-risk aggregate | ALLOW | 4 |
| Rewrite — add a subject threshold | ALLOW after rewrite | 3 |
| Block — compositional re-identification | BLOCK `COMPOSITIONAL_REIDENTIFICATION_RISK` | 0 |
| Attack — fabricated subject_count | BLOCK `REWRITE_FAILED` | 0 |
| Attack — caller-chosen weak subject | BLOCK `UNTRUSTED_SUBJECT_KEY` | 0 |

Agent loop, all three goals: BLOCK → adapt → ALLOW, 3 rows released on the final attempt.

---

## Phase 5 — Final verification

### D15 — README leads with the problem, not the disclaimers

The previous opening spent its first twenty lines on what the project does *not* claim. The
honesty is worth keeping, but it made a reviewer work to find out what the thing is. The first
fifteen lines are now: the compositional-risk problem, one command to run it, and the measured
claims. Claim boundaries moved down and into `docs/`.

The Agent Skill's threshold rule was also stale — it said a threshold is untrusted only when
"weakened by an `OR` path", which is exactly the gap the `NOT`/`CASE` bypass used. It now states
the full rule, including that the caller-supplied subject must be validated against governance.

### Stability

Two consecutive full runs: **930 passed, 1 skipped** in 99s and 97s. `ruff check src tests`
clean. Frontend: typecheck clean, 24 tests, production build succeeds.

### Probe results after all phases

| Probe | Before | After |
| --- | --- | --- |
| Inverted `HAVING` (`NOT`, `CASE`) | trusted as threshold 20 | untrusted, `UNTRUSTED_GROUP_THRESHOLD_NON_CONJUNCTIVE` |
| Bypass A — weak subject, fixture mode | ALLOW, 11 rows released | BLOCK, 0 rows |
| Bypass A — `/api/analyze`, authenticated | ALLOW | BLOCK |
| Bypass C — `/api/execute-safe`, authenticated + stateful | ALLOW, 15 rows released | BLOCK, 0 rows |
| Six compositional attacks (CTE, transform, `MIN()`, group-by-pseudonym, `WHERE` singling) | BLOCK | BLOCK (unchanged) |
| Public aggregate on an authenticated deployment | BLOCK, opaque error | ALLOW, rows released |
| Four consecutive protected queries, stateful | 1 allowed then permanently blocked | all four allowed within budget |

---

## Phase 6 — Live DataHub runtime

The governed DataHub path existed as a library and a one-shot CLI but never as a running
service. Three things were missing, and one of them was a latent bug.

### D16 — A failed refresh must never replace the snapshot

`DataHubSnapshotContextResolver` expires after a bounded age and `DataHubSnapshotLoader` can
fetch a new one, but nothing connected them: a live server worked until its first snapshot
aged out, then refused everything with `DATAHUB_CONTEXT_STALE`. Correct, and useless.

`DataHubSnapshotRefresher` refreshes on a daemon thread at half the freshness window, so one
failed attempt still leaves time to retry before expiry. The rule that matters more than the
scheduling is that a failed refresh leaves the existing snapshot untouched. Installing a
partial snapshot would convert an outage into silent governance drift — the pipeline would
keep answering from metadata that no longer reflects DataHub. Instead the old snapshot expires
on its own schedule and the request path fails closed.

### D17 — Live mode is chosen by environment, so `create_app` has to know before startup

The pipeline only materializes during lifespan startup, so `restricted_surface` computed as
`False` for a server launched with `TOXICJOIN_MODE=live` and no credentials: docs exposed, and
the anonymous fixture identity granted every scope **over real governed data**. `create_app`
now recognizes the deferred-live case and refuses to build without authentication.

### D18 — `asyncio.run` cannot nest, and that would have broken every live startup

The first factory bootstrapped its snapshot with `asyncio.run`. The ASGI lifespan is already
inside a running loop, so live mode would have failed every time with
`RuntimeError: asyncio.run() cannot be called from a running event loop` — an error with
nothing to do with DataHub, masking the real cause behind plumbing. A stray "coroutine was
never awaited" warning surfaced it. The server now uses `create_live_pipeline_async` and
awaits directly; the sync wrapper remains for CLI callers.

A test pins the fix by asserting the *specific* failure (`could not acquire a governed DataHub
snapshot`) rather than any exception — the original test passed for the wrong reason.

### Other live-mode guards

- **Fail fast at startup.** Unreachable DataHub means the server does not come up. No fallback
  to fixture governance exists, and a test asserts no pipeline is installed after a failure.
- **Read-only credentials on the request path.** Context is acquired through a role-bound
  client built from `DATAHUB_GMS_READ_TOKEN`; write-back stays a separate isolated process.
- **No implicit warehouse.** Live mode refuses to start without an existing database rather
  than seeding synthetic rows under real governance.
- **Readiness covers the refresher.** A live deployment whose refresh loop has died is not
  ready even while its snapshot is still valid — it is minutes from refusing everything.

### Verification

`tests/integration/test_live_pipeline_end_to_end.py` drives the real loader, real tag →
category normalization, real freshness binding, real policy engine, real DuckDB executor and
real receipt store against a simulated MCP server. Only the wire is faked.

The test that matters most for the product claim:
`test_refresher_reinstalls_governance_after_a_tag_change` reclassifies a column in DataHub and
shows the decision change **without a restart**. `test_untagged_datahub_fields_fail_closed`
shows an unclassified field blocking rather than defaulting permissive.

Suite: **955 passed, 1 skipped** in 100s. `ruff check src tests` clean.

| Env var | Purpose |
| --- | --- |
| `TOXICJOIN_MODE=live` | select the live runtime |
| `TOXICJOIN_DATAHUB_ASSET_MAP` | URN manifest (default `config/datahub-assets.json`) |
| `TOXICJOIN_DATAHUB_SNAPSHOT_MAX_AGE_SECONDS` | freshness window (default 300) |
| `TOXICJOIN_DATABASE` | governed warehouse; must exist in live mode |
