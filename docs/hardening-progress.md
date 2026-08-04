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

---

## Phase 7 — Interface redesign

### D19 — Show the composition, do not describe it

Every panel reported a verdict; none showed *why* one was possible. The product's entire
argument is that individually acceptable fields combine into an unsafe disclosure, and that
argument lands far harder when a reviewer sees a stable pseudonym sitting beside two
quasi-identifiers and a sensitive attribute than when they read the sentence.

`GovernanceStrip` renders every governed column the query touched, coloured by its DataHub
classification and **sorted riskiest first**, so the reason for the verdict is the first thing
met rather than something hunted for among public columns. The contrast across presets carries
the story on its own: the low-risk aggregate resolves one public column, the blocked
composition resolves five protected ones.

### D20 — One column, no ambient decoration

The old shell put a scenario sidebar beside a SQL editor and layered a grid texture and two
blurred glows behind it. Both split attention away from the evidence. The layout is now a
single 1080px column reading top to bottom — console, agent loop, then the supporting panels —
and the decoration is gone.

The palette moved from teal-on-navy to near-black with one decisive hue per verdict, and all
technical content (verdicts, column names, reason codes, hashes) is monospaced. It should read
as an enforcement tool, not a landing page.

### Verified in-browser against the running API

| Preset | Verdict | Rows | Governed columns shown |
| --- | --- | --- | --- |
| Allow — low-risk aggregate | ALLOW | 4 | 1 |
| Rewrite — add a subject threshold | ALLOW after rewrite | 3 | 4 |
| Block — compositional re-identification | BLOCK | 0 | 5 |
| Attack — fabricated subject_count | BLOCK | 0 | 5 |
| Attack — caller-chosen weak subject | BLOCK | 0 | 6 |

Agent loop: BLOCK → adapt → ALLOW. No console errors. No horizontal overflow at 375px or
1280px. Typecheck clean, 24 frontend tests, production build succeeds.

---

## Phase 8 — Public deployment

### D21 — Anonymous reviewers were sharing one traffic budget

The unauthenticated fixture surface shares a single identity on purpose: receipts and
cumulative disclosure history must not be partitioned by network address. But traffic budgets
were keyed on that same shared value, so the *entire public demo* had two concurrent requests
and sixty per minute in total. Two reviewers clicking at the same moment would have refused
each other's work, and one client could exhaust the deployment for everyone.

`_traffic_principal` now keys unauthenticated traffic per peer while leaving the identity
shared. Authenticated callers stay metered by their real principal and never by where they
connected from.

### D22 — The public demo runs fixture mode, and that is not a compromise

The synthetic warehouse contains no real people, so the interface can stay open without
handing out a credential, and every decision a reviewer sees still comes from the real parser,
policy engine, read-only DuckDB, verification and receipts. Only the governance *source* is
synthetic, and `/api/ready` and every receipt say so.

Two limits are raised from their defaults because the defaults assume a credentialed API
rather than a public audience: 240 requests/window and 8 concurrent per peer.

### D23 — A green deploy proves nothing about enforcement

The failure worth fearing is a stale image that still contains the bypasses — it looks
completely healthy from the outside. `scripts/verify_deployment.py` drives a deployed URL and
asserts on outcomes: the three deterministic decisions, and both closed bypasses returning
BLOCK with zero rows. Exit 1 on any deviation, so it belongs in a post-deploy step.

Verified against the running server: 5/5 pass, exit 0; unreachable host exits 1.

### D24 — An unused import can still be part of a module's surface

Fixing the long-standing `F401` in `scripts/phase5_live_datahub.py` broke five tests: the
import was unused *in* that file but reached through it as an implicit re-export. The fix was
to have the test import from the module that defines the helper, removing the fragile coupling
rather than silencing the lint. CI's lint scope now includes `scripts/`, which is why the
warning had survived this long.

### Artifacts

| File | Purpose |
| --- | --- |
| `fly.toml` | Fly.io deployment, volume-backed runtime directory |
| `render.yaml` | Render blueprint, ephemeral runtime directory documented as demo-only |
| `docs/deploy-public.md` | both deployments, the DataHub tag map, and what live mode will not do |
| `scripts/verify_deployment.py` | post-deploy proof that the bypasses are still refused |

Suite: **958 passed, 1 skipped**. `ruff check src tests scripts` clean.

**Not verified here:** the container image itself. Docker is unavailable in this environment,
so `fly deploy` / Render will be the first real build of it.

---

## Phase 9 — Proxy-trust boundary and a clean bandit scan

### D25 — `request.client.host` is only as trustworthy as the proxy in front of it

The pre-auth failure limiter (`_unauthenticated_principal`) and the per-peer traffic key
(`_traffic_principal`) both key on `request.client.host` — necessary, since Phase 8 had just
fixed the opposite problem of everyone sharing one bucket. But that value's trustworthiness
depends entirely on what sits in front of the process, and it was never examined: uvicorn
defaults to `proxy_headers=True, forwarded_allow_ips="127.0.0.1"`, silently rewriting
`request.client` from `X-Forwarded-For` whenever the *direct* TCP peer is `127.0.0.1` —
correct for a reverse proxy running on the same host, wrong and silent for anything else.

Both fly.toml and render.yaml terminate TLS at a managed edge and forward to the container
over an internal network, so on either platform the direct peer is not `127.0.0.1`. With
uvicorn's default, `X-Forwarded-For` would simply be ignored there and every caller would
correctly get its own peer key — the two shipped configs were never actually exposed by
this gap. But it was still an *unexamined* trust boundary sitting under a security control,
and any live/credentialed deployment placed behind an actual local reverse proxy would have
inherited it silently. Two ways that goes wrong:

- **Untrusted proxy honored** (CWE-346): distinct callers collapse onto one limiter key —
  the shared-budget denial of service Phase 8 exists to prevent, reintroduced by the proxy.
- **Proxy trusted but forwards a caller-supplied header verbatim** (CWE-290): an attacker
  mints a fresh `X-Forwarded-For` per request and the failure throttle stops throttling.

`cli.py:_uvicorn_proxy_kwargs` resolves this the way uvicorn already intends it to be
resolved — `forwarded_allow_ips` is the mechanism, not a hand-rolled header parse in
`app.py`. Trust is off by default (`proxy_headers=False`); an operator behind a real proxy
opts in with `TOXICJOIN_TRUSTED_PROXY_IPS`, documented in `docs/deploy-public.md` alongside
the same warning about what happens if the trusted proxy itself forwards an unverified
header. `tests/unit/test_cli_proxy_trust.py` pins the default-off behaviour, blank-is-unset,
explicit opt-in, and the real-environ fallback.

### D26 — Two bandit findings, both real interpolation, neither real input

`bandit -r src` flagged two `B608` (SQL built via string interpolation) findings at medium
severity: `demo/seed.py`'s CSV-staging insert (added in Phase 2) and
`benchmark/disclosure_sequences.py`'s evidence-corpus query builder. Both interpolate
identifiers — table names, a column spec, a region literal — into SQL text, which is exactly
the shape the rule exists to catch.

Neither is reachable from any request path or takes a caller-supplied value: `seed.py`'s
`table`/`column_spec` come only from a five-entry module constant, and
`disclosure_sequences.py`'s `_sql()` is called only with hardcoded literals from a standalone
offline evidence-generation CLI. Silencing them with a bare `# nosec` would leave that
reasoning undiscoverable to the next reader; each now carries the explanation inline, an
assertion that makes the safety self-evident rather than resting on the constant never
changing silently, and the `# nosec B608` marker on bandit's exact flagged line.

`bandit -ll -r src` now reports zero medium/high findings (0 accepted at face value — both
suppressions are justified, not hidden). `pip-audit` reports no known vulnerabilities in any
dependency.

### D27 — Machine-specific Claude Code settings must not enter the shared repository

`.claude/settings.json` on this machine points at personal hook scripts under
`C:/Users/<user>/.claude/hooks/*.ps1`. Committing it would leak a local path into a public
hackathon submission and, worse, break Claude Code for anyone else who opens this repo — the
hooks it references do not exist on their machine. It is now excluded via `.gitignore`
without being deleted, so it keeps working locally. `.claude/CLAUDE.md` (portable, no
machine-specific content) and the already-tracked `.claude/launch.json` remain committed.

### Verification

Full suite re-run clean after every change in this phase: **962 passed, 1 skipped**,
`ruff check src tests scripts` clean, `bandit -ll -r src` zero medium/high, `pip-audit` zero
known vulnerabilities, frontend typecheck/test/build clean.

---

## Phase 10 — Merge readiness: three real CI failures found and fixed pre-merge

`gh pr create` opened #140 cleanly, but its status checks showed 5 failures. Before merging,
each was traced to a root cause rather than assumed benign.

### Not caused by this branch — verified, not merged around blindly

`python-audit (datahub)` and `dependency-review-fallback` both fail on `cryptography==49.0.0`
(`CVE-2026-69247`, fixed in 50.0.0). Confirmed `main`'s `uv.lock` pins the identical version —
this is a live vulnerability-database result against an unchanged lock, not something this
branch introduced, and bumping a transitive dependency pulled in by `acryl-datahub` is a
separate maintenance task or the project owner's call, not a drive-by inside this PR.

### D28 — The disclosure-evidence generator still encoded the pre-Phase-2 model

`cumulative-disclosure-evidence` failed because `benchmark/disclosure_sequences.py` builds
four scenarios that all assume a single protected release blocks the very next one — exactly
the "one release, ever" behaviour Phase 2 deliberately replaced with a bounded, configurable
budget. That replacement was correct and stays; the evidence generator was simply proving the
wrong thing against the new code.

Rather than reopen the Phase 2 decision, each scenario's ledger is now built with
`DisclosureBudget(max_protected_releases=1)` — the same pinning pattern already used for the
unit/security tests Phase 2 touched. This reaches the exhaustion boundary in two calls instead
of requiring five, and it demonstrates the real property (the gate fails closed once its
budget is spent) rather than a number that is free to change independently of the enforcement
logic being proven. The report's `model` field now says so explicitly, including the shipped
default (5 per rolling 24h), so the evidence cannot be misread as describing what ships.

`candidate-manifest` had no independent cause — its own log states it refuses to compose a
release manifest when a required upstream evidence workflow fails. Fixing the above resolves
it too.

### D29 — Two inputs relied on label association a scripted check doesn't credit

`production-browser-e2e` failed with `unnamed interactive controls detected`. The check's
accessible-name computation (`aria-label` → `aria-labelledby` → `alt` → `title` →
`textContent`) does not credit an `<input>` wrapped in a `<label>` with sibling text — which
is how every field in the new console and agent panels was built. Real assistive technology
resolves that association; this script does not, so every bare input, the SQL textarea, and
both radio inputs needed an explicit `aria-label` matching their visible label text. Verified
by running the exact check function against the live page before and after triggering a
console query and an agent run — 28 interactive elements, zero unnamed, both times.

### Verification

Full suite re-run after all three fixes: **962 passed, 1 skipped**; `ruff check src tests
scripts` clean; frontend typecheck/test/build clean; the exact CI assertion blocks for both
fixed workflows replicated and passed locally before pushing.
