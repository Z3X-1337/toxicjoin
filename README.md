# ToxicJoin

> A field can be safe on its own while the **combination** is not. ToxicJoin is the firewall that catches the combination — before the query runs.

An AI data agent joins a stable pseudonym to a location signal, a support category and a model score. Every column passed its own review. The join re-identifies people. Column-by-column checks cannot see it, because the risk is in the composition.

ToxicJoin evaluates proposed SQL **before execution**, grounds every field in governed DataHub context and upstream lineage, and returns one deterministic outcome — **ALLOW**, **REWRITE**, or **BLOCK**. The agent proposes. ToxicJoin decides. Uncertainty fails closed.

## Try it in one command

```bash
bash run.sh
```

Then open `http://127.0.0.1:8000` and use the **live console**: paste SQL, pick an action, and watch the real decision, verification checks, released rows and signed receipt. The **Governed Agent loop** below it shows an agent being refused, reading the reason code, and adapting until its query is safe. Both panels call the real API — there is no replay fallback in either.

Windows: `.\run.ps1`. Full walkthrough: [`docs/judge-testing.md`](docs/judge-testing.md).

## Current Public Demo

[**Open the Current Public Demo**](https://toxicjoin-public-demo.onrender.com/) — last externally
verified on **2026-08-13**. It is a Render Free web service running the hardened Docker image in
explicit `fixture` mode: the deterministic synthetic judge warehouse goes through the real parser,
policy engine, read-only executor, independent verification, and authenticated-receipt path. It is
not a mock, a replay, a Live DataHub deployment, or a source of organization data or credentials.

The Free service may sleep after inactivity and cold-start on the next request. Its local fixture
database, receipts, and disclosure ledger are deliberately temporary and can reset after sleep,
restart, or redeploy; that is expected demo behavior, not a loss of production audit evidence.
The deployment PR records the exact deployed source revision and zero-cost verification details.

## What is proven

- **30-case regression corpus:** 30/30 expected decisions, reason codes and effective outcomes; **zero false allows**.
- **144 adversarial SQL mutations** across known-unsafe composition families: **zero unsafe executions**.
- **Two privacy bypasses found by adversarial review and closed**, each with regressions that fail against the unfixed source — reproducible live from the console's two attack presets:
  - a literal aliased as `subject_count` combined with a `NOT`-inverted `HAVING`;
  - a caller declaring a public column (`orders.order_id`) as the privacy subject.
- **968 passed, 1 skipped, 5 warnings** across unit, integration and security regressions.

Measurement scope and limits: [`docs/evidence/benchmark.md`](docs/evidence/benchmark.md). This is a regression corpus for a declared SQL/policy profile, not a claim of universal privacy detection.

## Architecture authority

[`docs/architecture.md`](docs/architecture.md) is the normative product-architecture and claim-boundary authority. Security, threat-model, deployment, judge, evidence, replay, vNext, and submission documents are subordinate or revision-bound views and may not upgrade a fixture, historical, replay-only, staged, off-main, or roadmap capability into a current product claim.

Recent hardening decisions and their rationale: [`docs/hardening-progress.md`](docs/hardening-progress.md).

The post-submission improvement window is governed by the measured
[`production-readiness plan`](docs/hackathon-build/production-readiness-plan.md) and its
[`autonomous execution contract`](docs/hackathon-build/production-execution-prompt.md).

## Judge quick path

1. **Run it:** `bash run.sh`, then exercise the live console and agent loop at `http://127.0.0.1:8000`.
2. **Reproduce the closed bypasses:** the two `Attack —` presets in the console.
3. **Inspect the claim boundary:** [`docs/evidence/submission-freeze.md`](docs/evidence/submission-freeze.md).
4. **Inspect sample outputs:** [`examples/`](examples/README.md).
5. **Inspect retained historical DataHub OSS + official MCP evidence:** [`docs/evidence/datahub-live.md`](docs/evidence/datahub-live.md).
   - These retained files prove their recorded revision and environment. For `main`, consult the
     [Phase 5 Exact-SHA workflow history](https://github.com/Z3X-1337/toxicjoin/actions/workflows/phase5-live-datahub.yml?query=branch%3Amain).
     Each workflow record, not this document, proves only the exact source revision recorded in
     that run.
6. **Inspect retained production-image black-box evidence:** [`docs/evidence/final-security-blackbox.md`](docs/evidence/final-security-blackbox.md).

A retained static replay of an earlier build remains at https://toxicjoin-replay.vercel.app/ — it is labelled **Historical Deterministic Replay**, carries policy identity `0.1.0` rather than current `0.2.0`, and is not live execution. Use the Current Public Demo above for a public interactive review, or `run.sh` for a local run.

The shortest product proof chain is:

```text
proposed SQL
  -> governed DataHub context + physical lineage
  -> deterministic ALLOW / REWRITE / BLOCK
  -> safe execution only after effective ALLOW
  -> independent verification
  -> sanitized SHA-256 + HMAC-authenticated receipt
  -> bounded DataHub Decision write-back
  -> fresh read-side verification
```

## Why this exists

A field can be acceptable in isolation while the **composition** is unsafe. An AI data agent can combine a stable pseudonym, location signal, support category, purchase information, or model score into a disclosure that column-by-column checks miss.

ToxicJoin reasons over what a query can expose, not only which columns it references. The deterministic kernel distinguishes raw/transformed values, group keys, aggregate operands and values, predicate-bearing conditional aggregates, filter-only and join-only references, aliases, CTEs, nested scopes, and DataHub upstream column lineage.

## Flagship flow

An analytics agent asks for a churn-risk aggregate grouped by coarse region. The proposed SQL lacks the trusted minimum distinct-subject threshold.

ToxicJoin returns **REWRITE** and adds the bounded policy requirement:

```sql
HAVING COUNT(DISTINCT c.customer_id) >= 20
```

The generated SQL is not trusted merely because ToxicJoin produced it. It is reparsed, regrounded against governance, reevaluated, authorized, executed read-only, and independently verified. Only an effective **ALLOW** can release accepted data.

A separate individual-level composition of pseudonymous identity, quasi-identifiers, and a sensitive attribute returns **BLOCK before DuckDB execution**. A genuinely low-risk aggregate remains **ALLOW**.

## Why DataHub is essential

DataHub is on the governed decision path; it is not decorative metadata.

The retained live integration evidence uses DataHub OSS and the official DataHub MCP Server to read governed entities, schema fields, and upstream lineage. The write side is process-isolated and application-allowlisted; a sanitized DataHub Decision is written and then independently read back through a fresh read-only MCP process.

That produces the knowledge loop the project is designed around:

```text
read DataHub context
  -> reason deterministically about compositional risk
  -> take the safe action
  -> write sanitized decision knowledge back
  -> fresh reader inherits the result
```

See [`docs/evidence/datahub-live.md`](docs/evidence/datahub-live.md) and [`docs/datahub-live-integration.md`](docs/datahub-live-integration.md) for retained historical evidence. For `main`, use the [Phase 5 Exact-SHA workflow history](https://github.com/Z3X-1337/toxicjoin/actions/workflows/phase5-live-datahub.yml?query=branch%3Amain); each run proves only the exact source revision recorded in that workflow. Branch-only evidence remains limited to the revision recorded by its own PR and workflow.

## Reusable DataHub Skill

The repository contains a git-backed **Compositional Risk Review** Agent Skill:

[`skills/compositional-risk-review/SKILL.md`](skills/compositional-risk-review/SKILL.md)

The skill describes how an agent gathers governed evidence through DataHub while keeping authorization outside the model.

## Submission freeze status

The last engineering phase before the submission-only freeze is **Phase 16 — Shared Disclosure State Topology Verification**.

Engineering baseline:

```text
Phase 16 merge on main:
5d297778a9a9caaae0732e7dfb7401a5f380f089

Exact Phase 16 candidate head validated before squash merge:
826881acdb1256a8dd1b1f97fba6dae00369dd0c
```

On that exact candidate head, the following completed successfully:

- CI;
- Python 3.11 and 3.12;
- balanced benchmark evidence;
- PPMC hard-gate evidence;
- hardened production container and flagship flow;
- Ground Truth Baseline;
- CodeQL;
- Supply Chain Security;
- Governance Dependency Evidence;
- Adversarial Mutation Evidence;
- Compositional Ablation Evidence;
- Disclosure Sequence Evidence, including the Phase 16 topology regression.

The repository's generated release workflow remains the revision-level release authority. The SHAs above identify the last engineering baseline and its exact pre-merge validation head; later submission-only documentation commits do not imply new runtime behavior.

See [`docs/evidence/submission-freeze.md`](docs/evidence/submission-freeze.md).

## Measured regression evidence

The supported deterministic corpus contains:

- 30 cases: 10 ALLOW / 10 REWRITE / 10 BLOCK;
- 30/30 expected initial decisions;
- 30/30 expected effective outcomes;
- 30/30 expected reason codes;
- zero false allows;
- zero unsafe effective allows;
- six rewrites remediated to verified ALLOW;
- four rewrite paths failed closed;
- 16 verified executions.

This is a regression corpus for the declared SQL/policy profile, not a claim of universal privacy-detection accuracy.

The retained adversarial mutation evidence covers 144 valid SQL mutations across known-unsafe composition families with zero unsafe executions. The compositional ablation evidence isolates the contribution of the targeted cross-column interaction rather than pretending to benchmark a competitor.

See [`docs/evidence/benchmark.md`](docs/evidence/benchmark.md), [`docs/evidence/adversarial-mutations.md`](docs/evidence/adversarial-mutations.md), and [`docs/evidence/compositional-ablation.md`](docs/evidence/compositional-ablation.md).

## Cross-query disclosure state

Authenticated stateful execution uses an append-only disclosure history with two-phase state:

```text
PENDING -> RELEASED
        -> ABORTED
```

`PENDING` participates immediately so concurrent requests cannot race around the privacy gate.

Protected releases consume a bounded per-scope budget inside a rolling window (default 5 per 24h, configurable via `TOXICJOIN_DISCLOSURE_MAX_PROTECTED_RELEASES` and `TOXICJOIN_DISCLOSURE_BUDGET_WINDOW_SECONDS`). This is an exposure **bound**, not a non-inference proof: ToxicJoin does not claim differential privacy, and two aggregates over overlapping populations can always be differenced. The budget makes the residual risk an explicit number instead of an unstated one, and exhaustion fails closed with `CUMULATIVE_BUDGET_EXHAUSTED`.

The public SQLite disclosure authority is explicitly **single-node**. Phase 16 proved that replica-local SQLite files partition cumulative privacy history, then added a fail-closed topology boundary: a deployment declaring more than one application replica cannot silently claim shared-authoritative cumulative privacy state.

ToxicJoin does **not** currently claim a PostgreSQL/shared-authoritative disclosure backend, distributed transactions, cross-node replay state, or horizontally shared receipt/key custody.

Draft PR #118 contains an off-main PostgreSQL shared-authoritative implementation and evidence workflow. It is staged work, not a capability present on `main`, not wired into the current HTTP runtime, and not a production-supported backend.

## What is wired, and what is not

Every package states its runtime status in its module docstring, and
[`tests/security/test_runtime_module_boundary.py`](tests/security/test_runtime_module_boundary.py)
enforces it in both directions, so the split cannot drift silently.

| Package | Status |
| --- | --- |
| `agent/` | **Wired** — `POST /api/agent/run` and the GUI agent panel |
| `proofs/` | **Partially wired** — models reach the execution boundary; the strict proof path is inactive and pinned inactive by test |
| `prospective/` (PPMC) | **Experimental** — real code with CI evidence, no request path invokes it |
| `repair/` (CPCC) | **Experimental** — same |

`docs/vnext/**` holds the design authority for the experimental work. Those components are real code with exact-revision tests, but the canonical HTTP runtime has **not** migrated to the complete vNext proof chain and does not claim to have.

## Run fixture mode

Requirements: Python 3.11 or 3.12.

Linux/macOS:

```bash
bash run.sh
```

Windows PowerShell:

```powershell
.\run.ps1
```

After startup:

- judge interface + live console: `http://127.0.0.1:8000`
- API docs: `http://127.0.0.1:8000/docs`
- liveness: `GET /api/health`
- detailed readiness: `GET /api/ready`
- curated scenarios: `GET /api/demo/scenarios`
- benchmark summary: `GET /api/benchmark/summary`
- analyze without execution: `POST /api/analyze`
- guarded execution: `POST /api/execute-safe`
- governed agent loop: `POST /api/agent/run`
- receipt lookup: `GET /api/receipts/{receipt_id}`

Fixture mode uses deterministic synthetic warehouse data. It is a real executable ToxicJoin path, but it is not represented as a live external DataHub deployment.

Follow [`docs/judge-testing.md`](docs/judge-testing.md).

## Run the live DataHub path

Use the committed lock:

```bash
python -m pip install --disable-pip-version-check 'uv==0.8.4'
uv sync --frozen --extra datahub
```

Then follow [`docs/datahub-live-integration.md`](docs/datahub-live-integration.md).

Core commands:

```bash
datahub docker quickstart
toxicjoin-seed
toxicjoin-datahub-seed --yes
toxicjoin-datahub-spike --verify
```

## Security and supply-chain posture

The repository includes single-use governed execution authorization, post-execution quarantine until independent verification, authenticated scope separation, principal-scoped receipt ownership, request/SQL/concurrency/rate/result/response budgets, persistent cross-query disclosure state, DataHub freshness/drift checks, role-separated MCP read/write/fresh-read-back, HMAC-authenticated receipts without raw result rows, committed Python/npm locks, dependency audits, Bandit, CodeQL, CycloneDX SBOMs, Dependabot, immutable Action SHA pins, digest-pinned Docker bases, and a non-root/read-only production container with dropped capabilities and no-new-privileges.

One narrow, documented, machine-validated, expiring `setuptools` exception remains because the current DataHub dependency profile constrains the package below the upstream fixed version. It is a temporary upstream-constrained non-runtime-applicability exception, not a complete fix.

See [`SECURITY.md`](SECURITY.md), [`docs/threat-model.md`](docs/threat-model.md), and [`docs/security/`](docs/security/).

## Historical evidence

The repository retains the earlier pre-vNext release evidence for provenance. It is intentionally labelled historical and must not be used as current repository identity.

See [`docs/evidence/release-candidate.md`](docs/evidence/release-candidate.md), [`docs/evidence/final-security-blackbox.md`](docs/evidence/final-security-blackbox.md), and [`docs/evidence/hosted-replay.md`](docs/evidence/hosted-replay.md).

## Repository map

```text
src/toxicjoin/
  agent/         governed Agent boundary, planner adapter, and runtime loop
  api/           FastAPI boundary and curated judge scenarios
  benchmark/     benchmark and evidence summaries
  context/       fixture and normalized DataHub context
  demo/          deterministic synthetic warehouse
  disclosure/    cumulative disclosure state
  execute/       authorization-gated read-only DuckDB execution
  integrations/  DataHub SDK/MCP/Agent Registry integrations
  policy/        deterministic policy v0.2
  proofs/        pre-execution privacy/provenance proof models
  receipts/      sanitized SHA + HMAC authenticated receipts
  rewrite/       constrained SQL remediation
  sql/           AST and physical/semantic lineage analysis
  verify/        independent execution/result verification
  pipeline.py    end-to-end orchestration

apps/web/         React/Vite judge interface
config/           policy and DataHub asset configuration
docs/evidence/    current and historical evidence
docs/vnext/       staged hardening architecture and phase records
examples/         judge-facing sample outputs
skills/           reusable DataHub Agent Skill
tests/            unit, integration, and security regressions
```

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
