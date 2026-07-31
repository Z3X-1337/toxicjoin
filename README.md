# ToxicJoin

> DataHub-grounded compositional privacy firewall for AI data agents.

ToxicJoin evaluates proposed analytical SQL **before execution**, resolves governed DataHub context and physical lineage, and returns one deterministic outcome:

- **ALLOW** — execute through the hardened read-only path.
- **REWRITE** — generate one constrained safer query, then parse, ground, and evaluate it again.
- **BLOCK** — stop before DuckDB is called.

The LLM/agent never owns the authorization decision. Unsupported SQL, unresolved or stale governance, ambiguous lineage, failed rewrite, failed verification, integrity failure, or incomplete evidence fails closed.

ToxicJoin was built for **Build with DataHub: The Agent Hackathon**, targeting **Agents That Do Real Work**.

## Architecture authority

[`docs/architecture.md`](docs/architecture.md) is the normative product-architecture and claim-boundary authority. Security, threat-model, deployment, judge, evidence, replay, vNext, and submission documents are subordinate or revision-bound views and may not upgrade a fixture, historical, replay-only, staged, off-main, or roadmap capability into a current product claim.

## Judge quick path

1. **See the interface immediately:** https://toxicjoin-replay.vercel.app/
   - Explicitly labeled **Historical Deterministic Replay**.
   - The retained public replay has policy identity `0.1.0`; it is not current-main policy `0.2.0` evidence.
   - It is not represented as live DuckDB execution, live DataHub mutation, or current-source release evidence.
2. **Run the executable product path:** [`docs/judge-testing.md`](docs/judge-testing.md).
3. **Inspect the submission freeze and current claim boundary:** [`docs/evidence/submission-freeze.md`](docs/evidence/submission-freeze.md).
4. **Inspect sample outputs:** [`examples/`](examples/README.md).
5. **Inspect retained real DataHub OSS + official MCP evidence:** [`docs/evidence/datahub-live.md`](docs/evidence/datahub-live.md).
   - This evidence is exact-revision evidence and was not rerun on final `main` `1aead67c339c218f5858a9eb9de05868cdc3a0e5`.
6. **Inspect retained production-image black-box evidence:** [`docs/evidence/final-security-blackbox.md`](docs/evidence/final-security-blackbox.md).

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

See [`docs/evidence/datahub-live.md`](docs/evidence/datahub-live.md) and [`docs/datahub-live-integration.md`](docs/datahub-live-integration.md). The retained live run proves its recorded revision and environment; it is not an exact-final-SHA live rerun.

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

The public SQLite disclosure authority is explicitly **single-node**. Phase 16 proved that replica-local SQLite files partition cumulative privacy history, then added a fail-closed topology boundary: a deployment declaring more than one application replica cannot silently claim shared-authoritative cumulative privacy state.

ToxicJoin does **not** currently claim a PostgreSQL/shared-authoritative disclosure backend, distributed transactions, cross-node replay state, or horizontally shared receipt/key custody.

Draft PR #118 contains an off-main PostgreSQL shared-authoritative implementation and evidence workflow. It is staged work, not a capability present on `main`, not wired into the current HTTP runtime, and not a production-supported backend.

## vNext claim boundary

`docs/vnext/**` contains staged security architecture developed during the hardening roadmap, including Governed-Agent authority separation, prospective privacy model checking (PPMC), proof handoffs, proof-bound execution, warehouse-snapshot revalidation, and cryptographic protocol separation.

Those components are real code with exact-revision tests, but they must not be confused with a claim that the canonical HTTP runtime has fully migrated to the complete vNext proof chain. The stable runtime and the staged vNext architecture are documented separately on purpose.

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

- API docs: `http://127.0.0.1:8000/docs`
- liveness: `GET /api/health`
- detailed readiness: `GET /api/ready`
- curated scenarios: `GET /api/demo/scenarios`
- benchmark summary: `GET /api/benchmark/summary`
- analyze without execution: `POST /api/analyze`
- guarded execution: `POST /api/execute-safe`
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
  agent/         governed Agent boundaries and proof authority
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
