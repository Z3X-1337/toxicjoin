# ToxicJoin

> DataHub-grounded compositional privacy firewall for AI data agents.

ToxicJoin evaluates proposed analytical SQL **before execution**, resolves governed context and physical lineage, and returns one deterministic outcome:

- **ALLOW** — execute through the hardened read-only path.
- **REWRITE** — generate a constrained safer query, then parse, ground, and evaluate it again.
- **BLOCK** — stop before DuckDB is called.

The LLM/agent never owns the authorization decision. Every completed path produces a content-hashed receipt that excludes raw result rows.

ToxicJoin was built for **Build with DataHub: The Agent Hackathon**, in **Agents That Do Real Work**.

## Judge quick path

1. **See the product immediately:** https://toxicjoin-replay.vercel.app/
   - Explicitly labeled **Deterministic Replay**.
   - Not presented as live DuckDB execution or a live DataHub mutation.
2. **Run the executable path:** [`docs/judge-testing.md`](docs/judge-testing.md).
3. **Inspect sample outputs:** [`examples/`](examples/README.md).
4. **Inspect the final release evidence:** [`docs/evidence/release-candidate.md`](docs/evidence/release-candidate.md).
5. **Inspect real DataHub OSS + MCP proof:** [`docs/evidence/datahub-live.md`](docs/evidence/datahub-live.md).

The proof chain is:

```text
proposed SQL
  -> DataHub-governed context + physical lineage
  -> deterministic ALLOW / REWRITE / BLOCK
  -> safe execution only after effective ALLOW
  -> independent verification
  -> sanitized content-hashed receipt
  -> DataHub Decision write-back
  -> fresh MCP process reads the Decision back
```

## Release state

Final audited **runtime candidate**:

```text
e139fa99bd666505ed83a18188423722405695a2
```

Deterministic policy version: `0.2.0`.

This candidate exists because the final repository hygiene pass found one real judge-facing defect: the package-owned benchmark summary served by `/api/benchmark/summary` still identified the pre-P0 policy `0.1.0` and an obsolete benchmark report hash. The correction changes only `src/toxicjoin/benchmark/evidence.py` so the running fixture judge reports the already-measured policy `0.2.0` benchmark evidence.

On `e139fa99…`, CI, CodeQL, Supply Chain, Governance Dependency, Adversarial Mutation, and Compositional Ablation all passed again. The generated 30-case benchmark retained the same decisions, metrics, data fingerprint, and report SHA.

The previous deep-security baseline:

```text
fe4f8da2579e09bdbfb1d998b92dfea86549733b
```

is the commit that passed Live DataHub, Disclosure Sequence, Hosted Replay, the frozen external 24-task replay, and the 24/24 exact-image black-box pentest. The only later runtime-source change is the benchmark-evidence constant above; no parser, policy rule, rewriter, executor, verifier, authentication, disclosure, DataHub integration, dependency, Docker, or workflow behavior changed.

Full provenance: [`docs/evidence/release-candidate.md`](docs/evidence/release-candidate.md).

No feature, refactor, dependency, or policy changes are authorized during release freeze unless a proven release blocker requires reopening the candidate.

## Why ToxicJoin is different

A field can be acceptable in isolation while the **composition** is unsafe. ToxicJoin reasons over semantic exposure and lineage rather than checking only column names independently.

It distinguishes:

- raw and transformed raw values;
- group keys;
- aggregate operands and aggregate values;
- filter-only and join-only references;
- aliases, CTEs, nested scopes, and physical source lineage;
- DataHub upstream column lineage;
- cross-query disclosure state for authenticated stateful execution.

Unsupported or ambiguous SQL, missing governance, stale context, failed rewrites, failed verification, integrity failures, and incomplete evidence fail closed.

ToxicJoin does **not** claim differential privacy, universal SQL repair, universal re-identification detection, or legal-compliance certification.

## Flagship flow

An analytics agent requests a churn-risk aggregate grouped by coarse region. The proposed SQL lacks a trusted minimum distinct-subject threshold.

ToxicJoin returns **REWRITE** and adds:

```sql
HAVING COUNT(DISTINCT c.customer_id) >= 20
```

The rewritten SQL is not trusted merely because ToxicJoin generated it. It is reparsed, regrounded, reevaluated, authorized, executed read-only, and independently verified. Only an effective **ALLOW** can release accepted data.

A separate individual-level composition of pseudonymous identity, quasi-identifiers, and a sensitive attribute returns **BLOCK before DuckDB execution**. A genuinely low-risk aggregate remains **ALLOW**.

## Real DataHub integration

The deep-security baseline `fe4f8da…` passed the real DataHub OSS + official MCP gate. The later benchmark-summary correction does not touch the DataHub subsystem.

The verified seed contains:

- **5 datasets**;
- **19 governed fields**;
- **10 controlled tags**;
- **7 glossary terms**;
- **4 lineage writes**.

The MCP verification uses three separated processes:

```text
read-only MCP child
  -> governed entity/schema/lineage snapshot
  -> child closed
isolated writer MCP child
  -> ToxicJoin effective surface = save_document only
  -> Decision written
  -> child closed
fresh read-only MCP child
  -> persisted Decision independently read back
```

The final spike schema is `1.3`: three upstream lineage relationships, two lineage-bound fields, six normalized lineage sources, zero unclassified lineage sources, and effective writer inventory exactly `save_document`.

See [`docs/evidence/datahub-live.md`](docs/evidence/datahub-live.md).

## Reusable DataHub Skill

The repository includes a git-backed **Compositional Risk Review** DataHub Agent Skill:

[`skills/compositional-risk-review/SKILL.md`](skills/compositional-risk-review/SKILL.md)

A separate development-channel Agent Registry proof verifies:

```text
ToxicJoin Privacy Firewall Agent
  -> Compositional Risk Review Agent Skill
  -> five DataHub MCP tool API entities
  -> five governed ToxicJoin datasets
```

This preview is deliberately isolated from the stable enforcement path. See [`docs/evidence/datahub-agent-registry.md`](docs/evidence/datahub-agent-registry.md).

## Measured evidence

### Balanced 30-case benchmark — final runtime candidate

Exact-head CI on `e139fa99…`, policy `0.2.0`:

- 30 cases: 10 ALLOW / 10 REWRITE / 10 BLOCK;
- 30/30 expected initial decisions;
- 30/30 expected effective outcomes;
- 30/30 expected reason codes;
- zero false allows;
- zero unsafe effective allows;
- six rewrites remediated to verified ALLOW;
- four rewrite paths failed closed;
- 16 verified executions.

See [`docs/evidence/benchmark.md`](docs/evidence/benchmark.md).

### Adversarial mutation suite — final runtime candidate

- 144/144 initial BLOCK;
- 144/144 effective BLOCK;
- 144/144 intended compositional-risk reason;
- zero database executions;
- zero unsafe allows.

See [`docs/evidence/adversarial-mutations.md`](docs/evidence/adversarial-mutations.md).

### Compositional interaction ablation — final runtime candidate

The shipped policy blocks 144/144 unsafe mutations. Removing only the targeted compositional interaction allows 144/144 while preserving all 20 ALLOW/REWRITE controls.

See [`docs/evidence/compositional-ablation.md`](docs/evidence/compositional-ablation.md).

### Frozen external validation — deep-security baseline

The unchanged frozen 24-task external workload passed: E01 remained ALLOW and executed; E18/E20/E24 remained BLOCK with zero execution; zero unsafe MUST_NOT_EXECUTE executions; zero unsafe grouped-sensitive executions; no patient rows in sanitized evidence.

### Exact-image black-box pentest — deep-security baseline

24/24 probes passed across authentication/scopes, request limits, rate limiting, fail-closed mutation/sensitive export, legitimate stateful ALLOW, receipt ownership/tamper detection, restricted API surface, non-root/read-only container boundaries, dropped capabilities, no-new-privileges, and leakage checks.

All run IDs, artifact IDs/digests, report hashes, and applicability notes are in [`docs/evidence/release-candidate.md`](docs/evidence/release-candidate.md).

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

The convenience launchers install from declared dependency ranges. The **release-reproducible paths are CI and Docker**, which consume the committed `uv.lock` with `uv sync --frozen`.

After startup:

- API docs: `http://127.0.0.1:8000/docs`
- liveness: `GET /api/health`
- detailed readiness: `GET /api/ready`
- curated scenarios: `GET /api/demo/scenarios`
- benchmark summary: `GET /api/benchmark/summary`
- analyze without execution: `POST /api/analyze`
- guarded execution: `POST /api/execute-safe`
- receipt lookup: `GET /api/receipts/{receipt_id}`

In fixture mode, `/api/health` intentionally returns only process liveness. `/api/ready` carries runtime mode, policy version, database readiness, receipt-store readiness, and governance readiness.

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

The release lineage includes:

- single-use governed execution authorization;
- post-execution quarantine until independent verification;
- authenticated scope separation and receipt ownership;
- request, SQL-complexity, concurrency, rate, result, and response budgets;
- persistent cross-query disclosure state and commitment binding;
- DataHub freshness/drift/TOCTOU checks;
- role-separated MCP read/write/read-back;
- content-hashed receipts with no raw result rows;
- committed Python and npm locks;
- dependency audits, Bandit, CodeQL, CycloneDX SBOMs, Dependabot;
- immutable GitHub Action SHAs and digest-pinned Docker bases;
- non-root production container, read-only root filesystem, dropped capabilities, and no-new-privileges.

See [`SECURITY.md`](SECURITY.md), [`docs/threat-model.md`](docs/threat-model.md), and [`docs/security/`](docs/security/).

## Repository map

```text
src/toxicjoin/
  api/           FastAPI boundary and curated judge scenarios
  benchmark/     benchmark and evidence summaries
  context/       fixture and normalized DataHub context
  demo/          deterministic synthetic warehouse
  disclosure/    append-only cumulative disclosure state
  execute/       authorization-gated read-only DuckDB execution
  integrations/  DataHub SDK/MCP/Agent Registry integrations
  policy/        deterministic policy v0.2
  receipts/      sanitized integrity-checked receipts
  rewrite/       constrained SQL remediation
  sql/           AST and physical/semantic lineage analysis
  verify/        independent execution/result verification
  pipeline.py    end-to-end orchestration

apps/web/         React/Vite judge interface
config/           policy and DataHub asset configuration
docs/evidence/    retained evidence and release index
examples/         judge-facing sample outputs
skills/           reusable DataHub Agent Skill
tests/            unit, integration, and security regressions
```

## License

Apache License 2.0. See [`LICENSE`](LICENSE).