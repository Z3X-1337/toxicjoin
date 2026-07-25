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
   - This site is explicitly labeled **Deterministic Replay**.
   - It is not presented as live DuckDB execution or a live DataHub mutation.
2. **Run the executable path:** follow [`docs/judge-testing.md`](docs/judge-testing.md).
3. **Inspect sample outputs:** [`examples/`](examples/README.md).
4. **Inspect the final exact-head evidence:** [`docs/evidence/release-candidate.md`](docs/evidence/release-candidate.md).
5. **Inspect real DataHub OSS + MCP proof:** [`docs/evidence/datahub-live.md`](docs/evidence/datahub-live.md).

The shortest proof chain is:

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

The release-frozen **runtime candidate** is:

```text
fe4f8da2579e09bdbfb1d998b92dfea86549733b
```

That commit was promoted to `main` by non-forced fast-forward after P4 software-supply-chain closure and P5 independent validation, so no new production SHA was introduced at promotion time. A later documentation/evidence synchronization may advance `main` with judge-facing files only; `fe4f8da2579e09bdbfb1d998b92dfea86549733b` remains the exact runtime tree that passed the release gates.

Current deterministic policy version: `0.2.0`.

No features, refactors, dependency changes, or policy changes are authorized during release freeze unless a proven release blocker requires reopening the candidate.

## What makes ToxicJoin different

A field can be acceptable in isolation while the **composition** is unsafe. ToxicJoin reasons over semantic exposure and lineage rather than checking only column names independently.

It distinguishes, among other things:

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

An analytics agent requests a churn-risk aggregate grouped by coarse region. The initial SQL lacks a trusted minimum distinct-subject threshold.

ToxicJoin returns **REWRITE** and adds:

```sql
HAVING COUNT(DISTINCT c.customer_id) >= 20
```

The rewritten SQL is not trusted just because ToxicJoin generated it. It is reparsed, regrounded, reevaluated, then independently verified. Only an effective **ALLOW** can execute.

A separate individual-level composition of pseudonymous identity, quasi-identifiers, and a sensitive attribute returns **BLOCK before DuckDB execution**. A genuinely low-risk aggregate remains **ALLOW**.

## Real DataHub integration

The final Live DataHub gate ran against real DataHub OSS and the official MCP Server on the exact release candidate.

The final seed created:

- **5 datasets**;
- **19 governed fields**;
- **10 controlled tags**;
- **7 glossary terms**;
- **4 lineage writes**.

The MCP verification uses a three-process authority split:

```text
read-only MCP child
  -> governed entity/schema/lineage snapshot
  -> child closed
isolated writer MCP child
  -> ToxicJoin transport exposes only save_document
  -> Decision written
  -> child closed
fresh read-only MCP child
  -> persisted Decision marker independently read back
```

The final spike schema is `1.3`. It verified three upstream lineage relationships, two lineage-bound fields, six normalized lineage sources, zero unclassified lineage sources, and an effective writer inventory of exactly `save_document`.

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

### Balanced 30-case benchmark

Final exact-head CI on policy `0.2.0` produced:

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

### Adversarial mutation suite

144 valid SQL mutations across three known-unsafe composition families:

- 144/144 initial BLOCK;
- 144/144 effective BLOCK;
- 144/144 intended compositional-risk reason;
- zero database executions;
- zero unsafe allows.

See [`docs/evidence/adversarial-mutations.md`](docs/evidence/adversarial-mutations.md).

### Compositional interaction ablation

The shipped policy blocks 144/144 unsafe mutations. Removing the targeted compositional interaction allows 144/144 of them while preserving all 20 ALLOW/REWRITE controls.

See [`docs/evidence/compositional-ablation.md`](docs/evidence/compositional-ablation.md).

### Independent frozen external replay

The exact release candidate passed the unchanged frozen 24-task external workload. E01 remained ALLOW and executed; E18/E20/E24 remained BLOCK with zero execution; there were zero unsafe MUST_NOT_EXECUTE executions and zero unsafe grouped-sensitive executions.

### Exact release-candidate black-box pentest

A separate validation branch built the exact Docker image and probed it externally through HTTP and container inspection. Final result: **24/24 PASS**.

Coverage included authentication/scopes, request limits, rate limiting, fail-closed mutation and sensitive export, legitimate stateful ALLOW, receipt ownership isolation, receipt tamper detection, restricted API surface, non-root/read-only container boundaries, dropped Linux capabilities, no-new-privileges, and leakage checks.

All final evidence IDs, digests, runs, and report hashes are indexed in [`docs/evidence/release-candidate.md`](docs/evidence/release-candidate.md).

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

The convenience launchers install the application from the declared project dependency ranges. The **release-reproducible paths are CI and Docker**, which consume the committed `uv.lock` with `uv sync --frozen`.

After startup:

- API docs: `http://127.0.0.1:8000/docs`
- liveness: `GET /api/health`
- detailed readiness: `GET /api/ready`
- curated scenarios: `GET /api/demo/scenarios`
- analyze without execution: `POST /api/analyze`
- guarded execution: `POST /api/execute-safe`
- receipt lookup: `GET /api/receipts/{receipt_id}`

In fixture mode, `/api/health` intentionally returns only process liveness. `/api/ready` carries runtime mode, policy version, database readiness, receipt-store readiness, and governance readiness.

Follow the exact [`90-second judge testing guide`](docs/judge-testing.md).

## Run the live DataHub path

For a reproducible environment, use the committed lock:

```bash
python -m pip install --disable-pip-version-check 'uv==0.8.4'
uv sync --frozen --extra datahub
```

Then follow [`docs/datahub-live-integration.md`](docs/datahub-live-integration.md).

The core commands are:

```bash
datahub docker quickstart
toxicjoin-seed
toxicjoin-datahub-seed --yes
toxicjoin-datahub-spike --verify
```

## Security and supply-chain posture

The release candidate includes:

- single-use, short-lived execution authorization bound to the governed request;
- post-execution quarantine until independent verification passes;
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
  benchmark/     regression, adversarial, governance, and ablation runners
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
docs/evidence/    retained evidence and final release index
examples/         judge-facing sample outputs
skills/           reusable DataHub Agent Skill
tests/            unit, integration, and security regressions
```

## License

Apache License 2.0. See [`LICENSE`](LICENSE).