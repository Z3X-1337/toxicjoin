# ToxicJoin

> DataHub-grounded compositional privacy firewall for AI data agents.

ToxicJoin evaluates proposed analytical SQL **before execution**, resolves governed metadata and physical lineage from DataHub, and returns one deterministic outcome:

- **ALLOW** — execute through the hardened read-only path.
- **REWRITE** — generate one constrained safer query, then parse, ground, and evaluate it again.
- **BLOCK** — stop before DuckDB is called.

The LLM/agent never owns the authorization decision. Released receipts exclude raw result rows and are protected by both a canonical content SHA-256 and keyed HMAC-SHA256 authenticity.

ToxicJoin was built for **Build with DataHub: The Agent Hackathon**, targeting **Agents That Do Real Work**.

## Judge quick path

1. **See the product immediately:** https://toxicjoin-replay.vercel.app/
   - Explicitly labeled **Deterministic Replay**.
   - It is not represented as live DuckDB execution or a live DataHub mutation.
2. **Run the executable path:** [`docs/judge-testing.md`](docs/judge-testing.md).
3. **Inspect sample outputs:** [`examples/`](examples/README.md).
4. **Inspect the authoritative final release index:** [`docs/evidence/release-candidate.md`](docs/evidence/release-candidate.md).
5. **Inspect the final exact-head black-box validation:** [`docs/evidence/final-security-blackbox.md`](docs/evidence/final-security-blackbox.md).
6. **Inspect the final real DataHub OSS + MCP proof:** [`docs/evidence/datahub-live.md`](docs/evidence/datahub-live.md).

The shortest proof chain is:

```text
proposed SQL
  -> DataHub-governed context + physical lineage
  -> deterministic ALLOW / REWRITE / BLOCK
  -> safe execution only after effective ALLOW
  -> independent verification
  -> sanitized SHA-256 + HMAC-authenticated receipt
  -> DataHub Decision write-back
  -> fresh MCP process reads the Decision back
```

## Final release identity

Current judge-facing `main` HEAD after the documentation/evidence synchronization in PR #70:

```text
e1192edc2deb961ad9d85187ba2985f82296ed53
```

Frozen runtime merge from PR #68:

```text
ee4991a93070c148e41dd158c952d5f1e9a6ed2c
```

Exact final security-remediation runtime head validated before landing:

```text
536c37c34de7b36495d33f63095585f72e5f4b46
```

PR #68 merged the exact validated runtime head into `main`; its merge commit introduced no file-tree difference relative to that runtime head. PR #70 landed afterward and changed only judge-facing README/documentation/evidence. It did **not** change runtime source, policy, parser, rewriter, executor, verifier, authentication, disclosure implementation, dependencies, Docker runtime, or workflow definitions. Therefore `e1192edc…` is the current judge-facing repository HEAD, while `536c37c…` remains the exact security-tested runtime provenance.

Deterministic policy version: `0.2.0`.

The repository is under **technical freeze**: no feature, refactor, dependency, or policy change is authorized before submission unless a proven release blocker requires reopening the candidate.

## What problem ToxicJoin solves

A field can be acceptable in isolation while the **composition** is unsafe. An AI data agent can combine a stable pseudonym, location signal, support category, purchase information, or model score into a disclosure that column-by-column checks miss.

ToxicJoin therefore reasons over what a query can expose, not only which column names it references. It distinguishes:

- raw and transformed raw values;
- group keys;
- aggregate operands and aggregate values;
- predicate-bearing / conditional aggregate disclosures;
- filter-only and join-only references;
- aliases, CTEs, nested scopes, and physical source lineage;
- DataHub upstream column lineage;
- cross-query disclosure state for authenticated stateful execution.

Unsupported or ambiguous SQL, missing governance, stale context, failed rewrites, failed verification, integrity failures, and incomplete evidence fail closed.

ToxicJoin does **not** claim differential privacy, universal SQL repair, universal re-identification detection, formal verification, or legal-compliance certification.

## Flagship flow

An analytics agent requests a churn-risk aggregate grouped by coarse region. The proposed SQL lacks a trusted minimum distinct-subject threshold.

ToxicJoin returns **REWRITE** and adds the bounded policy requirement:

```sql
HAVING COUNT(DISTINCT c.customer_id) >= 20
```

The generated SQL is not trusted merely because ToxicJoin produced it. It is reparsed, regrounded against governance, reevaluated, authorized, executed read-only, and independently verified. Only an effective **ALLOW** can release accepted data.

A separate individual-level composition of pseudonymous identity, quasi-identifiers, and a sensitive attribute returns **BLOCK before DuckDB execution**. A genuinely low-risk aggregate remains **ALLOW**.

## Cross-query protection

ToxicJoin also protects against disclosure that appears across multiple requests rather than inside one query.

Without a trusted warehouse snapshot/version identity, the final policy permits at most one new protected release in a privacy scope. A later protected release fails closed even when it appears semantically identical, because the underlying warehouse state may have changed and enabled differencing. Same-receipt idempotency is handled separately.

This is intentionally conservative. A production evolution can bind disclosure history to a trusted warehouse snapshot identity so legitimate same-snapshot replays can be distinguished from releases against changed data.

## Real DataHub integration — final security head

DataHub is on the authorization path; it is not decorative metadata.

The exact final security head `536c37c…` passed a real DataHub OSS + official MCP gate in GitHub Actions run `30143510876`.

The verified graph contains:

- **5 datasets**;
- **19 governed fields**;
- **10 controlled tags**;
- **7 glossary terms**;
- **4 lineage writes**.

The MCP proof uses three separated processes:

```text
read-only MCP child
  -> governed entity/schema/lineage snapshot
  -> child closed
isolated writer MCP child
  -> raw upstream writer inventory retained honestly
  -> ToxicJoin effective surface = save_document only
  -> sanitized Decision written
  -> child closed
fresh read-only MCP child
  -> persisted Decision independently read back
```

The official MCP server is pinned as `mcp-server-datahub==0.6.0`. In that version, `save_document` is registered inside a broader upstream mutation path. ToxicJoin therefore records the raw server inventory and places a mandatory allowlist transport in front of the writer. A broad raw upstream inventory is documented dependency behavior; a broad **effective ToxicJoin writer inventory** is treated as a security failure.

The final exact-head spike reports three upstream lineage relationships, two lineage-bound fields, six normalized lineage sources, zero unclassified lineage sources, and independent Decision read-back.

See [`docs/evidence/datahub-live.md`](docs/evidence/datahub-live.md).

## Reusable DataHub Skill

The repository includes a git-backed **Compositional Risk Review** DataHub Agent Skill:

[`skills/compositional-risk-review/SKILL.md`](skills/compositional-risk-review/SKILL.md)

A separate development-channel Agent Registry proof verifies the relationship between the ToxicJoin agent, the reusable skill, DataHub MCP tool API entities, and the five governed ToxicJoin datasets. The registry preview is deliberately isolated from the stable enforcement path.

## Final measured evidence

The exact security-remediation head passed the full release/security gate set:

| Gate | Run | Result |
|---|---:|---:|
| CI — Python 3.11 / 3.12, Web, benchmark, hardened Container | `30143510873` | PASS |
| CodeQL | `30143510868` | PASS |
| Supply Chain Security | `30143510883` | PASS |
| Governance Dependency Evidence | `30143510866` | PASS |
| Adversarial Mutation Evidence | `30143510877` | PASS |
| Compositional Ablation Evidence | `30143510871` | PASS |
| Disclosure Sequence Evidence | `30143510867` | PASS |
| Live DataHub Evidence | `30143510876` | PASS |
| Independent final security-head black-box pentest | `30145592349` | **24/24 PASS** |

Python 3.12 pytest artifact: **309 passed**, with one upstream framework deprecation warning only.

### Balanced 30-case benchmark

Final exact-head artifact:

- 30 cases: 10 ALLOW / 10 REWRITE / 10 BLOCK;
- 30/30 expected initial decisions;
- 30/30 expected effective outcomes;
- 30/30 expected reason codes;
- zero false allows;
- zero unsafe effective allows;
- six rewrites remediated to verified ALLOW;
- four rewrite paths failed closed;
- 16 verified executions.

This is explicitly a deterministic regression corpus for the supported SQL/policy profile, not a universal accuracy claim.

See [`docs/evidence/benchmark.md`](docs/evidence/benchmark.md).

### Adversarial and causal evidence

The adversarial mutation gate covers 144 valid SQL mutations across known-unsafe composition families. The final exact-head run remained fully fail-closed with zero unsafe executions.

The compositional ablation gate removes only the targeted cross-column interaction while preserving controls, isolating the causal contribution of the compositional rule instead of presenting a competitor benchmark.

See [`docs/evidence/adversarial-mutations.md`](docs/evidence/adversarial-mutations.md) and [`docs/evidence/compositional-ablation.md`](docs/evidence/compositional-ablation.md).

### Final exact-image black-box pentest

Validation-only PR #69 built the production Docker image from the **exact final security head** `536c37c…` and interacted with it externally through HTTP and container inspection. The validation branch was closed without merge.

Run `30145592349`: **24/24 PASS**.

Coverage includes authentication and scope separation, request limits, rate limiting, TrustedHost, restricted production surface, fail-closed mutation and compositional sensitive export, legitimate low-risk execution, receipt ownership isolation, receipt `0600` permissions, persisted-receipt tamper detection, non-root/read-only container boundaries, capability drop, no-new-privileges, loopback exposure, and response/log leakage checks.

See [`docs/evidence/final-security-blackbox.md`](docs/evidence/final-security-blackbox.md).

## Final security hardening

The final audit before submission found and closed concrete release-integrity and compositional-privacy issues rather than only performing cosmetic review. PR #68 added or strengthened:

- conditional `COUNT(CASE...)` and `COUNT(...) FILTER (WHERE ...)` exposure handling;
- root SELECT predicate/threshold/target binding in keyed cohort identity;
- conservative temporal-differencing protection for repeated protected releases;
- append-only two-phase disclosure state: `PENDING -> RELEASED | ABORTED`;
- receipt schema 1.5 with content SHA-256 plus HMAC-SHA256 authenticity;
- fail-closed receipt secret/key handling;
- filename/payload receipt identity validation;
- protected execution-error sanitization;
- loopback-only default Docker Compose publication.

The receipt HMAC key is never persisted in receipt JSON. Production can provide `TOXICJOIN_RECEIPT_HMAC_KEY`; zero-config local mode creates a random 256-bit sibling key with restrictive permissions. Existing receipts plus a missing key fail closed rather than silently minting a replacement identity.

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

The frozen release includes:

- single-use governed execution authorization;
- post-execution quarantine until independent verification;
- authenticated scope separation and principal-scoped receipt ownership;
- request, SQL-complexity, concurrency, rate, result, and response budgets;
- persistent cross-query disclosure state and commitment binding;
- DataHub freshness/drift/TOCTOU checks;
- role-separated MCP read/write/fresh-read-back;
- content-hashed and HMAC-authenticated receipts with no raw result rows;
- committed Python and npm locks;
- Python/npm dependency audits, Bandit, CodeQL, and CycloneDX SBOMs;
- Dependabot;
- immutable GitHub Action SHA pins and digest-pinned Docker bases;
- non-root production container with read-only root filesystem, dropped capabilities, and no-new-privileges;
- loopback-only default Compose host publication.

One narrow, documented, machine-validated, expiring `setuptools` exception remains because the current `acryl-datahub` dependency profile constrains the package below the upstream fixed version. It is recorded as a temporary upstream-constrained non-runtime-applicability exception, not described as a complete fix.

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
  receipts/      sanitized SHA + HMAC authenticated receipts
  rewrite/       constrained SQL remediation
  sql/           AST and physical/semantic lineage analysis
  verify/        independent execution/result verification
  pipeline.py    end-to-end orchestration

apps/web/         React/Vite judge interface
config/           policy and DataHub asset configuration
docs/evidence/    retained evidence and authoritative release index
examples/         judge-facing sample outputs
skills/           reusable DataHub Agent Skill
tests/            unit, integration, security regressions
```

## License

Apache License 2.0. See [`LICENSE`](LICENSE).
