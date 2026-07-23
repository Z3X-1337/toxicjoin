# ToxicJoin

> A compositional privacy firewall that blocks or safely rewrites risky SQL before AI data agents execute it.

ToxicJoin is being built for **Build with DataHub: The Agent Hackathon** in the **Agents That Do Real Work** category.

Individually acceptable datasets can become sensitive when an agent joins them. ToxicJoin analyzes the proposed SQL before execution, resolves governed column context, applies a deterministic policy, and returns one outcome:

- **ALLOW** — execute through a hardened read-only path.
- **REWRITE** — produce a constrained safe query, then analyze it again.
- **BLOCK** — stop before the database is called.

Every path creates a hashed decision receipt. Receipts contain metadata and verification evidence, but never raw result rows.

## Public judge replay

Open the verified deterministic Replay:

https://toxicjoin-replay.vercel.app/

The public site is explicitly labeled as a Replay. It demonstrates the exact judge-interface artifact that passed CI, but it does not claim live DuckDB execution or a live DataHub write. The Docker/FastAPI package is the executable product path, and the separate live DataHub evidence proves the real SDK/MCP integration.

Browser evidence: [docs/evidence/hosted-replay.md](docs/evidence/hosted-replay.md).

## Current status

The deterministic fixture-mode vertical slice works end to end:

```text
Task + SQL
  -> SQLGlot AST and physical column lineage
  -> governed metadata context
  -> deterministic BLOCK / REWRITE / ALLOW policy
  -> constrained subject-threshold rewrite
  -> policy reevaluation
  -> hardened read-only DuckDB execution
  -> independent result verification
  -> immutable sanitized receipt
  -> FastAPI response and receipt lookup
```

The DataHub integration also passed a real DataHub OSS evidence gate:

```text
DataHub SDK seed
  -> five datasets + 19 governed fields
  -> nine tags + seven glossary terms
  -> four column-lineage writes
  -> official MCP tool discovery and contract validation
  -> entity/schema reads + three upstream lineage relationships
  -> DataHub Decision document write
  -> first MCP process closed
  -> fresh MCP process
  -> persisted-content marker verification through grep_documents
  -> sanitized self-verifying evidence reports
```

Evidence from GitHub Actions run `29975433969` is committed in [docs/evidence/datahub-live.md](docs/evidence/datahub-live.md), [datahub-live-seed.json](docs/evidence/datahub-live-seed.json), and [datahub-live-spike.json](docs/evidence/datahub-live-spike.json). Both report hashes are reproducible from their persisted JSON, and the retained evidence contains no token value, password, local endpoint, raw warehouse row, or application secret.

## Measured benchmark

GitHub Actions runs a balanced 30-query regression corpus through the real pipeline and uploads the complete JSON and Markdown reports.

Current CI-generated result:

- 30 cases: 10 `ALLOW`, 10 `REWRITE`, 10 `BLOCK`;
- 100% initial decision accuracy on the declared corpus;
- 100% effective outcome accuracy after rewrite and verification;
- 100% expected reason-code coverage;
- zero false allows;
- zero unsafe effective allows;
- six rewrites remediated and executed;
- four rewrite paths failed closed;
- 16 verified executions.

Evidence:

- [Human-readable benchmark](docs/evidence/benchmark.md)
- [Machine-readable summary](docs/evidence/benchmark-summary.json)
- Full report SHA-256: `4a1b7630012ffd54eba698b6bf1fd66a9dc3b6167d2513ef1c4c5519a8483987`
- Data fingerprint: `bfeae85c4b238e38012aadc6f4c95d24c7a28bcb1da1c35e8eeef5be28be7d16`

Reproduce it:

```bash
toxicjoin-benchmark --output-dir artifacts/benchmark
```

The command exits non-zero if any decision, effective outcome, reason, safe-rewrite expectation, false-allow gate, or unsafe-effective-allow gate regresses. This is a deterministic test of the declared supported SQL and policy profile, not a claim of universal privacy detection.

## Try fixture mode

Requirements: Python 3.11 or 3.12.

### Linux or macOS

```bash
bash run.sh
```

### Windows PowerShell

```powershell
.\run.ps1
```

### Manual

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows: .venv\Scripts\Activate.ps1
python -m pip install -e .
toxicjoin-api
```

The launcher creates deterministic synthetic data on first startup and serves:

- API documentation: `http://127.0.0.1:8000/docs`
- Health: `GET /api/health`
- Curated scenarios: `GET /api/demo/scenarios`
- Analyze without execution: `POST /api/analyze`
- Verify and execute only a safe final query: `POST /api/execute-safe`
- Read and integrity-check a receipt: `GET /api/receipts/{receipt_id}`

A reviewer can follow the exact [90-second judge testing guide](docs/judge-testing.md).

## Run the live DataHub path

Install the optional integration:

```bash
python -m pip install -e '.[datahub]'
```

Then follow [docs/datahub-live-integration.md](docs/datahub-live-integration.md). The core commands are:

```bash
datahub docker quickstart
toxicjoin-seed
toxicjoin-datahub-seed --yes
toxicjoin-datahub-spike --verify
```

The seed command writes only synthetic metadata and creates:

- five DataHub datasets;
- 19 governed schema fields;
- controlled sensitivity tags;
- glossary terms and field associations;
- four table/column lineage links into `retention_scores`.

The spike reads the graph through the official DataHub MCP server, writes a `Decision`, closes the MCP process, opens a second process, and verifies the Decision marker through an independent read-back.

Generated reports are stored under `.toxicjoin/` and are ignored by Git. They contain hashes, counts, URNs, and verification state, but no token, DataHub URL, password, warehouse row, or raw sensitive result.

## The flagship scenario

An analytics agent proposes a churn-risk query grouped by region. The result contains a sensitive model score, but the SQL has no minimum distinct-subject threshold.

ToxicJoin:

1. parses the SQL into a real AST;
2. resolves physical datasets and columns;
3. classifies the governed context;
4. returns `REWRITE` with `SMALL_GROUP_RISK`;
5. adds `HAVING COUNT(DISTINCT c.customer_id) >= 20`;
6. reparses and reevaluates the rewritten query;
7. executes only after the final decision is `ALLOW`;
8. verifies all three output groups contain 40 distinct subjects;
9. stores a receipt without the returned rows;
10. can persist and independently verify the decision through DataHub MCP.

The synthetic warehouse deliberately contains:

- three coarse regions with 40 subjects each;
- twelve precise areas with 10 subjects each;
- pseudonymous customer keys rather than names, email addresses, or phone numbers;
- planted sensitive support categories and churn scores for deterministic testing.

## Security properties

- The policy engine, not an LLM, owns every decision.
- `BLOCK` and `REWRITE` outcomes never call DuckDB.
- SQL is limited to one supported `SELECT` statement.
- DML, DDL, commands, transactions, multiple statements, cross joins, and unresolved constructs fail closed.
- `SELECT *` is blocked until schema-aware governed expansion exists; `COUNT(*)` remains supported.
- A group threshold is trusted only when it counts the expected distinct subject key.
- Thresholds inside `OR` expressions are not trusted.
- CTE rewrites bind the physical subject key to the unique alias visible in the root query and fail closed on ambiguity.
- Rewritten SQL passes the same analyzer and policy engine again.
- DuckDB opens read-only with external access and extension auto-loading disabled, then locks configuration.
- Verification checks final policy status, raw output fields, full group inspection, and observed subject counts.
- Receipts exclude result rows, redact SQL literal values, use strict schemas, and verify a content hash on every read.
- Receipt files use exclusive creation and are never silently overwritten.
- Raw sensitive rows are never sent to an LLM.
- MCP tools and their input schemas are discovered and validated before use.
- MCP initialization and calls have hard timeouts.
- The MCP child process receives only required operating-system/network variables and DataHub credentials.
- OpenAI, AWS, database, and unrelated application secrets are not forwarded.
- Missing assets, unknown payload shapes, conflicting labels, duplicate fields, and incomplete pagination fail closed.
- DataHub write verification occurs from a new MCP process, not an in-memory write result.
- CI fails on any benchmark false allow or unsafe effective allow.

See [SECURITY.md](SECURITY.md), [docs/threat-model.md](docs/threat-model.md), [docs/datahub-live-integration.md](docs/datahub-live-integration.md), [docs/evidence/datahub-live.md](docs/evidence/datahub-live.md), [docs/evidence/hosted-replay.md](docs/evidence/hosted-replay.md), and [docs/judge-testing.md](docs/judge-testing.md).

## Deterministic scenarios

| Scenario | Initial decision | Effective decision | Database called? |
|---|---:|---:|---:|
| Sensitive individual export | `BLOCK` | `BLOCK` | No |
| Sensitive regional aggregate without threshold | `REWRITE` | `ALLOW` after verified rewrite | Yes, safe SQL only |
| Public order counts | `ALLOW` | `ALLOW` | Yes |

Fetch the exact payloads from `GET /api/demo/scenarios`.

## Development

```bash
python -m pip install -e '.[dev]'
ruff check src tests
pytest -q
toxicjoin-benchmark --output-dir artifacts/benchmark
```

GitHub Actions tests Python 3.11 and 3.12. Test diagnostics are uploaded even when a run fails, and the benchmark report is retained as a CI artifact.

Useful focused checks:

```bash
pytest tests/unit/test_sql_parser.py -q
pytest tests/unit/test_policy_engine.py -q
pytest tests/unit/test_receipts.py -q
pytest tests/unit/test_rewriter_cte.py -q
pytest tests/unit/test_datahub_mcp.py -q
pytest tests/unit/test_datahub_context.py -q
pytest tests/unit/test_datahub_settings.py -q
pytest tests/unit/test_datahub_seed.py -q
pytest tests/unit/test_datahub_report_hashes.py -q
pytest tests/integration/test_safe_execution.py -q
pytest tests/integration/test_pipeline.py -q
pytest tests/integration/test_api.py -q
pytest tests/integration/test_datahub_spike.py -q
pytest tests/integration/test_benchmark.py -q
```

## Repository map

```text
src/toxicjoin/
  api/           FastAPI contracts, app, and curated scenarios
  benchmark/     balanced corpus, runner, metrics, and report generation
  context/       fixture and normalized live DataHub context
  demo/          deterministic warehouse and package-owned catalog
  execute/       policy-gated read-only DuckDB execution
  integrations/  DataHub SDK seed, MCP client, and verification spike
  policy/        versioned deterministic policy
  receipts/      sanitized immutable decision receipts
  rewrite/       constrained SQL transformation
  sql/           AST analysis and physical source resolution
  verify/        independent pre/post execution checks
  pipeline.py    end-to-end orchestration

config/           DataHub asset manifest and policy configuration
demo/fixtures/    human-readable metadata fixture mirrored by tests
docs/evidence/    benchmark, live DataHub, and hosted Replay evidence
public/replay/    exact CI-produced static judge-interface bundle and provenance
tests/            unit, integration, adversarial, API, MCP, and benchmark coverage
docs/             scope, PRD, spec, threat model, live guide, judge guide, and evidence
```

## Deliberate limitations

The first rewrite supports an already-grouped analytical query that requires a stronger subject-count threshold. ToxicJoin does not yet claim general SQL repair, automatic identifier removal, location coarsening, differential privacy, or individual-to-grouped query synthesis. Unsupported transformations fail closed.

Fixture metadata provides deterministic judge accessibility. Separately, the committed live evidence proves the SDK seed and MCP read/write/fresh-process-read-back protocol against an ephemeral DataHub OSS deployment in GitHub Actions. It does not claim that the public static Replay is a live DataHub session or that a permanent public DataHub environment is hosted.

The benchmark measures the declared supported corpus. Real organizations must validate their own schemas, classifications, subject keys, policies, and workloads.

## Project principles

- Evidence before claims.
- Fail closed on uncertainty.
- DataHub as governed context and persistent agent memory.
- Honest fixture, live, and replay mode disclosure.
- No Rayluno code, assets, infrastructure, or submission content.

## License

Apache-2.0. See [LICENSE](LICENSE).
