# ToxicJoin

> A compositional privacy firewall that blocks or safely rewrites risky SQL before AI data agents execute it.

ToxicJoin is being built for **Build with DataHub: The Agent Hackathon** in the **Agents That Do Real Work** category.

Individually acceptable datasets can become sensitive when an agent joins them. ToxicJoin analyzes the proposed SQL before execution, resolves governed column context, applies a deterministic policy, and returns one outcome:

- **ALLOW** — execute through a hardened read-only path.
- **REWRITE** — produce a constrained safe query, then analyze it again.
- **BLOCK** — stop before the database is called.

Every path creates a hashed decision receipt. Receipts contain metadata and verification evidence, but never raw result rows.

## Current status

The deterministic fixture-mode vertical slice works end to end:

```text
Task + SQL
  -> SQLGlot AST and physical column lineage
  -> governed fixture metadata shaped like DataHub context
  -> deterministic BLOCK / REWRITE / ALLOW policy
  -> constrained subject-threshold rewrite
  -> policy reevaluation
  -> hardened read-only DuckDB execution
  -> independent result verification
  -> immutable sanitized receipt
  -> FastAPI response and receipt lookup
```

Live DataHub MCP read/write/read-back integration is the next milestone. Fixture mode is explicitly labeled and is not presented as a live DataHub run.

## Try it

Requirements: Python 3.11 or 3.12.

### Linux or macOS

```bash
./run.sh
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
9. stores a receipt without the returned rows.

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
- Rewritten SQL passes the same analyzer and policy engine again.
- DuckDB opens read-only with external access and extension auto-loading disabled, then locks configuration.
- Verification checks final policy status, raw output fields, full group inspection, and observed subject counts.
- Receipts exclude result rows, redact SQL literal values, use strict schemas, and verify a content hash on every read.
- Receipt files use exclusive creation and are never silently overwritten.
- Raw sensitive rows are never sent to an LLM.

See [SECURITY.md](SECURITY.md) and [docs/threat-model.md](docs/threat-model.md).

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
```

GitHub Actions tests Python 3.11 and 3.12. Test diagnostics are uploaded as artifacts even when a run fails.

Useful focused checks:

```bash
pytest tests/unit/test_sql_parser.py -q
pytest tests/unit/test_policy_engine.py -q
pytest tests/unit/test_receipts.py -q
pytest tests/integration/test_safe_execution.py -q
pytest tests/integration/test_pipeline.py -q
pytest tests/integration/test_api.py -q
```

## Repository map

```text
src/toxicjoin/
  api/          FastAPI contracts, app, and curated scenarios
  context/      governed metadata resolution
  demo/         deterministic warehouse and package-owned catalog
  execute/      policy-gated read-only DuckDB execution
  policy/       versioned deterministic policy
  receipts/     sanitized immutable decision receipts
  rewrite/      constrained SQL transformation
  sql/          AST analysis and physical source resolution
  verify/       independent pre/post execution checks
  pipeline.py   end-to-end orchestration

demo/fixtures/  human-readable metadata fixture mirrored by tests
tests/          unit, integration, and adversarial coverage
docs/           scope, PRD, spec, threat model, and build evidence
```

## Deliberate limitations

The first rewrite supports an already-grouped analytical query that requires a stronger subject-count threshold. ToxicJoin does not yet claim general SQL repair, automatic identifier removal, location coarsening, or individual-to-grouped query synthesis. Unsupported transformations fail closed.

Fixture metadata proves deterministic behavior and judge accessibility. It does not replace the required live DataHub integration, which will add MCP context reads, decision write-back, and independent read-back verification.

## Project principles

- Evidence before claims.
- Fail closed on uncertainty.
- DataHub as governed context and persistent agent memory.
- Honest fixture, live, and replay mode disclosure.
- No Rayluno code, assets, infrastructure, or submission content.

## License

Apache-2.0. See [LICENSE](LICENSE).
