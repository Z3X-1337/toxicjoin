# ToxicJoin Technical Specification

Status: implementation contract for the first working vertical slice.
Target category: Agents That Do Real Work.

## 1. Objectives

ToxicJoin evaluates SQL proposed by an AI data agent before execution. It combines SQL structure with governed metadata from DataHub to detect sensitivity created by joining otherwise acceptable datasets. It returns one deterministic outcome: `ALLOW`, `REWRITE`, or `BLOCK`.

The flagship path must work end to end:

```text
Task + SQL
  -> SQL AST
  -> referenced tables and columns
  -> DataHub governed context
  -> compositional-risk evidence
  -> deterministic decision
  -> safe SQL execution when allowed or rewritten
  -> verification
  -> receipt and DataHub write-back
```

## 2. Architecture principles

1. The policy engine, not an LLM, owns the decision.
2. Unknown SQL, unresolved metadata, and failed verification are fail-closed states.
3. Raw data rows are never sent to an LLM.
4. DataHub is the source of governed context and persistent decision memory.
5. Replay mode must be clearly labeled and generated from a captured live run.
6. Every decision contains machine-readable evidence.

## 3. Components

### 3.1 FastAPI application

Responsibilities:
- expose health and analysis endpoints;
- validate request and response models;
- compose the analyzer, context resolver, policy engine, rewriter, executor, verifier, and receipt writer;
- prevent execution until a decision is complete.

### 3.2 SQL analyzer

Library: `sqlglot`.

Supported profile for the MVP:
- `SELECT` statements only;
- table aliases;
- inner and left joins;
- projections;
- filters;
- `GROUP BY` and `HAVING`;
- common table expressions;
- nested read-only subqueries where source columns can be resolved.

Rejected or fail-closed:
- inserts, updates, deletes, merges, DDL, commands, and transactions;
- multiple statements;
- unresolved `SELECT *` after schema resolution;
- unsupported dialect constructs;
- ambiguous unqualified columns.

Output: a normalized `QueryPlan` containing statement type, sources, joins, projections, group keys, aggregate functions, predicates, and analysis warnings.

### 3.3 DataHub context resolver

Primary read path: DataHub MCP Server.

Required governed context:
- dataset URNs;
- schemas and field paths;
- tags;
- glossary terms;
- ownership and domains when available;
- table and column lineage when available;
- previous ToxicJoin decisions when available.

The resolver maps every referenced source column to a normalized `ColumnContext`.

Classification vocabulary:
- `DIRECT_IDENTIFIER`
- `STABLE_PSEUDONYM`
- `QUASI_IDENTIFIER`
- `SENSITIVE_ATTRIBUTE`
- `PUBLIC_OR_LOW_RISK`
- `UNCLASSIFIED`

If a referenced column cannot be resolved or classified, the resolver records a metadata gap. The policy engine must not silently downgrade the gap.

### 3.4 Compositional-risk engine

The engine is deterministic and versioned. Rules are loaded from YAML and evaluated in a fixed priority order.

Priority:

```text
BLOCK > REWRITE > ALLOW
```

Initial rules:

- direct identifier projected with a sensitive attribute at individual granularity -> `BLOCK`;
- stable pseudonym plus multiple quasi-identifiers plus sensitive attribute at individual granularity -> `BLOCK`;
- sensitive grouped output without a minimum distinct-subject threshold -> `REWRITE`;
- unresolved SQL, unresolved metadata, unsupported constructs, or verification failure -> `BLOCK` with a specific reason code;
- otherwise -> `ALLOW`.

The engine emits an `EvidenceGraph` with nodes for task, query, dataset, column, classification, join, rule, and decision.

### 3.5 Safe SQL rewriter

Supported rewrite operations:
- remove projected direct or stable identifiers;
- remove unnecessary precise quasi-identifiers;
- replace a precise location field with a configured coarser field when an explicit mapping exists;
- convert individual output to grouped output for the flagship scenario;
- add `HAVING COUNT(DISTINCT subject_key) >= minimum_group_size`;
- preserve the requested aggregate purpose where possible.

A rewrite is accepted only if it reparses successfully and passes policy evaluation a second time.

### 3.6 DuckDB executor

MVP execution target: a synthetic DuckDB warehouse.

Safety constraints:
- read-only connection;
- one statement per request;
- execution timeout;
- bounded result preview;
- no external file or network access from SQL;
- no extension installation.

### 3.7 Verification engine

Verification occurs before a rewritten result is considered successful.

Checks:
- rewritten SQL parses as a single read-only query;
- prohibited identifiers are absent from output columns;
- every group meets the configured minimum subject count;
- output row count and schema are captured;
- policy reevaluation returns `ALLOW`;
- execution completed without mutation.

### 3.8 Receipt writer

Each analysis produces an immutable JSON-compatible receipt containing:
- receipt ID;
- timestamp;
- task purpose;
- SQL hashes;
- original and safe SQL when applicable;
- policy version;
- decision and reason codes;
- resolved DataHub URNs and classifications;
- evidence graph;
- verification results;
- execution summary;
- write-back status.

Receipts are stored under `examples/receipts/` for checked-in examples and in a runtime directory for local runs.

### 3.9 DataHub write-back

Preferred write-back:
- save a Decision document through DataHub MCP;
- attach a derived-risk tag or governed property to the relevant asset;
- register the safe view and its lineage through the DataHub SDK when the MCP mutation surface is insufficient;
- record the policy version and receipt reference.

Every mutation must be independently verified through a separate read.

## 4. Domain models

### AnalysisRequest

```json
{
  "task_purpose": "Identify neighborhoods with elevated churn risk",
  "sql": "SELECT ...",
  "dialect": "duckdb",
  "subject_key": "customer_id"
}
```

### AnalysisResponse

```json
{
  "decision": "REWRITE",
  "reason_codes": ["COMPOSITIONAL_REIDENTIFICATION_RISK", "SMALL_GROUP_RISK"],
  "original_sql": "SELECT ...",
  "safe_sql": "SELECT ... HAVING COUNT(DISTINCT customer_id) >= 20",
  "evidence": {},
  "verification": {},
  "receipt_id": "tj_...",
  "writeback": {"status": "verified"}
}
```

### Decision enum

- `ALLOW`
- `REWRITE`
- `BLOCK`

### Failure reason codes

- `UNSUPPORTED_STATEMENT`
- `MULTIPLE_STATEMENTS`
- `AMBIGUOUS_COLUMN`
- `UNRESOLVED_DATASET`
- `UNRESOLVED_COLUMN`
- `UNCLASSIFIED_COLUMN`
- `COMPOSITIONAL_REIDENTIFICATION_RISK`
- `DIRECT_SENSITIVE_LINKAGE`
- `SMALL_GROUP_RISK`
- `REWRITE_FAILED`
- `VERIFICATION_FAILED`
- `DATAHUB_UNAVAILABLE`

## 5. API contracts

### GET /api/health

Returns package version, policy version, DataHub mode, DuckDB status, and replay/live mode.

### POST /api/analyze

Validates and analyzes SQL without executing it. Returns decision, evidence, and proposed safe SQL.

### POST /api/execute-safe

Runs the full pipeline. It may execute only when the final policy result is `ALLOW`. For an original `REWRITE` decision, the rewritten SQL must pass reevaluation and verification first.

### GET /api/receipts/{receipt_id}

Returns a stored receipt.

### GET /api/demo/scenarios

Returns curated flagship scenarios and expected outcomes.

## 6. Flagship synthetic data model

- `customers`: pseudonymous customer key, age band, precise area, coarse region;
- `orders`: customer key, purchase amount, category, timestamp;
- `support_cases`: customer key, case category, sensitivity level;
- `location_activity`: customer key, precise area, activity count;
- `retention_scores`: customer key, churn score and model timestamp.

Data is synthetic and deterministic from a fixed seed.

## 7. Modes

### Fixture mode

Uses checked-in DataHub-shaped metadata and synthetic DuckDB data. It supports deterministic tests but must never be presented as live DataHub.

### Live mode

Reads governed context through DataHub MCP and performs verified write-back. This is the source of the captured replay.

### Replay mode

Displays a signed/captured live run without requiring judge credentials. The UI must label it as a recorded run.

## 8. Error strategy

- API errors are structured and contain a public message plus internal reason code.
- DataHub timeouts produce a fail-closed decision, not a fallback allow.
- A rewriter error produces `BLOCK` with `REWRITE_FAILED`.
- A verifier error produces `BLOCK` with `VERIFICATION_FAILED`.
- No exception may cause the original query to execute.

## 9. Security controls

- strict read-only SQL statement allowlist;
- no raw sensitive values in prompts or logs;
- secrets loaded only from environment variables;
- structured log redaction;
- bounded result previews;
- deterministic policy version in each receipt;
- independent verification of DataHub mutations;
- synthetic data only in the public repository.

## 10. File structure

```text
src/toxicjoin/
  api.py
  models.py
  sql/parser.py
  context/base.py
  context/fixture.py
  context/datahub_mcp.py
  policy/engine.py
  policy/default_policy.yaml
  rewrite/engine.py
  execute/duckdb_executor.py
  verify/engine.py
  receipts/writer.py
  integrations/datahub_writeback.py

tests/
  unit/
  integration/
  adversarial/
  benchmark/
```

## 11. Testing strategy

Unit tests:
- statement allowlist;
- SQL source and projection extraction;
- classification combinations;
- rule priority;
- rewrite transformations;
- receipt serialization.

Integration tests:
- fixture metadata plus DuckDB end-to-end;
- safe SQL execution;
- blocked SQL never reaches the executor;
- rewrite reevaluation;
- captured DataHub write-back contract.

Adversarial tests:
- multiple statements;
- comments and formatting tricks;
- CTE aliasing;
- nested queries;
- wildcard projections;
- ambiguous columns;
- unsupported mutations.

Benchmark:
- 10 allow;
- 10 rewrite;
- 10 block;
- published confusion matrix and known limitations.

## 12. Deployment

- local live mode for DataHub integration;
- public hosted replay for judges;
- GitHub Actions for lint and tests;
- no production credentials in the hosted replay.

## 13. Demo contract

The public judge path must demonstrate:
1. an agent-proposed query;
2. governed context loaded from DataHub evidence;
3. derived sensitivity created by joins;
4. deterministic `REWRITE` or `BLOCK`;
5. successful safe execution for the rewrite scenario;
6. verification details;
7. persistent DataHub decision memory.

## 14. Definition of done for the integration spike

The integration spike is complete only when:
- Python reads real metadata from DataHub;
- Python writes a Decision or equivalent governed result;
- a separate read confirms the write landed;
- the exact commands and sanitized output are committed;
- failure produces a non-zero exit and a clear error.
