# ToxicJoin Build Checklist

Build mode: autonomous, with review through draft pull requests.
Verification: automated checks at every item; no automatic merge.
Git cadence: one focused branch/PR per milestone.
Wow moment: a query built from individually acceptable datasets becomes unsafe only after joining them; ToxicJoin explains the derived risk, safely rewrites the SQL, executes it, and leaves a verified decision in DataHub.

- [ ] **1. Lock domain models and statement boundary**
  Spec ref: `spec.md > Domain models` and `SQL analyzer`
  What to build: Add typed request, query-plan, evidence, decision, verification, and receipt models. Reject multiple statements and all non-SELECT statements.
  Acceptance: A single SELECT parses; INSERT/UPDATE/DELETE/DDL and multi-statement inputs return deterministic failure codes.
  Verify: `pytest tests/unit/test_sql_parser.py -q`

- [ ] **2. Extract SQL sources and referenced columns**
  Spec ref: `spec.md > SQL analyzer`
  What to build: Resolve table aliases, joins, projections, group keys, aggregate functions, and CTEs into a normalized QueryPlan.
  Acceptance: The flagship query produces the expected source tables, join keys, projected columns, and group keys.
  Verify: `pytest tests/unit/test_sql_parser.py tests/adversarial/test_sql_resolution.py -q`

- [ ] **3. Build fixture context resolver**
  Spec ref: `spec.md > DataHub context resolver` and `Modes`
  What to build: Load DataHub-shaped fixture metadata and map every referenced field to ColumnContext classifications.
  Acceptance: Missing datasets, fields, or classifications create explicit metadata-gap reasons and never permit execution.
  Verify: `pytest tests/unit/test_fixture_context.py -q`

- [ ] **4. Implement deterministic policy engine**
  Spec ref: `spec.md > Compositional-risk engine`
  What to build: Load versioned YAML rules and implement BLOCK > REWRITE > ALLOW priority.
  Acceptance: Direct-sensitive linkage blocks; pseudonym plus multiple quasi-identifiers plus sensitive data blocks; unsafe grouped output rewrites; low-risk aggregate allows.
  Verify: `pytest tests/unit/test_policy_engine.py -q`

- [ ] **5. Seed synthetic DuckDB warehouse**
  Spec ref: `spec.md > Flagship synthetic data model`
  What to build: Deterministically generate customers, orders, support cases, location activity, and retention scores.
  Acceptance: One command creates the same database and planted scenario every run.
  Verify: `python -m toxicjoin.demo.seed --output .toxicjoin/demo.duckdb && pytest tests/integration/test_seed.py -q`

- [ ] **6. Implement constrained safe SQL rewrite**
  Spec ref: `spec.md > Safe SQL rewriter`
  What to build: Remove identifiers, coarsen configured location fields, add grouping and minimum distinct-subject threshold, then reparse.
  Acceptance: Flagship SQL becomes executable safe SQL; unsupported rewrites fail closed.
  Verify: `pytest tests/unit/test_rewriter.py -q`

- [ ] **7. Execute and verify safe SQL**
  Spec ref: `spec.md > DuckDB executor` and `Verification engine`
  What to build: Read-only executor, bounded preview, timeout, output-column checks, group-size validation, and policy reevaluation.
  Acceptance: Blocked SQL never reaches DuckDB; rewritten SQL executes only after reevaluation and all groups meet the threshold.
  Verify: `pytest tests/integration/test_safe_execution.py -q`

- [ ] **8. Produce immutable receipts**
  Spec ref: `spec.md > Receipt writer`
  What to build: Serialize evidence, policy version, SQL hashes, decision, verification, and execution summary.
  Acceptance: Receipts are deterministic apart from ID/time fields, validate against Pydantic models, and contain no raw sensitive rows.
  Verify: `pytest tests/unit/test_receipts.py -q`

- [ ] **9. Complete real DataHub integration spike**
  Spec ref: `spec.md > DataHub context resolver`, `DataHub write-back`, and `Definition of done for the integration spike`
  What to build: Read schemas/tags/lineage through DataHub MCP, save a Decision, and independently read it back.
  Acceptance: Sanitized evidence proves Python -> DataHub read -> write -> independent verification; failures exit non-zero.
  Verify: `python scripts/datahub_spike.py --verify`

- [ ] **10. Expose API and curated scenarios**
  Spec ref: `spec.md > API contracts`
  What to build: Health, analyze, safe-execute, receipt, and demo-scenario endpoints.
  Acceptance: API tests cover ALLOW, REWRITE, BLOCK, DataHub outage, and invalid input without executing unsafe SQL.
  Verify: `pytest tests/integration/test_api.py -q`

- [ ] **11. Add CI, benchmark, and judge evidence**
  Spec ref: `spec.md > Testing strategy` and `Demo contract`
  What to build: GitHub Actions, 30-query benchmark, confusion matrix, examples, known limitations, and 90-second judge guide.
  Acceptance: Fresh checkout passes lint/tests; benchmark results are generated, not hand-edited; examples include allow/rewrite/block receipts.
  Verify: `ruff check . && pytest -q && python -m toxicjoin.benchmark`

- [ ] **12. Build hosted replay and Devpost handoff**
  Spec ref: `spec.md > Modes`, `Deployment`, and `Demo contract`
  What to build: Clearly labeled recorded replay, SQL diff, evidence graph, verification, DataHub write-back proof, README, video storyboard, and submission links.
  Acceptance: A judge understands and verifies the flagship flow within 90 seconds; video is under three minutes; repository and Apache 2.0 are public.
  Verify: Follow `docs/judge-testing.md` from a clean browser and complete the Devpost readiness checklist.
