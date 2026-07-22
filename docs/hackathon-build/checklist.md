# ToxicJoin Build Checklist

Build mode: autonomous, with review through draft pull requests.
Verification: automated checks at every item; no automatic merge until the milestone is green.
Git cadence: one focused branch/PR per milestone.
Wow moment: a query built from individually acceptable datasets becomes unsafe only after joining them; ToxicJoin explains the derived risk, safely rewrites the SQL, executes it, and leaves a verified decision in DataHub.

- [x] **1. Lock domain models and statement boundary**
  Spec ref: `spec.md > Domain models` and `SQL analyzer`
  What was built: Strict request, query-plan, context, decision, execution, and verification models. Multiple statements and all non-SELECT statements are rejected.
  Acceptance: A single supported SELECT parses; INSERT/UPDATE/DELETE/DDL and multi-statement inputs return deterministic failure codes.
  Verified: `pytest tests/unit/test_sql_parser.py -q` and full CI on Python 3.11/3.12.

- [x] **2. Extract SQL sources and referenced columns**
  Spec ref: `spec.md > SQL analyzer`
  What was built: Resolve table aliases, joins, root projections, all governed references, group keys, aggregate functions, supported CTE lineage, and subject-bound HAVING thresholds into a normalized QueryPlan.
  Acceptance: The flagship query produces the expected physical sources, join keys, root output lineage, referenced columns, group keys, and trusted threshold subject.
  Verified: `pytest tests/unit/test_sql_parser.py -q` and full CI on Python 3.11/3.12.

- [x] **3. Build fixture context resolver**
  Spec ref: `spec.md > DataHub context resolver` and `Modes`
  What was built: Load DataHub-shaped fixture metadata and map every referenced field to governed ColumnContext classifications and DataHub-like URNs.
  Acceptance: Missing datasets, fields, classifications, or wildcard expansion create explicit metadata-gap reasons and never permit execution.
  Verified: `pytest tests/unit/test_fixture_context.py -q` and full CI on Python 3.11/3.12.

- [x] **4. Implement deterministic policy engine**
  Spec ref: `spec.md > Compositional-risk engine`
  What was built: A package-owned versioned YAML policy with fixed `BLOCK > REWRITE > ALLOW` evaluation and fail-closed upstream failures.
  Acceptance: Direct-sensitive linkage blocks; pseudonym plus multiple quasi-identifiers plus sensitive data blocks; unsafe grouped output rewrites; only a threshold bound to the expected subject key can allow sensitive grouped output.
  Verified: `pytest tests/unit/test_policy_engine.py -q` and full CI on Python 3.11/3.12.

- [x] **5. Seed synthetic DuckDB warehouse**
  Spec ref: `spec.md > Flagship synthetic data model`
  What was built: Deterministically generate customers, orders, support cases, location activity, and retention scores with a reproducible data fingerprint and no direct identity fields.
  Acceptance: One command creates the same database and planted privacy boundary every run; coarse regions contain 40 subjects while precise areas contain 10.
  Verified: `python -m toxicjoin.demo.seed --output .toxicjoin/demo.duckdb` and `pytest tests/integration/test_seed.py -q` in full CI.

- [x] **6. Implement constrained safe SQL rewrite**
  Spec ref: `spec.md > Safe SQL rewriter`
  What was built: For already-grouped supported analytics, add or strengthen `HAVING COUNT(DISTINCT subject_key) >= minimum_group_size`, then reparse and validate the bound subject. Unsupported transformations fail closed.
  Scope cut: automatic identifier removal, location coarsening, and individual-to-grouped synthesis are not claimed in this milestone; they remain optional extensions only if the flagship experience requires them.
  Acceptance: The flagship grouped SQL becomes executable safe SQL; wrong-subject, OR-based, wildcard, individual-level, and unsupported rewrites fail closed.
  Verified: `pytest tests/unit/test_rewriter.py -q` and full CI on Python 3.11/3.12.

- [x] **7. Execute and verify safe SQL**
  Spec ref: `spec.md > DuckDB executor` and `Verification engine`
  What was built: Policy-gated read-only executor, disabled external access and extension auto-loading, locked configuration, bounded preview, timeout interruption, raw-output checks, subject-threshold validation, observed group-size validation, and policy reevaluation.
  Acceptance: BLOCK and REWRITE never reach DuckDB; rewritten SQL executes only after a final ALLOW decision; all returned groups meet the threshold; configuration confirms external access is disabled.
  Verified: `pytest tests/integration/test_safe_execution.py -q` and two independent green GitHub Actions workflows on Python 3.11/3.12.

- [ ] **8. Produce immutable receipts**
  Spec ref: `spec.md > Receipt writer`
  What to build: Serialize evidence, policy version, SQL hashes, decision, verification, execution summary, and write-back status without raw sensitive rows.
  Acceptance: Receipts are deterministic apart from ID/time fields, validate against strict models, and contain no raw sensitive rows.
  Verify: `pytest tests/unit/test_receipts.py -q`

- [ ] **9. Complete real DataHub integration spike**
  Spec ref: `spec.md > DataHub context resolver`, `DataHub write-back`, and `Definition of done for the integration spike`
  What to build: Read schemas/tags/lineage through DataHub MCP, save a Decision, and independently read it back.
  Acceptance: Sanitized evidence proves Python -> DataHub read -> write -> independent verification; failures exit non-zero.
  Verify: `python scripts/datahub_spike.py --verify`

- [ ] **10. Expose API and curated scenarios**
  Spec ref: `spec.md > API contracts`
  What to build: Health, analyze, safe-execute, receipt, and demo-scenario endpoints.
  Acceptance: API tests cover ALLOW, REWRITE, BLOCK, DataHub outage, invalid input, and replay/fixture disclosure without executing unsafe SQL.
  Verify: `pytest tests/integration/test_api.py -q`

- [ ] **11. Add CI, benchmark, and judge evidence**
  Spec ref: `spec.md > Testing strategy` and `Demo contract`
  What to build: Consolidated CI, 30-query benchmark, confusion matrix, examples, known limitations, and a 90-second judge guide.
  Acceptance: Fresh checkout passes lint/tests; benchmark results are generated, not hand-edited; examples include allow/rewrite/block receipts.
  Verify: `ruff check . && pytest -q && python -m toxicjoin.benchmark`

- [ ] **12. Build hosted replay and Devpost handoff**
  Spec ref: `spec.md > Modes`, `Deployment`, and `Demo contract`
  What to build: Clearly labeled recorded replay, SQL diff, evidence graph, verification, DataHub write-back proof, README, video storyboard, and submission links.
  Acceptance: A judge understands and verifies the flagship flow within 90 seconds; video is under three minutes; repository and Apache 2.0 are public.
  Verify: Follow `docs/judge-testing.md` from a clean browser and complete the Devpost readiness checklist.
