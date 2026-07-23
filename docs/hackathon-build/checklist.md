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
  What was built: For already-grouped supported analytics, add or strengthen `HAVING COUNT(DISTINCT subject_key) >= minimum_group_size`, then reparse and validate the bound subject. CTE rewrites bind physical subjects to a unique root-query alias; ambiguous bindings fail closed.
  Scope cut: automatic identifier removal, location coarsening, and individual-to-grouped synthesis are not claimed in this milestone; they remain optional extensions only if the flagship experience requires them.
  Acceptance: The flagship and supported CTE grouped SQL become executable safe SQL; wrong-subject, OR-based, wildcard, individual-level, ambiguous-alias, and unsupported rewrites fail closed.
  Verified: `pytest tests/unit/test_rewriter.py tests/unit/test_rewriter_cte.py -q` and full CI on Python 3.11/3.12.

- [x] **7. Execute and verify safe SQL**
  Spec ref: `spec.md > DuckDB executor` and `Verification engine`
  What was built: Policy-gated read-only executor, disabled external access and extension auto-loading, locked configuration, bounded preview, timeout interruption, raw-output checks, subject-threshold validation, observed group-size validation, and policy reevaluation.
  Acceptance: BLOCK and REWRITE never reach DuckDB; rewritten SQL executes only after a final ALLOW decision; all returned groups meet the threshold; configuration confirms external access is disabled.
  Verified: `pytest tests/integration/test_safe_execution.py -q` and two independent green GitHub Actions workflows on Python 3.11/3.12.

- [x] **8. Produce immutable receipts**
  Spec ref: `spec.md > Receipt writer`
  What was built: Strict receipts preserve initial/final decisions and policy evidence; store SQL hashes, governed columns, verification checks, deterministic execution summaries, and write-back state; redact SQL literals; exclude result rows and variable timing; calculate a deterministic content hash; use exclusive atomic creation and verify integrity on every read.
  Acceptance: IDs and timestamps may vary while semantic content remains hash-stable; unknown fields, traversal IDs, lifecycle contradictions, overwrites, and tampered files are rejected; no result rows enter persisted receipts.
  Verified: `pytest tests/unit/test_receipts.py -q` and full CI on Python 3.11/3.12.

- [x] **9. Complete real DataHub integration spike**
  Spec ref: `spec.md > DataHub context resolver`, `DataHub write-back`, and `Definition of done for the integration spike`
  What was built: Provider-neutral context models; official SDK seed for five datasets, 19 governed fields, nine tags, seven glossary terms, and four column-lineage writes; official MCP stdio transport; runtime tool/schema validation; bounded pagination; normalized live metadata; fail-closed classifications; hard operation timeouts; minimal child environment; entity/schema/lineage reads; Decision write; process closure; fresh-process `grep_documents` read-back; sanitized atomic reports; reproducible evidence hashes; and complete fake-SDK/fake-MCP regression tests.
  Live result: GitHub Actions run `29975433969` passed against DataHub OSS. MCP read three upstream relationships for the flagship field, persisted `urn:li:document:shared-8d25384c-c52d-4864-a103-1203b0c34bf6`, and verified its unique marker from a fresh MCP process.
  Acceptance: Sanitized evidence proves SDK seed -> MCP entity/schema/lineage reads -> Decision write -> first process closed -> new MCP process -> persisted-content marker read-back; failures exit non-zero.
  Verified: `docs/evidence/datahub-live.md`, `docs/evidence/datahub-live-seed.json`, `docs/evidence/datahub-live-spike.json`, and GitHub Actions run https://github.com/Z3X-1337/toxicjoin/actions/runs/29975433969.

  **Preview Agent Registry extension:** A reusable git-backed `Compositional Risk Review` Agent Skill, five MCP tool API entities, and a ToxicJoin AI Agent were independently read back from DataHub's coordinated development quickstart. This preview is isolated from the stable enforcement path and is documented in `docs/evidence/datahub-agent-registry.md`.

- [x] **10. Expose API and curated scenarios**
  Spec ref: `spec.md > API contracts`
  What was built: Zero-configuration fixture startup, package-owned governed catalog, pipeline orchestration, Health, Analyze, Safe Execute, Receipt Lookup, and curated scenario endpoints; one-command Windows/Linux launchers; strict request/response models; no-cache and browser-hardening headers.
  Acceptance: HTTP tests cover ALLOW, REWRITE, BLOCK, context outage, invalid input, COUNT(*) versus SELECT *, executor unavailability, receipt lookup/tamper detection, fixture disclosure, secure headers, and real DuckDB output without executing unsafe SQL.
  Verified: `pytest tests/integration/test_pipeline.py tests/integration/test_api.py tests/integration/test_api_security_headers.py -q` and full CI on Python 3.11/3.12.

- [x] **11. Add CI, benchmark, and judge evidence**
  Spec ref: `spec.md > Testing strategy` and `Demo contract`
  What was built: Consolidated CI with latest-commit cancellation and diagnostic artifacts; balanced 30-query corpus; real pipeline execution; initial/effective confusion matrices; deterministic JSON/Markdown reports and hashes; zero-false-allow gates; CI benchmark artifact; committed human/machine-readable evidence; declared limitations; curated ALLOW/REWRITE/BLOCK scenarios that generate inspectable receipts; and a 90-second judge guide.
  Measured result: 30/30 initial decisions, 30/30 effective outcomes, 30/30 expected reasons, zero false allows, zero unsafe effective allows, six rewrites remediated, four rewrites failed closed, and 16 verified executions.
  Acceptance: Fresh checkout passes lint/tests; benchmark evidence is generated by code and CI; regression gates exit non-zero; judges can generate and inspect ALLOW, REWRITE, and BLOCK receipts through the documented API path.
  Verified: `ruff check src tests && pytest -q && toxicjoin-benchmark --output-dir artifacts/benchmark`; CI run 97; `docs/evidence/benchmark.md`; `docs/judge-testing.md`.

- [ ] **12. Complete Devpost handoff**
  Spec ref: `spec.md > Modes`, `Deployment`, and `Demo contract`
  What is complete: Judge decision cockpit; clearly labeled deterministic Replay; evidence graph; SQL diff; verification and receipt panels; hardened Docker/FastAPI executable path; public Vercel replay; immutable CI-produced interface assets; external Chrome verification at 1440×1000 and 390×844; committed Replay evidence and screenshot hashes; Devpost draft; owner review index/checklist; real-interface cover; Microsoft neural narration specification; and under-three-minute storyboard.
  Hosted Replay result: https://toxicjoin-replay.vercel.app/ passed HTTP, immutable asset, desktop/mobile rendering, visible disclosure, REWRITE→ALLOW, benchmark, console, request, and overflow gates in GitHub Actions run `29980181195`.
  Remaining gates: receive and approve the Microsoft WAV, edit and publish the final video, replace the final video placeholder, complete the exact-version owner review, and stop for explicit submission approval.
  Acceptance: A judge understands and verifies the flagship flow within 90 seconds; video is under three minutes; repository and Apache 2.0 are public; owner approves the exact final packet.
  Verify: Follow `docs/judge-testing.md`, `docs/evidence/hosted-replay.md`, and `docs/submission/owner-review-index.md`, then complete `docs/submission/review-checklist.md`.
