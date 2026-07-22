# ToxicJoin Product Requirements Document

## 1. Product overview
ToxicJoin protects enterprise data access performed by AI agents. Before a generated SQL query reaches the warehouse, ToxicJoin inspects its structure, retrieves governed context from DataHub, detects sensitive combinations that emerge across joins, and either allows, safely rewrites, or blocks execution. The user receives a clear explanation and an auditable receipt. DataHub receives the resulting decision and safe-asset lineage so future humans and agents inherit the knowledge.

## 2. Problem statement
Dataset-level and column-level labels are insufficient when risk emerges only after combining sources. A pseudonymous customer identifier, precise location, behavioral history, and support category may each appear acceptable in isolation but produce a sensitive individual profile when joined. AI agents increase this risk because they can compose broad queries quickly and without understanding governance intent.

## 3. Primary persona
### AI/Data Platform Engineer
Responsible for enabling governed AI access to organizational data. Needs a pre-execution control that is explainable, deterministic for safety decisions, grounded in existing DataHub metadata, and easy to audit.

## 4. User journey
1. User opens ToxicJoin and selects a prepared scenario or pastes a task and SQL query.
2. User starts analysis.
3. ToxicJoin displays parsing and DataHub-context resolution progress.
4. The evidence graph shows datasets, columns, classifications, joins, and the derived-risk node.
5. ToxicJoin returns ALLOW, REWRITE, or BLOCK with specific reasons.
6. For REWRITE, the user sees an original-versus-safe SQL diff.
7. ToxicJoin executes only the approved safe query.
8. The result panel shows output and verification checks.
9. ToxicJoin creates a signed execution receipt.
10. The DataHub panel shows the decision document, tags, and safe-view lineage written back.

## 5. Epics and user stories

### Epic A — Query intake and structural understanding

#### A1. Submit a task and SQL
As a platform engineer, I want to provide the agent's task and SQL so ToxicJoin can evaluate what the agent intends to do.

Acceptance criteria:
- User can provide non-empty task text and SQL.
- Empty task or SQL returns a clear validation error.
- SQL is never executed before a final safe decision.

#### A2. Parse supported SQL
As a platform engineer, I want ToxicJoin to identify referenced tables, aliases, columns, joins, filters, grouping, and CTEs so decisions are based on the actual query structure.

Acceptance criteria:
- Supported flagship queries produce a normalized query model.
- SELECT * is expanded only when schema metadata is available.
- Ambiguous or unresolved columns produce a fail-closed status.
- Unsupported mutation statements are blocked.

### Epic B — DataHub-grounded context

#### B1. Resolve governed metadata
As a platform engineer, I want ToxicJoin to retrieve schema and governance metadata from DataHub so the system relies on organizational truth rather than hard-coded guesses.

Acceptance criteria:
- Each referenced table maps to a DataHub URN.
- Each referenced output or join column has a classification or an explicit metadata-gap state.
- Ownership, domain, and lineage are included when available.
- Missing critical metadata produces BLOCKED_METADATA_GAP.

#### B2. Show evidence provenance
As a reviewer, I want each risk reason to point to the DataHub entity and property that supports it.

Acceptance criteria:
- Every rule finding includes source URNs and column names.
- UI can display the evidence path for the flagship scenario.
- Receipt records the policy version and metadata snapshot identifiers or hashes.

### Epic C — Compositional risk decisions

#### C1. Detect derived sensitivity
As a platform engineer, I want ToxicJoin to detect when safe-looking columns become sensitive through composition.

Acceptance criteria:
- Direct identifier plus sensitive attribute at row level blocks.
- Stable pseudonym plus configured quasi-identifier threshold plus sensitive attribute blocks or rewrites according to purpose.
- Grouped sensitive analytics below the minimum group-size threshold rewrites.
- Safe aggregate analytics allow.

#### C2. Fail closed
As a security reviewer, I want uncertainty to prevent execution rather than silently permit it.

Acceptance criteria:
- Parse failure blocks.
- Missing table resolution blocks.
- Missing critical classification blocks.
- Unsupported SQL blocks.
- DataHub unavailability blocks live execution but allows clearly labeled replay mode.

### Epic D — Safe rewriting and execution

#### D1. Produce a safe analytical rewrite
As a platform engineer, I want a risky but legitimate analytical query to be transformed into a safer equivalent when possible.

Acceptance criteria:
- Rewriter removes individual identifiers from the flagship query.
- Rewriter lowers location precision where policy requires it.
- Rewriter adds a minimum group-size constraint.
- Generated SQL parses and executes successfully.
- UI shows exact differences between original and rewritten SQL.

#### D2. Refuse non-rewritable requests
As a platform engineer, I want requests whose purpose inherently requires sensitive individual output to be blocked rather than cosmetically rewritten.

Acceptance criteria:
- Secondary flagship scenario returns BLOCK.
- No SQL is executed.
- Explanation states why aggregation would change the requested purpose.

#### D3. Verify safe output
As a reviewer, I want proof that the rewritten result meets the configured safeguards.

Acceptance criteria:
- Verification confirms no forbidden output columns.
- Verification confirms minimum group size.
- Verification confirms the query is read-only.
- Failure of any verification blocks result release.

### Epic E — Auditability and DataHub memory

#### E1. Generate execution receipt
As an auditor, I want a machine-readable record of the decision and evidence.

Acceptance criteria:
- Receipt contains request ID, timestamp, policy version, input hash, decision, findings, original SQL hash, safe SQL hash if applicable, execution status, verification results, and DataHub references.
- Receipt is stored under examples/receipts for demo scenarios.

#### E2. Write decision to DataHub
As a future human or agent, I want the decision preserved in DataHub.

Acceptance criteria:
- Decision document is written to DataHub in live mode.
- Derived-risk tag or property is attached to the relevant entity or safe view.
- Write-back result is independently verified.
- Replay mode clearly labels captured evidence as recorded, not live.

#### E3. Register safe-view lineage
As a data platform engineer, I want the safe output asset connected to its source assets.

Acceptance criteria:
- Generated safe view has a DataHub entity.
- Upstream lineage points to the source datasets.
- Decision document links to the safe view and policy receipt.

### Epic F — Judge experience

#### F1. Run a public replay
As a judge, I want to understand the full workflow without installing DataHub.

Acceptance criteria:
- Public replay opens without authentication.
- Replay explicitly identifies itself as recorded evidence.
- Judge can run the flagship flow and inspect SQL diff, decision, verification, and write-back proof.

#### F2. Run locally
As a technical judge, I want a reproducible local path.

Acceptance criteria:
- Windows and Linux/macOS launch instructions exist.
- Default replay or fixture path requires no API key.
- Live DataHub setup is documented separately.
- Judge testing guide completes in under 90 seconds for the replay path.

## 6. Edge cases
- Empty query.
- Unsupported INSERT, UPDATE, DELETE, DDL, or multi-statement input.
- Ambiguous unqualified column.
- SELECT * with missing schema.
- Alias collision.
- CTE shadowing a physical table name.
- Nested query hiding a sensitive projection.
- Missing DataHub classification.
- DataHub unavailable.
- Safe rewrite returns zero rows.
- Safe rewrite creates groups smaller than policy threshold.
- An LLM explanation contradicts the deterministic result; deterministic result wins and contradiction is logged.

## 7. Experience requirements
- Decision must be visible without scrolling on a standard laptop viewport.
- Unsafe concepts must not rely on color alone.
- Evidence wording must identify exact columns and rules.
- Product must never imply formal legal compliance certification.
- Recorded replay and live execution must be visibly distinct.

## 8. Evaluation requirements
- At least 30 labeled benchmark queries.
- Expected-decision manifest checked into the repository.
- Automated tests compare actual and expected decisions.
- False positives and misses are reported honestly.
- Benchmark command generates a machine-readable and Markdown summary.

## 9. Submission requirements
- Public repository.
- Apache 2.0 license at root.
- Public demo video under three minutes.
- Public replay or hosted demo.
- Complete README and judge-testing guide.
- Sample queries, decisions, rewrites, and receipts in examples/.
- DataHub technologies explicitly documented.

## 10. Definition of done
The project is done when a judge can observe a real or recorded DataHub-grounded query analysis, see ToxicJoin detect compositional sensitivity, see a deterministic REWRITE or BLOCK, verify that only safe SQL executes, inspect the resulting receipt and DataHub write-back proof, and reproduce the benchmark from a clean checkout.
