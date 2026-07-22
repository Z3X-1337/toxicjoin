# Build Notes

## Locked decisions
- Name: ToxicJoin.
- Track: Agents That Do Real Work.
- Core differentiator: compositional sensitivity before SQL execution.
- Decision authority: deterministic policy engine.
- LLM role: explanation only.
- Primary database: DuckDB.
- Metadata source: DataHub OSS through the official MCP server, with the official Python SDK used to seed deterministic demo metadata.
- Frontend: React/Vite after vertical slice.
- Freeze target: August 8, 2026.

## Operating constraints
- Rayluno code, assets, infrastructure, submissions, and content are excluded completely.
- Unsupported SQL, missing metadata, failed rewrites, and failed verification are fail-closed states.
- No raw sensitive rows may be sent to an LLM or stored in public receipts.
- Pull requests remain draft until automated validation is green.
- Fixture, live, and replay evidence must be labeled honestly and never substituted for each other.

## Core foundation implemented
- Strict Pydantic domain models and package-owned versioned policy configuration.
- Deterministic `BLOCK > REWRITE > ALLOW` policy engine.
- Read-only SQL statement boundary using SQLGlot.
- Physical source and column resolution across aliases and supported CTEs.
- Separate root-output lineage from all governed references.
- Trusted group-size extraction bound to `COUNT(DISTINCT subject_key)`.
- DataHub-shaped fixture metadata resolver and governed synthetic catalog.
- Deterministic DuckDB warehouse with reproducible fingerprints.
- Constrained minimum-group SQL rewrite with full reparse and policy reevaluation.
- Policy-gated DuckDB executor with read-only mode, disabled external access, disabled extension auto-loading, locked configuration, timeout interruption, and bounded previews.
- Independent verification of final policy status, subject-bound threshold, raw output fields, complete result inspection, and observed group sizes.
- Immutable receipt lifecycle preserving initial and final decisions, policy evidence, SQL hashes, governed columns, verification evidence, deterministic execution summaries, and write-back state.
- Receipt literal redaction, semantic content hashes, exclusive creation, idempotent writes, traversal protection, and integrity verification on every read.
- Pipeline orchestration that emits a receipt for invalid SQL, metadata outage, BLOCK, REWRITE, ALLOW, missing executor, and failed verification paths.
- FastAPI endpoints for health, analysis, safe execution, curated scenarios, and receipt lookup.
- Zero-configuration fixture startup with a package-owned governed catalog and deterministic DuckDB seed.
- One-command Windows and Linux/macOS launchers.
- HTTP no-store and browser-hardening headers without permissive CORS defaults.
- Provider-neutral context resolution used by both fixture and live DataHub snapshots.
- Pinned optional DataHub SDK and stable MCP SDK dependencies.
- DataHub SDK seed plan creating five datasets, 19 fields, controlled tags, glossary terms, field associations, and four column-lineage relationships.
- Official MCP stdio transport with lazy dependency loading and minimal child-process environment.
- Runtime MCP tool discovery and input-schema contract validation.
- Bounded schema pagination, entity-set verification, duplicate-field rejection, and controlled tag/term classification.
- Hard timeouts on MCP initialization, tool discovery, and every tool call.
- Two-process Decision verification: write in one MCP process, close it, then read and verify the marker in a fresh process.
- Sanitized atomic seed and spike evidence reports without tokens, private endpoints, passwords, or warehouse rows.
- Unit, integration, adversarial, API, SDK-fake, MCP-fake, and security-header tests for the implemented surface.

## Security findings addressed
1. CTE output names cannot be treated as physical governed columns; they are traced to source columns.
2. Intermediate CTE projections cannot be mistaken for final output columns.
3. A group threshold is not trusted merely because it counts a distinct field; it must count the expected subject key.
4. Thresholds inside `OR` expressions are not accepted as guarantees.
5. `SELECT *` remains blocked until schema-aware expansion is implemented, while `COUNT(*)` is correctly treated as an aggregate rather than an output wildcard.
6. Rewritten SQL is not trusted automatically; it must pass the same analyzer and policy engine again.
7. `BLOCK` and `REWRITE` outcomes never invoke the database executor.
8. DuckDB external access and extension auto-loading are disabled before configuration is locked.
9. Receipt files never persist raw execution rows or variable timing data.
10. API exception responses do not expose SQL, local paths, credentials, or internal exception messages.
11. Receipt lookup detects content tampering and returns a stable integrity error.
12. Runtime metadata and the human-readable fixture catalog are checked for exact drift in CI.
13. DataHub MCP tools and input properties are verified dynamically before any read or mutation.
14. Missing assets, unclassified fields, conflicting classifications, duplicate fields, malformed payloads, and pagination without progress fail closed.
15. OpenAI, AWS, database, and unrelated environment secrets are not forwarded to the MCP child process.
16. MCP timeout errors do not include tool arguments, URNs, tokens, or private endpoint details.
17. DataHub write success cannot be inferred from the write response; a new MCP process must read back the unique marker.
18. Live reports are excluded from Git and contain only sanitized counts, URNs, state, and hashes.

## CI evidence
- Initial full CI exposed six failures: five stale policy paths and one CTE projection-lineage defect.
- The canonical policy loader and root-output analyzer fixed both root causes.
- GitHub Actions `CI` run 41 completed successfully on Python 3.11 and 3.12 for the deterministic safety core.
- Independent `Pull Request CI` run 12 completed successfully on Python 3.11 and 3.12 for the deterministic safety core.
- GitHub Actions `CI` run 76 completed successfully on Python 3.11 and 3.12 for receipts, orchestration, API, secure headers, launchers, and documentation.
- GitHub Actions `CI` run 82 completed successfully on Python 3.11 and 3.12 after the initial DataHub MCP contract and context tests.
- GitHub Actions `CI` run 84 completed successfully on Python 3.11 and 3.12 after adding hard MCP timeouts and child-secret isolation tests.
- CI cancels stale runs for the same pull request and persists per-version pytest artifacts for diagnosis.

## Deliberate scope cut
The first safe rewrite supports an already-grouped query that needs a stronger subject-count threshold. Automatic identifier removal, location coarsening, and individual-to-grouped synthesis are not claimed yet. Unsupported transformations fail closed. This preserves technical honesty and keeps the flagship vertical slice deterministic.

## External verification gate
The DataHub SDK seed, live snapshot normalization, MCP read/write/read-back protocol, and reports are implemented and tested over fake transports. The final live evidence remains intentionally unclaimed until Docker or a hosted DataHub instance is available and both commands succeed:

```text
toxicjoin-datahub-seed --yes
toxicjoin-datahub-spike --verify
```

The execution environment used by the assistant does not expose Docker, so it cannot fabricate or substitute this evidence.

## Next milestone
After the real DataHub report is captured, build the 30-query benchmark, generated confusion matrix, judge guide, and hosted replay interface.
