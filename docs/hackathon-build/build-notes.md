# Build Notes

## Locked decisions
- Name: ToxicJoin.
- Track: Agents That Do Real Work.
- Core differentiator: compositional sensitivity before SQL execution.
- Decision authority: deterministic policy engine.
- LLM role: explanation only.
- Primary database: DuckDB.
- Metadata source: DataHub OSS through MCP, with SDK for gaps such as lineage write-back.
- Frontend: React/Vite after vertical slice.
- Freeze target: August 8, 2026.

## Operating constraints
- Rayluno code, assets, infrastructure, submissions, and content are excluded completely.
- Unsupported SQL, missing metadata, failed rewrites, and failed verification are fail-closed states.
- No raw sensitive rows may be sent to an LLM or stored in public receipts.
- Pull requests remain draft until automated validation is green.

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
- Unit, integration, adversarial, API, and security-header tests for the implemented surface.

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

## CI evidence
- Initial full CI exposed six failures: five stale policy paths and one CTE projection-lineage defect.
- The canonical policy loader and root-output analyzer fixed both root causes.
- GitHub Actions `CI` run 41 completed successfully on Python 3.11 and 3.12 for the deterministic safety core.
- Independent `Pull Request CI` run 12 completed successfully on Python 3.11 and 3.12 for the deterministic safety core.
- GitHub Actions `CI` run 76 completed successfully on Python 3.11 and 3.12 for receipts, orchestration, API, secure headers, launchers, and documentation.
- CI cancels stale runs for the same pull request and persists per-version pytest artifacts for diagnosis.

## Deliberate scope cut
The first safe rewrite supports an already-grouped query that needs a stronger subject-count threshold. Automatic identifier removal, location coarsening, and individual-to-grouped synthesis are not claimed yet. Unsupported transformations fail closed. This preserves technical honesty and keeps the flagship vertical slice deterministic.

## Next milestone
Complete a real DataHub MCP read/write/read-back spike, normalize live DataHub metadata into the same context model, and persist verified write-back state into receipts.
