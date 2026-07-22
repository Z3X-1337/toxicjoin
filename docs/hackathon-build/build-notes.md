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
- Strict Pydantic domain models and versioned policy configuration.
- Deterministic `BLOCK > REWRITE > ALLOW` policy engine.
- Read-only SQL statement boundary using SQLGlot.
- Physical source and column resolution across aliases and supported CTEs.
- Trusted group-size extraction bound to `COUNT(DISTINCT subject_key)`.
- DataHub-shaped fixture metadata resolver and governed synthetic catalog.
- Deterministic DuckDB warehouse with reproducible fingerprints.
- Constrained minimum-group SQL rewrite with full reparse and policy reevaluation.
- Unit, integration, and adversarial tests for the implemented surface.

## Security findings addressed
1. CTE output names cannot be treated as physical governed columns; they are traced to source columns.
2. A group threshold is not trusted merely because it counts a distinct field; it must count the expected subject key.
3. Thresholds inside `OR` expressions are not accepted as guarantees.
4. `SELECT *` remains blocked until schema-aware expansion is implemented.
5. Rewritten SQL is not trusted automatically; it must pass the same analyzer and policy engine again.

## Verification state
- Lint passed in the first independent GitHub Actions run.
- The first full pytest run failed; durable per-version test artifacts were added to CI for exact diagnostics.
- A bootstrap PR workflow was placed on `main` to validate the current branch without merging untested code.

## Next gate
Obtain green CI on Python 3.11 and 3.12, then implement the read-only DuckDB executor and independent verification engine.
