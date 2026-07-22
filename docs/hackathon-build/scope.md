# ToxicJoin — Winning Scope

## Project thesis
ToxicJoin is a compositional privacy firewall for AI data agents. It intercepts SQL before execution, resolves the query's tables and columns against DataHub, detects sensitivity that emerges only when individually acceptable datasets are joined, and returns one of three deterministic decisions: ALLOW, REWRITE, or BLOCK. It then executes the safe path and writes the decision, evidence, and safe-view lineage back into DataHub.

## Winning claim
Individually safe datasets can become sensitive when an AI agent combines them. ToxicJoin catches that risk before execution.

## Target category
Agents That Do Real Work.

## Primary user
A data or AI platform engineer responsible for allowing AI agents to query governed enterprise data without exposing individual-level sensitive information.

## Flagship demo
An analytics agent asks for neighborhoods with highest churn risk and contributing factors. Its generated SQL joins customer pseudonyms, location activity, purchases, support-case categories, and churn scores. ToxicJoin identifies derived individual-level sensitivity, rewrites the query into a coarser aggregated form with a minimum group-size threshold, executes it safely, verifies the result, creates a safe view, and writes the decision plus lineage into DataHub.

## Secondary demo
An agent requests a list of identifiable customers with financial-hardship support cases and high churn. ToxicJoin returns BLOCK because the purpose itself requires sensitive individual-level output and cannot be made safe through aggregation without changing the requested outcome.

## Must-have capabilities
1. Parse supported SQL into an AST.
2. Resolve tables, aliases, projections, joins, filters, grouping, and CTEs.
3. Fetch schemas, column classifications, ownership, domains, and lineage from DataHub.
4. Build an evidence graph linking intent, SQL, assets, columns, classifications, joins, and derived risk.
5. Make deterministic ALLOW, REWRITE, or BLOCK decisions.
6. Fail closed when SQL or metadata cannot be resolved.
7. Rewrite a narrow supported class of risky analytical queries.
8. Execute original-safe or rewritten SQL against DuckDB.
9. Verify that rewritten outputs satisfy the configured safety conditions.
10. Produce a machine-readable execution receipt.
11. Write a decision document and derived-risk metadata back to DataHub.
12. Register safe-view lineage where a safe view is generated.
13. Offer a public replay and a live local DataHub mode.
14. Include a benchmark of safe, rewrite, block, and adversarial cases.

## Explicit non-goals
- Full IAM, RBAC, or ABAC platform.
- General text-to-SQL generation.
- Complete GDPR, HIPAA, or PCI compliance automation.
- Universal SQL dialect support.
- Formal privacy guarantees for arbitrary queries.
- Differential privacy engine.
- Multi-tenant SaaS administration.
- Production secrets management.
- Raw sensitive-row analysis by an LLM.
- Integrations with Slack, Jira, Teams, or ticketing systems.

## Supported SQL profile
SELECT queries using a bounded subset of joins, projections, filters, GROUP BY, HAVING, aggregate functions, CTEs, and nested SELECTs. Unsupported syntax returns BLOCKED_UNSUPPORTED_SQL.

## Core policy categories
- DIRECT_IDENTIFIER
- STABLE_PSEUDONYM
- QUASI_IDENTIFIER
- SENSITIVE_ATTRIBUTE
- PUBLIC_OR_LOW_RISK

## Core decision rules
- Direct identifier plus sensitive attribute at individual granularity: BLOCK.
- Stable pseudonym plus multiple quasi-identifiers plus sensitive attribute: BLOCK or REWRITE depending on requested purpose and aggregation feasibility.
- Sensitive grouped analytics with insufficient group size: REWRITE.
- Missing classification or unresolved source: BLOCKED_METADATA_GAP.
- No risky composition: ALLOW.

## Technical proof required
Python to DataHub MCP read, deterministic decision, optional safe SQL rewrite, real DuckDB execution, verification, DataHub write-back, and independent confirmation that the write-back exists.

## Timebox
Build window: July 22–August 8, 2026. Submission freeze target: August 8. Emergency-only changes: August 9–10. Final submission target: August 10 before 18:00 Asia/Amman.

## Success metrics
- Zero blocked benchmark queries executed.
- All supported benchmark cases receive the expected decision.
- All generated rewrites execute successfully in the flagship scenarios.
- No rewritten result violates the configured group-size threshold.
- Every decision contains DataHub-grounded evidence.
- Fresh-clone demo path is reproducible.
- Judge can understand and evaluate the product in under 90 seconds.
- Demo video stays under three minutes.

## Kill criteria
Pivot or reduce scope if any of the following occurs:
- No reliable live DataHub read/write proof by July 24.
- No end-to-end vertical slice by July 27.
- Rewriter remains unstable for the flagship scenario by July 30.
- A direct competitor publicly demonstrates the same compositional-risk detection, safe SQL rewriting, execution verification, benchmark, and DataHub write-back before our vertical slice is stable.
