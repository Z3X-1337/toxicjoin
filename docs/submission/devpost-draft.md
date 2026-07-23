# ToxicJoin — Devpost Submission Draft

> **Review status:** Draft only. Nothing in this file has been submitted to Devpost.

## Project identity

**Name:** ToxicJoin

**Tagline:** A compositional privacy firewall that blocks or safely rewrites risky SQL before AI data agents execute it.

**Challenge category:** Agents That Do Real Work

**Country:** Jordan

**Built with:** Python, FastAPI, SQLGlot, DuckDB, DataHub OSS, DataHub Python SDK, DataHub MCP Server, MCP Python SDK, React, TypeScript, Vite, Docker, GitHub Actions

## Links

- **Public repository:** https://github.com/Z3X-1337/toxicjoin
- **Hosted judge replay:** [PENDING_VERIFIED_PAGES_URL]
- **Examples:** https://github.com/Z3X-1337/toxicjoin/tree/main/examples
- **Demo video:** [PENDING_PUBLIC_YOUTUBE_OR_VIMEO_URL]
- **Live DataHub evidence:** https://github.com/Z3X-1337/toxicjoin/blob/main/docs/evidence/datahub-live.md

## Devpost field answers

### Which challenge category are you submitting to?

Agents That Do Real Work

### Public code repository

https://github.com/Z3X-1337/toxicjoin

### Project URL for easy testing

[PENDING_VERIFIED_PAGES_URL]

The hosted site is a clearly labeled deterministic replay for immediate judge access. The repository also provides a single hardened Docker service that runs the real FastAPI, policy, DuckDB execution, verification, and receipt path.

### Sample outputs

https://github.com/Z3X-1337/toxicjoin/tree/main/examples

### Which DataHub technologies did you use?

- DataHub OSS / Core Platform
- DataHub MCP Server

### DataHub contribution

No upstream DataHub contribution is claimed in the current submission draft. ToxicJoin contributes an independent open-source integration and compatibility evidence, but this field should remain explicit rather than presenting project code as an upstream contribution.

### Country of residence

Jordan

### Was the project newly created during the submission period?

Yes, newly created during the Submission Period.

### Pre-existing code disclosure

No non-standard pre-existing product code was incorporated. ToxicJoin was created during the submission period. It uses standard open-source frameworks, libraries, official DataHub components, and AI coding assistance. No Rayluno code, assets, infrastructure, branding, or submission material was reused.

### Feedback Prize

Yes, consider me for the Feedback Prize.

### Which parts of DataHub felt polished or useful?

The strongest part of the build was the combination of DataHub's metadata graph and agent-facing interfaces. The Python SDK made it possible to create deterministic synthetic datasets, governed schema fields, tags, glossary terms, and column-level lineage in a repeatable seed step. The MCP Server then exposed the same governed context to an agent through discoverable tools instead of requiring custom GraphQL for every read. The read → act → write pattern was especially useful: ToxicJoin could resolve assets and schema classifications, inspect lineage, write a Decision document, close the MCP process, and verify the Decision from a fresh session. That made DataHub function as both governed context and durable agent memory.

### Where did you get stuck or lose time?

The largest integration cost was version and transport compatibility across the DataHub MCP package, FastMCP structured outputs, and the MCP Python SDK. The official `get_entities` tool returns a list for batch requests, while MCP structured content must be an object, so FastMCP exposes that result under a standard `result` envelope. The first ToxicJoin adapter expected the bare list and failed closed. The live integration workflow was valuable because it exposed this difference immediately; the adapter was then updated to accept only the exact one-key FastMCP envelope and reject ambiguous wrappers. A concise compatibility section in the MCP documentation covering structured-output envelopes and recommended pinned launch commands would save builders significant time.

### What would you build or fix with unlimited DataHub engineering time?

I would build a first-class policy decision and enforcement evidence model for agent-generated queries. It would connect a proposed query, the exact schema fields and lineage paths used for context, the policy decision, any safe rewrite, verification results, and the final execution receipt. This matters because organizations increasingly allow agents to generate and run analytical SQL, while traditional dataset-level authorization cannot always detect sensitivity that appears only after datasets are combined. A standard model would let security, governance, and data-platform teams audit agent decisions without storing raw query results.

### Bugs or unexpected behavior

During live testing, two concrete compatibility issues were found:

1. An initially attempted npm package name for the MCP Server was not valid. The reliable launch path was the verified Python package, pinned and executed through `uvx`.
2. Batch `get_entities` output arrived through FastMCP's standard `{"result": ...}` structured-content envelope rather than as a bare list. ToxicJoin originally rejected it. The adapter now unwraps only that exact standard envelope and continues to fail closed for any additional or ambiguous keys.

The repository retains regression tests and a live DataHub workflow so these behaviors remain reproducible.

## Full project description

## Inspiration

AI data agents can generate useful SQL quickly, but they can also create a privacy problem that traditional controls miss: two datasets may be acceptable independently while their combination reconstructs a sensitive individual profile. A stable pseudonym joined with location, demographic signals, support history, financial behavior, or model outputs can create risk that does not exist in any single source table.

ToxicJoin was built around one question:

> Can an agent be stopped or safely constrained before a risky composition reaches the warehouse?

## What it does

ToxicJoin is a pre-execution compositional privacy firewall for agent-generated SQL. It receives a task purpose, SQL, and the expected subject key, then returns one deterministic outcome:

- **ALLOW** — the supported query has no prohibited composition and may execute through the hardened read-only path.
- **REWRITE** — the analytical purpose is valid, but the query lacks a trusted privacy boundary. ToxicJoin creates a constrained safe query, reparses it, reevaluates it, executes only after a final ALLOW, and verifies the complete result.
- **BLOCK** — the proposed output creates an unsafe individual-level composition or cannot be proven safe. The database is never called.

The policy engine owns every enforcement decision. An LLM is not required and has no authority to override the deterministic policy.

## How DataHub is used

DataHub is foundational rather than decorative.

ToxicJoin uses the official DataHub Python SDK to seed five synthetic datasets, 19 governed fields, controlled tags, glossary terms, ownership, and four column-lineage relationships. Through the official DataHub MCP Server, ToxicJoin discovers and validates the live tool contracts, reads configured entities, resolves governed schema fields, inspects upstream lineage, and writes a DataHub **Decision** document.

The write is verified independently: ToxicJoin closes the MCP process that performed the write, opens a fresh MCP process, reads the Decision back, and verifies a unique marker. This proves that the result was persisted in DataHub rather than retained only in application memory.

A real DataHub OSS gate passed in GitHub Actions. The official SDK created five datasets, 19 governed fields, nine tags, seven glossary terms, and four column-lineage writes. The official MCP Server then read the five entities and their schemas, returned three upstream relationships for the flagship churn-score field, wrote a DataHub Decision, closed the writing process, opened a fresh MCP process, and found the unique marker inside the persisted document through `grep_documents`. Sanitized JSON evidence with reproducible content hashes is committed under `docs/evidence/`, and the retained proof contains no token value, password, local endpoint, raw warehouse row, or local filesystem path.

## Flagship scenario

An analytics agent asks for regional churn analysis. The query joins customer regions with a sensitive churn score and groups the result, but it does not enforce a minimum number of distinct customers per group.

ToxicJoin:

1. parses the SQL with SQLGlot;
2. resolves physical datasets, aliases, columns, joins, and group keys;
3. grounds those columns in DataHub-governed context;
4. returns `REWRITE` with `SMALL_GROUP_RISK`;
5. adds `HAVING COUNT(DISTINCT c.customer_id) >= 20`;
6. reparses and reevaluates the rewritten SQL;
7. executes only after the final decision becomes `ALLOW`;
8. verifies every returned group using the complete DuckDB result set;
9. confirms all three groups contain 40 distinct subjects;
10. writes a sanitized immutable receipt that contains hashes and evidence, but never raw result rows.

A second scenario joins a stable customer pseudonym, age band, precise area, and sensitive support category. ToxicJoin returns `BLOCK`; verification and execution remain absent, proving the unsafe query never reaches DuckDB.

## Technical execution

The product is built as a narrow, auditable safety system rather than a generic SQL chatbot:

- SQLGlot AST analysis and physical source resolution;
- deterministic versioned YAML policy with `BLOCK > REWRITE > ALLOW` precedence;
- constrained subject-threshold rewriting;
- mandatory reparse and policy reevaluation after every rewrite;
- read-only DuckDB with external access and extension auto-loading disabled;
- independent verification of final policy, raw output fields, complete group inspection, and observed subject counts;
- immutable receipts with exclusive creation, SQL literal redaction, content hashing, and integrity checks on every read;
- official DataHub SDK and MCP integrations with runtime contract discovery, hard timeouts, bounded pagination, minimal child-process environment, and fail-closed behavior;
- React judge interface and a single hardened Docker deployment;
- non-root container, read-only root filesystem, dropped Linux capabilities, `no-new-privileges`, dedicated data volume, and end-to-end container smoke tests.

## Measured evidence

GitHub Actions runs a balanced 30-query regression corpus through the real ToxicJoin pipeline:

- 10 expected ALLOW cases;
- 10 expected REWRITE cases;
- 10 expected BLOCK cases;
- 30/30 correct initial decisions;
- 30/30 correct effective outcomes;
- 30/30 expected reason codes;
- zero false allows;
- zero unsafe effective allows;
- six rewrites remediated and executed;
- four unsupported rewrite paths failed closed;
- 16 verified executions.

These numbers describe the declared deterministic corpus and supported SQL profile. They are not presented as universal privacy-detection accuracy.

## Challenges

The hardest problem was preserving a trustworthy safety boundary while integrating systems with different data contracts. ToxicJoin does not silently coerce unknown metadata or MCP payloads. Missing fields, unknown classifications, ambiguous aliases, incomplete pagination, unsupported SQL, and incompatible tool contracts fail closed.

The live DataHub workflow also revealed a real FastMCP compatibility boundary: list output is represented by an object envelope in MCP structured content. The final adapter accepts only the exact documented envelope and rejects wrappers with extra keys. This became a regression test rather than an undocumented workaround.

## Accomplishments

- A complete pre-execution BLOCK / REWRITE / ALLOW enforcement loop.
- A real SQL rewrite that is reparsed, reevaluated, executed, and independently verified.
- DataHub used for governed context, column lineage, and durable Decision write-back.
- Immutable receipts that prove what happened without persisting result rows.
- A measured, reproducible benchmark with zero-false-allow gates.
- A judge-facing interface, public replay, and hardened single-container executable path.
- Strict separation from every previous project and submission asset.

## What we learned

Compositional privacy risk needs a different enforcement unit from dataset-level permissions: the output shape and join path matter. We also learned that agent integrations need explicit compatibility tests around tool schemas and structured outputs. Discovering a tool is not enough; the client must validate inputs, normalize only documented payloads, and prove writes through independent read-back.

## What's next

The current scope intentionally supports a narrow, auditable rewrite: strengthening a minimum distinct-subject threshold on an already-grouped query. Future work could add governed location coarsening, approved identifier removal, organization-specific policy packs, warehouse adapters beyond DuckDB, and a first-class DataHub Skill for compositional-risk analysis. Those extensions should preserve the same rule: unsupported or ambiguous transformations fail closed.

## Submission safety review

Before any Devpost submission, replace every `[PENDING_*]` marker, verify every public link in a clean browser, confirm the final video is public and under three minutes, review the thumbnail, and obtain the project owner's explicit approval.
