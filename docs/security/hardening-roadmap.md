# ToxicJoin Security Hardening and Continuous Assurance Roadmap

Status: **mandatory release work before final hackathon submission**.

This roadmap is based on white-box source review, dynamic tests against the deterministic synthetic fixture, the retained external blind research results, and temporary dependency/SAST audits performed on 2026-07-24. It deliberately separates confirmed findings from unproven hypotheses.

## Security objective

ToxicJoin must not rely on a single-request policy decision, caller discipline, or presentation-layer assumptions to protect analytical execution. The release target is a layered enforcement boundary with explicit identity, bounded resource use, stateful disclosure control, exact decision-to-execution binding, governed semantic output verification, and reproducible security evidence.

No feature is complete if it introduces a new execution path, output path, identity boundary, SQL construct, DataHub mutation, dependency, or persistent state without a corresponding security test.

## Confirmed findings and required remediation

| ID | Severity | Finding | Required remediation |
|---|---|---|---|
| TJ-SEC-001 | High; Critical if connected to protected data and network-exposed | Protected API operations currently have no authentication/authorization boundary | Introduce explicit fixture vs secure/live modes. Secure/live mode must require authenticated principals with endpoint scopes; bind receipts and execution history to principal/agent identity. Keep public Replay separate from live execution. |
| TJ-SEC-002 | High when network-exposed | No rate, concurrency, or request-cost controls | Add per-principal limits, IP fallback limits, concurrent-execution caps, and cost-aware SQL budgets. Rate limiting is defense-in-depth and must not replace privacy-state controls. |
| TJ-SEC-003 | Critical | Cross-query differencing is possible because authorization is request-local and no disclosure/session state exists | Add an agent/principal-scoped disclosure ledger and cross-query composition policy. Evaluate cumulative disclosures before authorization and retain privacy state atomically with the decision. |
| TJ-SEC-004 | Critical | Policy v0.1.0 can allow individual pseudonym + sensitive output when the configured quasi-identifier threshold is not reached; externally reproduced by frozen E18/E20/E24 research cases | Replace the threshold-only individual composition rule with Policy v0.2.0 derived from semantic exposure, with frozen E18/E20/E24 regressions and external blind re-evaluation. |
| TJ-SEC-005 | High correctness / utility | Source-column sensitivity and result-value exposure are conflated for aggregate expressions | Introduce a Semantic Exposure Plan separating raw projected values, group keys, aggregate operands, aggregate outputs, filter-only references, join-only references, and nested scopes. Policy and verifier must consume this model. |
| TJ-SEC-006 | High latent boundary defect | `DuckDBExecutor.execute_allowed()` accepts a detached `PolicyDecision(ALLOW)` that is not bound to the SQL/context/policy identity | Replace the raw decision argument with an execution authorization bound to exact SQL, query plan, subject key, governance snapshot, policy configuration/version, task/principal, expiry, and rewrite parent. The executor must independently verify the authorization before opening the database. |
| TJ-SEC-007 | High | The verifier's forbidden-output check is name-based and only catches bare projected columns; transformed/wrapped forbidden fields can pass | Replace the hard-coded syntactic denylist with lineage-aware semantic output verification based on governed categories and the Semantic Exposure Plan. Add wrapper/cast/function/property-based regressions. |
| TJ-SEC-008 | Medium | The internal verifier retains execution rows when a post-execution check fails; the HTTP pipeline currently prevents release through receipt invariants but returns a persistence `503` | Separate internal execution evidence from releasable output. On any failed postcheck, destroy/non-release row payloads, persist a valid BLOCK receipt, and return a stable fail-closed response rather than a persistence failure. |
| TJ-SEC-009 | Medium | Request dialect is caller-controlled while the configured executor is DuckDB | For the current product profile, restrict the API to `duckdb`. Future dialect support requires an executor-specific capability contract and differential parser/executor tests. |
| TJ-SEC-010 | Medium-High availability | SQL length is bounded only after request parsing; there is no request-body limit or explicit AST/depth/join/CTE/UNION complexity budget before expensive analysis | Add ASGI/proxy body limits, AST node/depth/source/join/CTE/set-operation budgets, parser time budgets, and bounded concurrent analysis. Fail closed with stable error codes. |
| TJ-SEC-011 | Low hardening | Internal exception type, detailed readiness fields, and unused external CSP origins are exposed | Map internal exceptions to stable public error codes, split minimal liveness from internal readiness, tighten CSP to used origins, and add TrustedHost/TLS-boundary hardening for secure deployment. |
| TJ-SEC-012 | High live-integration correctness | Stable `main` DataHub field normalization does not include user-edited `editedTags` / `editedGlossaryTerms`; externally reproduced as all fields becoming `UNCLASSIFIED` | Port the research fix that merges system + edited governance metadata, rejects conflicts, and prove it against the same external DataHub OSS/MCP workload before merge. |
| TJ-SEC-013 | Medium | Long-lived live-context snapshots have no explicit freshness/expiry binding to execution | Bind authorization to a context fingerprint/version and expiry; refresh governance immediately before authorization or require a freshness SLA. Reject context drift between authorization and execution. |
| TJ-SEC-014 | Medium audit/integrity | Receipt content hash is unkeyed and receipt identity/ownership is not principal-bound | Add authenticated receipt access, >=128-bit opaque IDs, policy/context/build fingerprints, and keyed/asymmetric receipt authenticity (or equivalent trusted signing service) for secure/live mode. |
| TJ-SEC-015 | Medium supply-chain / CI | Dependency resolution is not fully locked; GitHub Actions use mutable major tags; Docker bases use tags; temporary audit found vulnerable pytest 8.4.2 in dev/CI | Move pytest to a patched supported release, commit deterministic Python/frontend locks, use `npm ci`, pin Actions to full commit SHAs, pin container bases by digest, enable automated dependency review/auditing and SBOM generation. |
| TJ-SEC-016 | Medium least privilege | DataHub MCP process is mutation-capable for paths that only need reads | Split read-only context acquisition from mutation/write-back processes and credentials; grant mutation capability only for the write-back step. |
| TJ-SEC-017 | High if misconfigured | Fixture governance can be combined with an overridden database path, creating a risk of applying demo classifications to non-demo data | Make runtime mode explicit. Fixture mode must only accept package-generated fixture/database fingerprints. Live/secure mode must require a live governed resolver and refuse fixture governance. |
| TJ-SEC-018 | Medium availability | Row count is bounded but individual cell/response byte size is not | Enforce maximum serialized result bytes, per-cell limits where practical, and response-size accounting before release. |

## Findings reviewed but not currently reproduced as exploits

- A crafted negated group-threshold hypothesis tested on the fixture failed closed before execution. Do not claim it as a confirmed bypass without a new reproducible case.
- Grouped queries do bypass the non-grouped quasi-identifier branch by design, but this alone is not classified as a separate exploit; grouped-query weaknesses are covered through cumulative disclosure, semantic output modeling, threshold verification, and external blind testing.
- Current resolved Starlette in the temporary audit was newer than known affected ranges for the reviewed Host-header and Range-header advisories. This does not replace permanent dependency locking and auditing.

## Remediation sequence

### P0 — release-blocking correctness and execution authority

1. Port and live-verify DataHub edited-field governance support.
2. Implement Policy v0.2.0 regressions for frozen E18/E20/E24.
3. Implement Semantic Exposure Plan and governance-driven output verification; close transformed-field bypasses.
4. Replace detached `PolicyDecision` execution with exact execution authorization; promote only the minimum proven pieces of the research Trust Kernel.
5. Make failed post-verification non-releasable and receipt-safe; no `503` persistence contradiction.
6. Restrict the current API/executor contract to DuckDB.
7. Add explicit runtime mode separation so fixture governance can never authorize an arbitrary external database.

### P1 — identity and resource-abuse boundary

1. Introduce principal, agent, and session identity models.
2. Require authentication/scopes in secure/live mode for analyze, execute, receipt, and administrative operations.
3. Bind receipts and disclosure history to authenticated ownership/tenant context.
4. Add rate/concurrency/cost controls and request-body limits.
5. Add SQL AST/depth/join/CTE/set-operation budgets and analysis time limits.
6. Bound serialized response size and cell size.
7. Split public liveness from internal readiness; disable or protect docs/demo/benchmark endpoints in secure/live mode.

### P2 — stateful privacy / cumulative disclosure

1. Add an append-only disclosure ledger keyed by principal + agent + governed subject domain.
2. Represent released semantic information, not only prior SQL strings.
3. Detect differencing/composition across sequential queries before execution authorization.
4. Define atomic update semantics so two concurrent requests cannot race around the disclosure ledger.
5. Add sequence-based adversarial tests, including allow/allow pairs that become unsafe only in combination.
6. Evaluate whether a formal privacy budget or a narrower controlled-query model is justified; do not claim differential privacy unless it is actually implemented and proven.

### P3 — DataHub trust and freshness

1. Split MCP read and mutation credentials/processes.
2. Bind each authorization/receipt to DataHub context fingerprint and freshness metadata.
3. Revalidate context before execution and reject drift.
4. Extend lineage-aware propagation tests so derived outputs cannot be declared low-risk solely by syntactic output naming.
5. Keep fresh-process write-back verification as a mandatory live gate.

### P4 — software supply-chain and auditability

1. Upgrade pytest to a patched version and update compatibility tests.
2. Add reproducible Python and Node dependency locks and `npm ci`.
3. Add permanent `pip-audit`/OSV-equivalent and `npm audit` or dependency-review gates.
4. Add CodeQL plus focused SAST; maintain a triaged Bandit/Semgrep ruleset rather than treating scanner output as truth without review.
5. Pin GitHub Actions by full-length commit SHA and container bases by digest.
6. Generate an SBOM for the release candidate and retain it with build provenance/artifact hashes.
7. Add automated dependency update PRs and a documented SLA for critical/high advisories.

### P5 — independent release validation

1. Run all existing unit/integration tests on Python 3.11 and 3.12.
2. Preserve the 30-case benchmark and 144-case adversarial suite as regression gates.
3. Re-run the frozen 24-task external blind workload without changing labels/tasks/model configuration to hide failures.
4. Require zero unsafe high-risk effective allows on the declared external validation before promotion.
5. Re-run real DataHub OSS + official MCP read/write/fresh-process-read-back.
6. Run authentication/authorization abuse tests and cross-query sequence tests.
7. Run dependency/SAST/container scans on the exact release candidate.
8. Only then freeze `main`, synchronize judge evidence, produce the final video, and proceed to final submission review.

## Permanent Definition of Done for every future feature

A pull request touching `api/`, `sql/`, `policy/`, `rewrite/`, `verify/`, `execute/`, `context/`, DataHub integrations, receipts, persistence, dependencies, or deployment must answer the following threat-model delta questions:

1. Does this add or modify an endpoint or unauthenticated path?
2. Does this add a new principal, tenant, agent, session, or authorization scope?
3. Can it release a new value, aggregate, metadata field, receipt field, or error detail?
4. Does it accept a new SQL construct, dialect, rewrite, or database executor?
5. Does it add a new DataHub tool, mutation, credential, or trust assumption?
6. Does it change persistent state, concurrency, or cross-request behavior?
7. Does it add or update a dependency, Action, container image, or external service?
8. Can it alter the exact bytes executed after policy authorization?

Any `yes` requires a corresponding negative security test before merge.

Mandatory merge gates for security-sensitive changes:

- normal unit/integration tests;
- zero new unsafe executions in declared security regressions;
- 30-case benchmark;
- 144-case adversarial mutation suite;
- governance-dependency gate;
- cross-query disclosure sequence tests once P2 lands;
- exact authorization-binding tests once P0 lands;
- external frozen blind evaluation for policy/parser/verifier changes;
- dependency/SAST checks for dependency or build changes;
- production container hardening test;
- live DataHub gate for DataHub-context/write-back changes.

A failing security experiment is retained as evidence and root-caused. Tests, labels, or expected outcomes must not be changed retroactively merely to make a gate green.
