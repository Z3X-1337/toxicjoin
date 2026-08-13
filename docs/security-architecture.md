# ToxicJoin Security Architecture Detail

This document is subordinate to the normative product architecture in [`architecture.md`](architecture.md). It describes current security implementation details, authority ownership, migration constraints, and explicit non-claims. It may not expand the product surface defined by the normative architecture.

## 1. Architectural rule

ToxicJoin separates planning from authority.

The AI or Governed Agent may propose analytical work, but it does not own the final policy decision, disclosure-state authority, execution authorization, database connection, result-release decision, or DataHub mutation authority.

The canonical execution boundary is fail-closed and read-only.

## 2. Current canonical product path

The current `POST /api/execute-safe` path is:

```text
caller
  -> API authentication + EXECUTE scope
  -> authenticated request identity binding
  -> ToxicJoinPipeline construction
       -> require an unbound executor
       -> when authority prerequisites are present, create one ExecutionAuthorizer
       -> bind that authorizer to the executor exactly once
       -> if required disclosure state is absent, remain unbound and fail closed
       -> reject externally pre-bound product executors
  -> request handling
       -> SQL analysis
       -> governed context resolution
       -> deterministic policy evaluation
       -> BLOCK | ALLOW | constrained REWRITE
       -> rewritten SQL re-resolution + re-evaluation when applicable
  -> verify_and_execute
       -> governance snapshot capture + pinning
       -> SQL re-analysis
       -> governed-context re-resolution
       -> deterministic policy re-evaluation
       -> subject-threshold and semantic-output checks
       -> cumulative-disclosure reservation when required
       -> validate the already-bound executor authority
       -> issue and consume a single-use execution capability
  -> hardened read-only DuckDB
  -> bounded execution result held in quarantine
  -> post-execution verification
       -> release rows only if every check passes
       -> otherwise discard rows and fail closed
  -> disclosure state RELEASED or ABORTED
  -> sanitized authenticated decision receipt
```

The exported verifier is proof-aware, but the current HTTP pipeline does not supply a strict vNext privacy proof. It therefore remains on the canonical governance-verification and pipeline-owned `ExecutionAuthorizer` path.

## 3. Authority ownership

| Security decision or capability | Current canonical owner | Agent-owned? |
|---|---|---:|
| API authentication and scope | API authentication boundary | No |
| Request identity | authenticated request context | No |
| SQL parsing and semantic plan | deterministic SQL analyzer | No |
| Governed context | configured resolver; verified DataHub snapshot resolver in LIVE mode | No |
| Deterministic privacy decision | `PolicyEngine` | No |
| Rewrite safety | deterministic rewrite, re-analysis, and policy re-evaluation | No |
| Cumulative disclosure state | `DisclosureLedger` when required | No |
| Execution capability | pipeline-owned `ExecutionAuthorizer` | No |
| Database execution | `DuckDBExecutor` | No |
| Result release | independent verifier | No |
| Receipt persistence | `ReceiptStore` | No |

## 4. Execution authorization

A runnable execution-capable `ToxicJoinPipeline` accepts only an unbound `DuckDBExecutor`. When required security state exists, the pipeline creates one `ExecutionAuthorizer` from its resolver, policy engine, disclosure ledger, and stateful-privacy requirement, then binds it once.

Verification may validate that authority but cannot create or replace it. A pre-bound executor with mismatched resolver, policy, disclosure state, or disclosure requirement is rejected.

The issued authorization is bound to:

- exact SQL and parsed query plan;
- governed context and governance binding;
- policy configuration and recomputed decision;
- task purpose and subject key;
- authenticated request identity;
- optional rewrite parent;
- required disclosure commitment;
- dialect;
- expiry, integrity, and single-use state.

Only a successfully consumed capability can reach DuckDB.

## 5. Database and result-release boundary

The supported canonical executor is DuckDB-only. It opens the database read-only and disables external access, community extensions, automatic extension loading, and automatic extension installation before locking configuration.

Execution time, result rows, columns, cell values, and response size are bounded. Database success is not equivalent to result release: rows remain quarantined until post-execution verification passes.

## 6. Stateful privacy boundary

When stateful privacy is required, the verifier evaluates cumulative disclosure and obtains a commitment before authorization and execution.

- passed verification transitions the reservation to `RELEASED`;
- failed or exceptional verification transitions it to `ABORTED`;
- authorization issuance and consumption independently validate the commitment.

If required disclosure state is unavailable, ToxicJoin does not construct a reduced-safety authorizer. The executor remains unbound, the request fails before DuckDB access, and an auditable fail-closed receipt is preserved.

The current public SQLite disclosure authority is explicitly single-node. Declared multi-replica use fails closed rather than claiming shared-authoritative state.

## 7. Live DataHub authority separation

The stable live path separates:

- SDK seeding authority;
- read-only MCP authority;
- isolated document-write MCP authority;
- fresh read-back through a new read-only MCP process.

The effective ToxicJoin writer surface is allowlisted to `save_document`. A broader raw upstream MCP inventory does not broaden the application-visible authority.

The retained tested MCP launcher profile is pinned to `mcp-server-datahub==0.6.0`. Retained live evidence is revision-bound and is not an exact-final-`main` live rerun.

## 8. vNext proof-bound components

The repository contains implemented and tested staged components including:

- `PreExecutionPrivacyProof`;
- `ProofBoundExecutionAuthorization`;
- `ProofBoundExecutionAuthorizer`;
- strict proof, provenance, and execution key separation;
- `DataHubAgentPreExecutionProofAuthority`;
- authenticated Agent PPMC provenance binding.

These components are not yet the canonical HTTP execution path. The current product pipeline does not build and pass the strict privacy proof or bootstrap the strict proof-bound authorizer.

The mandatory claim boundary is:

> The repository contains proof-bound execution primitives and tests; the current HTTP product path has not completed strict proof-bound authorization migration.

## 9. Governed Agent boundary

The Governed Agent is planning-only and non-authoritative. Discovery, proposal, PPMC, governance-trust, and proof authorities may produce security-owned evidence, but none independently execute SQL or mutate disclosure or DataHub state.

Request identity is derived from the authenticated context rather than caller-supplied proof fields.

## 10. Strict-mode key separation

When strict proof-bound execution becomes canonical, these authority classes must remain cryptographically separated:

1. privacy-proof integrity key;
2. Agent-provenance integrity key;
3. execution-authorization HMAC key.

Possession of one key must not permit forgery of another artifact class.

## 11. Security invariants

Any migration must preserve:

1. No execution before deterministic policy approval and verifier prechecks.
2. BLOCK, uncertainty, stale governance, drift, missing state, malformed proof, or authorization failure never reaches DuckDB.
3. The Agent cannot mint execution authority.
4. Request identity is security-owned and bound to proof and authorization state.
5. Governance is pinned and revalidated.
6. Rewrites are reparsed, regrounded, and reevaluated.
7. Required cumulative-disclosure state fails closed.
8. Authorization is exact-state, short-lived, authenticated, and single-use.
9. DuckDB remains read-only and externally isolated.
10. Rows remain quarantined until verification passes.
11. Failed verification releases no result rows.
12. Proof, provenance, and execution keys remain separated in strict mode.
13. A proof-aware path never silently downgrades when proof is supplied or required.
14. Request verification cannot create or replace product execution authority.
15. Missing required disclosure state cannot create a reduced-safety authority.

## 12. PostgreSQL staged boundary

Draft PR #118 contains an off-main PostgreSQL shared-authoritative disclosure implementation and dedicated evidence workflow.

It is staged work only. It is not present on current `main`, not selected by the canonical HTTP runtime, and not a production-supported backend. It does not establish distributed receipt storage, key custody, replay prevention, rate limiting, or cross-service transaction semantics.

## 13. Explicit non-claims

The current architecture does not claim that:

- the HTTP API exposes a dedicated Agent proof or provenance endpoint;
- every product execution is proof-bound;
- `ProofBoundExecutionAuthorizer` is the default authority;
- local process state is distributed replay prevention;
- local SQLite is horizontally shared disclosure state;
- the in-process traffic limiter is distributed;
- historical browser evidence is current-main live execution evidence;
- PostgreSQL disclosure state is available on current `main` or in production.

## 14. Deployment topology limitations

The authorization consumed-ID cache, default authorization keys, and default traffic limiter are process-local. The public disclosure ledger is local SQLite. Those controls are valid for the supported single-process and single-state topology but must not be represented as horizontally coordinated controls.

Shared transactional disclosure state, distributed rate limiting, distributed replay state, shared receipt storage, and production key-management topology require separate implementation and exact-head evidence.

## 15. Authorization migration boundary

A later phase may make proof-bound execution canonical only through an explicit migration that:

- wires security-owned proof creation into the product path without giving proof authority to the Agent;
- changes pipeline bootstrap from the legacy authorizer to the strict proof-aware authorizer;
- preserves a single product authority-establishment path;
- keeps fail-closed semantics when proof, provenance, governance, or state is absent or inconsistent;
- reruns exact-head internal, HTTP and Docker black-box, container, supply-chain, and release-manifest evidence.

Until that migration lands and is proven, Sections 2–7 describe current security runtime truth.
