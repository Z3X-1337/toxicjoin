# ToxicJoin Canonical Security Architecture

This document defines the **current canonical security architecture** of ToxicJoin and the boundary between code that is active in the product runtime and stronger vNext components that are implemented but not yet wired into the canonical execution path.

It is deliberately a truth document, not a roadmap claim. A component is called **canonical** here only when the current product path actually invokes it.

## 1. Architectural rule

ToxicJoin separates planning from authority.

The AI/Governed Agent may propose analytical work, but it does not own the final policy decision, disclosure-state authority, execution authorization, database connection, or result-release decision.

The canonical execution boundary is fail-closed and read-only.

## 2. Current canonical product path

The current `POST /api/execute-safe` path is:

```text
caller
  -> API authentication + EXECUTE scope
  -> authenticated request identity binding
  -> ToxicJoinPipeline construction
       -> require an unbound executor
       -> when authority prerequisites are present, create one canonical ExecutionAuthorizer
       -> bind that authorizer to the executor exactly once
       -> if required disclosure state is absent, leave the executor unbound for audited fail-closed handling
       -> reject externally pre-bound product executors
  -> ToxicJoinPipeline request handling
       -> SQL analysis
       -> governed context resolution
       -> deterministic policy evaluation
       -> BLOCK | ALLOW | constrained REWRITE
       -> rewritten SQL re-resolution + re-evaluation when applicable
  -> toxicjoin.verify.verify_and_execute
       -> proof-bound wrapper
            -> no privacy proof is supplied by the current pipeline
            -> delegates to governance verifier
       -> governance snapshot capture + pinning
       -> core verifier
            -> SQL re-analysis
            -> governed-context re-resolution
            -> deterministic policy re-evaluation
            -> subject-threshold / semantic-output checks
            -> cumulative-disclosure reservation when required
            -> validate the already-bound executor authority
            -> issue single-use execution capability
            -> verify + consume capability
  -> hardened read-only DuckDB connection
  -> bounded execution result held in quarantine
  -> post-execution verification
       -> release rows only if every check passes
       -> otherwise discard rows and fail closed
  -> disclosure state RELEASED or ABORTED
  -> sanitized decision receipt
```

### Source anchors

The API route authenticates `EXECUTE` scope before calling the pipeline. The pipeline owns product authority bootstrap: a runnable execution pipeline accepts only an unbound executor, creates the current canonical `ExecutionAuthorizer` from the security-owned resolver/policy/disclosure configuration, and binds it once before any request can execute. If stateful privacy is required but the disclosure ledger is absent, the pipeline deliberately leaves the executor unbound so the verifier can fail closed with an auditable request receipt rather than constructing a weaker authority. The pipeline then performs deterministic analysis/policy handling and calls the exported verifier for execution. The exported verifier currently points to the proof-aware wrapper, but the pipeline does **not** supply a `privacy_proof`, so the wrapper delegates to the governance verifier.

The governance verifier pins one governance binding for the request and injects that binding into execution-authorization issuance. The core verifier performs pre-execution checks, reserves cumulative-disclosure state when required, validates that the executor is already bound to the same resolver/policy/disclosure authority, issues a capability, and only then calls the executor. Verification no longer creates an execution authority lazily.

## 3. Authority ownership

| Security decision / capability | Current canonical owner | Agent-owned? |
|---|---|---:|
| API authentication and scope | API authentication boundary | No |
| Request identity | authenticated request context | No |
| SQL parsing / semantic plan | deterministic SQL analyzer | No |
| Governed context | configured context resolver; verified DataHub snapshot resolver in LIVE mode | No |
| Deterministic privacy decision | `PolicyEngine` | No |
| Rewrite safety | deterministic rewrite + re-analysis + policy re-evaluation | No |
| Cumulative disclosure state | `DisclosureLedger` when stateful privacy is required | No |
| Execution capability | pipeline-owned `ExecutionAuthorizer` in the current canonical runtime | No |
| Database execution | `DuckDBExecutor` | No |
| Result release | verifier post-execution checks | No |
| Receipt persistence | `ReceiptStore` | No |

## 4. Canonical execution authorization today

When a runnable execution-capable `ToxicJoinPipeline` is constructed with its required security state available, it requires an unbound `DuckDBExecutor`, creates one `ExecutionAuthorizer` from the pipeline-owned context resolver, policy engine, disclosure ledger, and stateful-privacy requirement, and binds that authorizer through `DuckDBExecutor.bind_authorizer()`.

`DuckDBExecutor.bind_authority()` retains its historical name for verifier compatibility, but it is now validation-only: it rejects an unbound executor and rejects any resolver, policy, disclosure-ledger, or disclosure-requirement mismatch. It cannot create an authorizer during request verification.

That authorizer independently re-analyzes the exact SQL, re-resolves governed context, re-evaluates deterministic policy, validates request identity and disclosure commitment, binds the resulting capability to the exact execution state, and issues an HMAC-authenticated short-lived authorization.

At consumption, the authorization is revalidated against:

- exact SQL;
- parsed query plan;
- governed context and governance binding;
- policy configuration and freshly recomputed policy decision;
- task purpose;
- subject key;
- authenticated request identity;
- optional rewrite parent;
- required disclosure commitment;
- dialect;
- expiry, integrity, and single-use state.

Only a successfully consumed capability can reach the DuckDB connection.

## 5. Database boundary

The supported execution contract is DuckDB-only.

The canonical executor opens the database read-only and disables external access, community extensions, automatic extension loading, and automatic extension installation before locking configuration. Query execution is time-bounded and result/cell payloads are bounded before crossing the execution boundary.

Database success is **not** equivalent to result release. Execution rows remain quarantined until post-execution verification passes.

## 6. Stateful privacy boundary

When stateful privacy is required, the verifier evaluates cumulative disclosure and obtains a disclosure commitment before authorization/execution.

The governance wrapper treats this commitment as a release reservation:

- a fully passed verification transitions the reservation to `RELEASED`;
- a failed or exceptional path transitions it to `ABORTED`;
- execution-authorization issuance and consumption independently validate the commitment when it is required.

If stateful privacy is required but its disclosure ledger is unavailable during pipeline construction, ToxicJoin does not create a reduced-safety execution authorizer. The executor remains unbound; request verification returns `DISCLOSURE_STATE_UNAVAILABLE` before capability issuance or DuckDB access, and the pipeline still persists the fail-closed decision receipt.

This prevents a failed request that releases no rows from poisoning future disclosure history and preserves an audit record for missing-state failures.

## 7. vNext proof-bound components: implemented, not canonical yet

The repository contains a stronger proof-bound authorization stack:

- `PreExecutionPrivacyProof`;
- `ProofBoundExecutionAuthorization`;
- `ProofBoundExecutionAuthorizer`;
- strict proof/provenance/execution key separation;
- `DataHubAgentPreExecutionProofAuthority`;
- authenticated Agent PPMC provenance binding.

These components are **implemented and tested**, but they are not yet the canonical product execution path.

The current product pipeline does not build or pass a `PreExecutionPrivacyProof` into `verify_and_execute`, and it rejects an executor that was externally pre-bound before pipeline construction. Therefore a direct/library caller may still explicitly construct a pre-bound proof-bound executor for staged security tests, but that path cannot be injected into the current `ToxicJoinPipeline` product bootstrap. The current product authority remains the pipeline-created legacy `ExecutionAuthorizer` until a later explicit migration changes that bootstrap.

This distinction is mandatory for release claims:

> The repository has proof-bound execution primitives and security tests; the current HTTP/product execution path has not yet completed the strict proof-bound authorization migration.

## 8. Governed Agent boundary

The Governed Agent is planning-only and non-authoritative.

Its DataHub discovery, proposal authority, PPMC authority, governance-trust binding, and pre-execution proof authority may produce security-owned evidence/capabilities, but none of those components independently execute SQL or mutate disclosure/DataHub state.

`DataHubAgentPreExecutionProofAuthority` derives request identity from the bound authenticated context rather than caller input, rebinds proposal/PPMC/governance/policy evidence, authenticates Agent provenance under a separate authority key, and seals the pre-execution proof. This is a staged input to the future canonical proof-bound authorization path, not a current HTTP execution endpoint.

## 9. Key separation in strict proof mode

When strict proof-bound execution becomes canonical, three authority classes must remain cryptographically separated:

1. privacy-proof integrity key;
2. Agent-provenance integrity key;
3. execution-authorization HMAC key.

The strict authorizer rejects equality between those keys. Possession of one authority key must not allow forgery of another artifact class.

## 10. Security invariants that must survive migration

Any authorization migration must preserve all of the following:

1. No SQL execution before deterministic policy approval and verifier prechecks.
2. BLOCK, uncertainty, stale governance, drift, missing state, malformed proof, or authorization failure never reaches DuckDB execution.
3. The Agent cannot mint its own execution authority.
4. Request identity is security-owned and bound to authorization/proof state.
5. Governance state is pinned and revalidated across verification and authorization.
6. Rewrites are re-parsed, re-resolved, and re-evaluated before execution.
7. Cumulative-disclosure state fails closed when required.
8. Execution authorization is exact-state, short-lived, HMAC-authenticated, and single-use.
9. DuckDB remains read-only and externally isolated.
10. Database rows are quarantined until all post-execution checks pass.
11. Failed verification releases no `ExecutionResult` rows.
12. Proof, provenance, and execution keys remain separated in strict proof mode.
13. A proof-aware code path must never silently downgrade to legacy authorization when a proof was supplied or required.
14. Request verification cannot create or replace the product execution authority.
15. Missing required disclosure state cannot cause construction of a reduced-safety execution authority.

## 11. Explicit non-claims

The current architecture does **not** claim that:

- the HTTP API exposes a dedicated Agent proof/provenance endpoint;
- every product execution is currently proof-bound;
- the strict `ProofBoundExecutionAuthorizer` is the default executor authority;
- local process state is a distributed replay-prevention service;
- local SQLite disclosure state is horizontally composable across independent replicas;
- the in-process traffic limiter is a distributed rate limiter;
- the deterministic hosted replay is current-main live execution evidence.

Those boundaries must stay explicit until the corresponding implementation phase changes them and exact-head evidence proves the new behavior.

## 12. Deployment topology limitations

The current execution-authorization consumed-ID cache and default authorization keys are process-local. The default API traffic limiter is also process-local. The default disclosure ledger is local SQLite.

Those controls are valid for the supported single-process/single-state topology but must not be represented as horizontally coordinated controls. Shared transactional disclosure state, distributed rate limiting/replay state, and production key-management topology are separate later phases.

## 13. Authorization migration boundary

Phase 4 unified the legacy and proof-aware call contract. Phase 5 closes execution-time product authority creation: for runnable configurations with required state present, product authority is established once at pipeline construction and request verification can only validate that already-bound authority. Degraded configurations missing required disclosure state remain deliberately unbound and fail closed before execution while preserving the request receipt.

A later phase may make proof-bound execution canonical, but only through an explicit migration that:

- wires security-owned proof creation into the product path without giving proof authority to the Agent;
- changes the pipeline-owned bootstrap from legacy `ExecutionAuthorizer` to the strict proof-aware authorizer;
- preserves the single product authority-establishment path rather than reintroducing verifier-time or caller-prebinding alternatives;
- keeps fail-closed semantics when proof/provenance/state is absent or inconsistent;
- re-runs exact-head internal, HTTP/Docker black-box, container, supply-chain, and release-manifest evidence before any stronger product claim is made.

Until that migration lands and is proven, Sections 2–7 are the canonical runtime truth.
