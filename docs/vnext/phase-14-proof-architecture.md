# Phase 14 — Proof Architecture Verification

## Scope

Phase 14 audits the staged proof-producing and strict proof-bound execution chain after the PPMC resource profile was hardened in Phase 13.

The phase is deliberately narrow. It does not make proof-bound execution canonical in the current HTTP/product runtime, does not invent a physical DuckDB snapshot algorithm, and does not change the generic proof-bound authorizer used for staged migration/offline assurance.

The target invariant is:

> A strict Governed-Agent execution may consume a prospectively accepted proof only while the security-owned runtime warehouse snapshot still matches the exact warehouse snapshot commitment modeled by the Disclosure Twin and carried by that proof.

## Proven gap

`DisclosureState` commits `warehouse_snapshot_sha256`. `FutureActionGrammarContext` commits the base warehouse snapshot and can include explicit directed `SNAPSHOT_ADVANCE` transitions. `PreExecutionPrivacyProof` then carries the exact `warehouse_snapshot_sha256` from the accepted state.

Before this phase, the strict `ProofBoundExecutionAuthorizer` independently rebound the proof to current SQL, query plan, DataHub governance context, policy, request identity, subject, proof HMAC, and authenticated Agent PPMC provenance, but it had no security-owned source from which to obtain the current warehouse snapshot.

That left a proof-to-runtime TOCTOU boundary: a proof could be minted for warehouse snapshot A, the warehouse could move to unmodelled snapshot B without a corresponding DataHub-governance change, and the strict execution layer had no independent snapshot comparison to reject the stale prospective proof.

The red TDD head `0e05b937608ac3bb704bc5cadf4ddbb9f9200c56` required the strict execution constructor to expose a `warehouse_snapshot_provider`. Both Python 3.11 and Python 3.12 failed the new regression. Python 3.11 recorded:

- `1 failed, 830 passed`
- failure: `strict proof-bound execution has no security-owned warehouse snapshot source; proof/runtime snapshot TOCTOU cannot be revalidated`

This was a proof/runtime binding gap, not a break in the existing proof HMAC, Agent provenance, policy, or governance-context verification.

## Fix

### Security-owned runtime snapshot provider

The public strict Agent-aware `ProofBoundExecutionAuthorizer` now accepts a `warehouse_snapshot_provider` dependency.

The provider is not supplied by the planning Agent and is not a field inside the proof. It is a composition-root authority dependency that returns the current canonical warehouse snapshot commitment.

The generic proof-bound authorizer remains unchanged.

### Revalidation at both authorization boundaries

The strict authorizer performs warehouse-snapshot rebinding from `_verify_bound_privacy_proof()`. That verifier is invoked when an execution authorization is issued and again when the authorization is verified/consumed.

Consequently:

1. a proof whose warehouse commitment already differs from the runtime snapshot cannot mint an execution capability;
2. a snapshot change after capability issuance but before consumption invalidates execution;
3. a missing provider fails closed when a proof is actually used;
4. provider failure or malformed snapshot output fails closed;
5. exact matching commitments continue through the existing proof/provenance/current-governance verification chain.

Stable failures include:

- `AUTH_WAREHOUSE_SNAPSHOT_UNAVAILABLE`
- `AUTH_PRIVACY_PROOF_WAREHOUSE_SNAPSHOT_INVALID`
- `AUTH_PRIVACY_PROOF_WAREHOUSE_SNAPSHOT_MISMATCH`

### Compatibility boundary

The constructor may be instantiated without a provider so constructor-only tests and staged key-separation checks remain possible. This is not an execution opt-out: any strict proof use without a provider fails closed with `AUTH_WAREHOUSE_SNAPSHOT_UNAVAILABLE`.

Operational strict-execution fixtures explicitly provide the warehouse commitment from the same security-owned state used to build the proof.

## Regression coverage

Phase 14 covers:

- the strict constructor exposes the warehouse snapshot authority dependency;
- matching warehouse commitment permits the previously valid strict execution path;
- missing warehouse snapshot authority fails closed at proof use;
- warehouse drift between authorization issue and consume is rejected before successful consumption;
- existing Agent proof provenance remains required;
- existing SQL/query-plan/governance/policy/identity/subject bindings remain enforced;
- integration execution still rejects missing, tampered, and swapped proofs before DuckDB connection;
- legacy generic execution/proof primitives remain available for staged migration.

## Architectural boundary

Phase 14 establishes the **proof architecture contract**, not a universal physical-snapshot implementation.

A real product composition root must supply a canonical warehouse snapshot provider whose commitment represents the execution substrate being modeled. This phase intentionally does not hash a DuckDB database file as a shortcut: file bytes, WAL state, and logical database state are not interchangeable security semantics.

Until a canonical runtime wires an appropriate provider, this proof-bound path remains staged vNext architecture.

## Claim boundary

Phase 14 does **not** claim:

- that the current canonical HTTP `/api/execute-safe` path is proof-bound;
- that every supported warehouse already has a production snapshot provider;
- serializable database transactions or distributed consensus across warehouse and DataHub state;
- that DataHub metadata freshness alone proves warehouse-state freshness;
- unbounded prospective privacy safety;
- DataHub decision write-back or cross-agent inheritance.

The next roadmap phase is Phase 15 — Cryptographic Domain Separation. Phase 15 should audit artifact/key/domain separation on the now-closed proof architecture without broadening product claims or prematurely changing the canonical runtime.