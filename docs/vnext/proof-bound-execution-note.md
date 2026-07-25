# Proof-Bound Execution — Day-11 Completion Boundary

This slice completes Day-11 by carrying one exact `PreExecutionPrivacyProof` from the public verifier boundary through authorization issuance and capability consumption before the read-only DuckDB connection is opened.

## No parallel verifier

The provider-neutral core verifier remains unchanged.

The public `toxicjoin.verify.verify_and_execute` symbol now points to a small proof-aware wrapper over the existing governance-bound verifier. The existing governance wrapper still owns snapshot pinning, pending/released/aborted disclosure lifecycle, and injection of the exact `expected_governance_binding`.

When a proof is supplied, the public wrapper places one validated immutable copy around the existing `DuckDBExecutor`. The governance verifier then wraps that executor as usual. The proof-injecting layer adds the same proof to both:

- `issue_authorization`;
- `execute_authorized`.

It rejects any attempt by an inner/outer wrapper to substitute a different proof.

When no proof is supplied, legacy behavior is unchanged. A pre-bound `ProofBoundExecutionAuthorizer` still fails closed with `AUTH_PRIVACY_PROOF_REQUIRED` because no proof keyword reaches its issue method.

Supplying a proof with an execution object that is not a `DuckDBExecutor` fails closed rather than silently dropping the proof.

## DuckDB execution boundary

`DuckDBExecutor.issue_authorization` and `execute_authorized` now accept an optional typed `PreExecutionPrivacyProof`.

For backward compatibility the proof keyword is forwarded only when non-null. Existing legacy authorizers therefore receive exactly the same call shape as before. Strict proof-bound authorizers receive the proof on both issue and consume.

The ordering remains security-critical:

1. authorization/proof verification;
2. wildcard/output safety guard;
3. open hardened read-only DuckDB connection;
4. execute exact authorized SQL.

Therefore a missing, malformed, expired, runtime-mismatched, or authorization-swapped proof fails before `_connect()` and before any SQL reaches DuckDB.

## Integration evidence model

The new end-to-end tests do not synthesize a fake safe proof. They build:

- DataHub snapshot and governed resolver;
- canonical DataHub evidence bundle;
- independent derivation validation;
- unchanged PolicyEngine decision;
- semantic release and subject scope;
- Disclosure Digital Twin;
- Future Action Grammar;
- real `PolicyEngineLocalOracle`;
- trusted governance binding;
- bounded PPMC `NO_COUNTEREXAMPLE_WITHIN_BOUND` result;
- real `PreExecutionPrivacyProof`;
- `ProofBoundExecutionAuthorizer` with distinct proof/auth HMAC keys;
- hardened DuckDB file and executor.

A spy executor counts hardened connection attempts.

The tests require:

- matching proof: verification passes, rows are released, exactly one DuckDB connection is opened;
- missing proof: verification fails at capability issuance, no execution attempt, zero DuckDB connections;
- tampered proof: verification fails at capability issuance, zero DuckDB connections;
- a second independently HMAC-valid proof swapped after issue: capability consumption fails with `AUTH_PRIVACY_PROOF_BINDING_MISMATCH`, zero DuckDB connections;
- proof mode with a non-DuckDB execution boundary: fail closed instead of silently delegating.

## Security claim after this slice

When the public verifier is called with a `DuckDBExecutor` pre-bound to `ProofBoundExecutionAuthorizer`, execution can reach DuckDB only if the exact authenticated, unexpired privacy proof used at capability issuance is presented again at capability consumption and matches the independently recomputed governed runtime state.

This claim is deliberately conditional on selecting the strict proof-bound authorizer. Legacy `ExecutionAuthorizer` remains available for compatibility until the later prospective Pipeline/Agent integration selects strict mode by construction.

This slice does not claim universal privacy, public verifiability, arbitrary-SQL completeness, or that every legacy ToxicJoin execution path is proof-required.
