# Proof-Bound Execution Authorization — Day-11 Core

This slice binds the exact `privacy_proof_sha256` into ToxicJoin's existing short-lived, single-use execution capability without changing the legacy authorizer or the execution/verifier orchestration yet.

## Staged compatibility model

`ExecutionAuthorizer` remains unchanged for regression compatibility and staged migration.

`ProofBoundExecutionAuthorizer` is the strict prospective mode. Selecting this authorizer is itself the security configuration: it cannot issue or consume an execution capability without a `PreExecutionPrivacyProof` and a distinct proof-integrity key.

The next Day-11 slice will propagate the proof through `DuckDBExecutor` and `verify_and_execute` and pre-bind this strict authorizer in the prospective runtime path.

## Capability extension

`ProofBoundExecutionAuthorization` extends the existing authorization artifact with one required field:

`privacy_proof_sha256`

The inherited authorization HMAC serializes the complete subclass model, so this proof commitment is covered by the same single-use capability MAC as SQL, plan, governance, policy, purpose, identity, rewrite lineage, disclosure commitment, and expiry.

A forged proof commitment therefore invalidates the authorization HMAC.

## Independent proof verification at issue and consume

The strict authorizer authenticates the full proof with the proof HMAC key and then matches it against the same independently recomputed runtime objects used for authorization:

- exact SQL text;
- freshly analyzed QueryPlan;
- full ContextResolution, including lineage;
- exact GovernanceContextBinding;
- PolicyEngine configuration;
- freshly recomputed PolicyDecision;
- task purpose;
- current authenticated RequestIdentity;
- subject key.

This is intentionally stronger than relying only on the legacy authorization `context_sha256`, whose historical normalized representation does not include lineage sources. Legacy compatibility is preserved, while prospective execution obtains a second, full-context commitment through the privacy proof.

## Same-snapshot issue path

Proof verification at issuance occurs after SQL analysis, context resolution, policy evaluation, disclosure-commitment validation, and governance revalidation, but before a disclosure commitment is claimed by an authorization ID. An invalid/missing/mismatched proof therefore cannot consume the disclosure commitment as a side effect.

The capability expiry is:

`min(issue_time + authorization_ttl, privacy_proof.expires_at)`

so the authorization cannot outlive its proof.

## Same-snapshot consume path

Consumption does not call the legacy `verify_and_consume` as a second pass. The strict subclass performs the complete verification sequence itself so the exact QueryPlan, ContextResolution, GovernanceContextBinding, PolicyDecision, and privacy proof are evaluated from the same pass before replay consumption.

It preserves the existing checks for:

- authorization HMAC;
- not-yet-valid / expiry / TTL;
- dialect;
- subject, identity, task and rewrite-parent binding;
- exact SQL and QueryPlan;
- governance binding and current governance revalidation;
- legacy context/policy/decision commitments;
- disclosure commitment and authorization claim;
- single-use replay protection.

It then additionally requires the presented proof to authenticate successfully, match the independently recomputed full runtime state, match the authorization's exact `privacy_proof_sha256`, and not expire before the authorization.

## Key separation

The proof HMAC key and execution-authorization HMAC key are distinct inputs. Possession of one key does not provide the other artifact's signing authority.

Both keys require at least 32 bytes.

## Failure behavior

Stable proof-bound authorization failures include:

- `AUTH_PRIVACY_PROOF_REQUIRED`
- `AUTH_PRIVACY_PROOF_INVALID`
- `AUTH_PRIVACY_PROOF_EXPIRED`
- `AUTH_PRIVACY_PROOF_NOT_YET_VALID`
- `AUTH_PRIVACY_PROOF_GOVERNANCE_BINDING_REQUIRED`
- `AUTH_PRIVACY_PROOF_IDENTITY_REQUIRED`
- exact SQL / plan / context / governance / policy / decision / task / identity / subject mismatch codes
- `AUTH_PRIVACY_PROOF_BINDING_MISMATCH`
- `AUTH_PRIVACY_PROOF_TTL_MISMATCH`
- `AUTH_PRIVACY_PROOF_BINDING_REQUIRED` when a legacy authorization is presented to the strict authorizer.

All failures occur before replay consumption. Existing legacy authorization failure codes remain unchanged.

## Security boundary

This slice does not yet make the core verifier require a proof. It provides the proof-bound capability primitive that the next slice will wire through the executor/verifier boundary.

The supported claim after this slice is only:

> When `ProofBoundExecutionAuthorizer` is selected, a single-use capability cannot be issued or consumed without an authenticated, unexpired privacy proof that matches the exact independently recomputed governed execution state, and the capability MAC binds the exact proof commitment.

It is not yet a claim that every ToxicJoin execution path is proof-required; that becomes testable only after the next orchestration slice.
