# Phase 15 — Cryptographic Domain Separation

## Scope

Phase 15 audits the authenticated artifact chain after the Phase 14 proof/runtime binding closure. The focus is protocol-level MAC separation: an authentication tag minted for one security artifact family must not remain valid when the same key material is accidentally reused by a different protocol family.

The phase does not change PolicyEngine semantics, PPMC semantics, DataHub credentials, warehouse snapshot semantics, or the canonical HTTP execution flow.

The target invariant is:

> A capability authenticated for the staged proof-bound execution protocol cannot be reinterpreted as a legacy execution capability, even if deployment configuration accidentally reuses the same execution HMAC key in both authorities.

## Audit result

The existing Governed-Agent/proof chain already uses explicit HMAC domains for its authenticated artifact families, including:

- pre-execution privacy proofs;
- Agent PPMC proof provenance;
- proposal-evaluation handoff capsules;
- Agent PPMC handoff capsules;
- Agent pre-execution proof handoff capsules.

Those domains are intentionally distinct even where the same Agent-provenance trust root is reused.

Execution capability authentication was the exception relevant to this phase. `ExecutionAuthorizer._mac()` authenticated only the canonical JSON payload. `ProofBoundExecutionAuthorizer` inherited that exact MAC function. Therefore legacy and proof-bound capability protocols were cryptographically identical when configured with the same execution key.

## Proven gap

The red TDD head `5716349cef61fd540817ed567345638e17eae63b` constructed one exact `ProofBoundExecutionAuthorization` and computed its capability MAC through both:

- legacy `ExecutionAuthorizer`; and
- strict public `ProofBoundExecutionAuthorizer`.

Both authorities were deliberately configured with the same execution key while proof/provenance keys remained correctly separated.

The MACs were identical.

Ground Truth on Python 3.11 recorded:

- `1 failed, 833 passed`
- failure: legacy and proof-bound execution capabilities shared one MAC protocol domain.

The ordinary CI matrix failed the same regression on Python 3.11 and Python 3.12.

This is a cross-protocol/downgrade gap, not a break of HMAC-SHA256. The cryptographic primitive was sound; the protocol message namespace was not separated.

The legacy verifier accepts the `ExecutionAuthorization` base shape and historically did not possess an independent proof-bound MAC namespace. Under execution-key reuse, a capability minted after strict proof checks could therefore retain a valid legacy capability MAC and cross the legacy verification boundary without presenting the privacy proof at consumption.

## Fix

### Dedicated proof-bound execution MAC domain

`ProofBoundExecutionAuthorizer` now authenticates its capability payload under:

`toxicjoin:proof-bound-execution-authorization:v1\0`

The canonical payload remains the complete `ProofBoundExecutionAuthorization`, including `privacy_proof_sha256`; only the protocol message domain changes.

The proof-bound authorizer overrides capability MAC generation, so issuance and consumption use the same dedicated domain.

### Legacy protocol intentionally unchanged

Phase 15 does not rewrite the legacy `ExecutionAuthorizer` MAC format. That path is still the canonical staged-migration/current-runtime primitive and changing its wire authentication format was not required to close the proven proof-bound downgrade.

Separation is achieved because a proof-bound tag is now computed over:

`proof-bound-domain || canonical-capability`

while the historical legacy tag is computed over its historical message format. Even with identical execution-key bytes, the authenticated messages are different.

This keeps the production blast radius narrow while making the stronger vNext protocol cryptographically non-interchangeable with legacy execution.

## Regression coverage

Phase 15 covers:

- legacy and proof-bound authorities produce different MACs for the exact same proof-bound capability under deliberate execution-key reuse;
- a capability MAC produced by the proof-bound authority is rejected by `legacy.verify_and_consume()` with `AUTH_INVALID_MAC` before legacy policy/context processing can reinterpret it;
- proof integrity, Agent-provenance, and execution keys remain independently separated in the strict authority;
- existing proof-bound issue/consume behavior remains unchanged apart from the protocol MAC namespace;
- existing Agent/proof handoff domains remain untouched.

## Security interpretation

Key separation and domain separation solve different failure classes.

Key separation limits what compromise of one authority key can forge. Domain separation additionally prevents a configuration or composition mistake that reuses key material from turning one valid protocol artifact into another protocol artifact.

Phase 15 therefore preserves the existing key-role isolation and adds protocol-role isolation at the proof-bound execution boundary.

## Claim boundary

Phase 15 does **not** claim:

- that all deployments derive keys through a KDF or managed KMS;
- automatic rotation or distributed key custody;
- that legacy execution has become proof-bound;
- that the canonical HTTP runtime has migrated to the vNext strict proof chain;
- public-key/non-repudiation semantics for capability MACs;
- cross-node shared replay state.

Those concerns remain separate roadmap work. The next phase should proceed from this exact cryptographic boundary without broadening the current runtime claims.