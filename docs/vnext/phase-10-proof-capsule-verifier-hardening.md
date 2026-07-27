# Phase 10 — Privacy Proof Capsule + Verifier Hardening

Status: **staged vNext proof hardening; not canonical HTTP/product runtime wiring**.

## Proven gap

Phase 10 began with a test-only TDD head against the existing generic
`verify_preexecution_privacy_proof()` boundary.

The verifier accepted any object satisfying `isinstance(value, PreExecutionPrivacyProof)` and then
used virtual `model_dump()` dispatch to compute the proof content commitment and HMAC input.

A malicious `PreExecutionPrivacyProof` subclass could therefore:

1. inherit the trusted proof type;
2. override `model_dump()` to serialize a legitimate proof;
3. expose different security-relevant attributes on the actual object, including a different
   `disclosure_state_sha256` and `ppmc_result_sha256`;
4. pass the generic verifier as `valid=True` because content-hash and HMAC verification operated on
   the substituted serialization instead of the object later read by callers.

The initial CI run proved the gap on both supported Python versions. On Python 3.11 the full suite
reported `1 failed, 808 passed`; the Phase 10 assertion failed because the verifier returned
`valid=True` for the polymorphic proof.

This is a type-confusion / virtual-serialization boundary flaw, not a cryptographic break in
HMAC-SHA256.

## Fix

`src/toxicjoin/proofs/preexec.py` now requires exact model types before proof-object serialization.

For a `PreExecutionPrivacyProof` object, the shared serialization boundary requires:

- `type(proof) is PreExecutionPrivacyProof`;
- exact `AgentPpmcProofBinding` when Agent provenance is present;
- exact `RepairProofBinding` when a CPCC repair commitment is present.

The guard is used by both public compute helpers and the generic verifier. A polymorphic proof is
therefore rejected before virtual `model_dump()` can influence either the content hash or HMAC
input.

Serialized mapping input remains supported. The verifier first validates that mapping through the
canonical Pydantic proof model and then applies the same exact nested-type checks before hashing.

## Regression coverage

Phase 10 locks the boundary with explicit tests for:

- a malicious proof subclass whose virtual serialization returns a legitimate proof while direct
  object attributes contain different DisclosureState and PPMC commitments;
- direct use of `compute_preexecution_privacy_proof_sha256()` with the malicious proof subclass;
- direct use of `compute_preexecution_privacy_proof_hmac()` with the malicious proof subclass;
- a malicious nested `AgentPpmcProofBinding` rejected before its `model_dump()` can execute;
- a malicious nested `RepairProofBinding` rejected before its `model_dump()` can execute.

The existing positive proof, benchmark, PPMC, execution-authorizer, and container suites remain the
regression baseline.

## Security properties retained

This phase does not change:

- proof schema/version;
- proof HMAC domain (`toxicjoin:preexecution-privacy-proof:v1`);
- PPMC execution profile or bounded-safety claim;
- proof TTL/freshness semantics;
- proof-integrity key material or execution-authorization keys;
- policy, disclosure, DataHub, or Governed Agent behavior.

The existing `ProofBoundExecutionAuthorizer` key-separation invariant remains unchanged: the privacy
proof integrity key must differ from the execution authorization HMAC key. Agent provenance remains
a distinct authenticated trust domain in the strict Agent path.

## Claim boundary

Phase 10 does **not**:

- make proof-bound execution the canonical HTTP/product path;
- wire the Governed Agent or proof generation into `ToxicJoinPipeline`;
- change the current canonical legacy `ExecutionAuthorizer` product behavior;
- make bounded PPMC a universal proof of future safety;
- give the planning Agent any proof, execution, disclosure-state mutation, credential, or DataHub
  write authority.

`docs/security-architecture.md` remains the canonical current-runtime truth until a later explicit
migration phase changes product wiring.
