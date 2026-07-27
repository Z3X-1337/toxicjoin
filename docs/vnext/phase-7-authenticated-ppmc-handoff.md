# Phase 7 — Authenticated Agent PPMC Handoff

## Status

This phase closes a staged authority-authenticity gap between the security-owned Governed-Agent PPMC authority and the security-owned pre-execution proof authority. It does not change the current HTTP/product execution path and it does not make proof-bound execution canonical.

## Proven gap

Before this phase, `TrustedAgentPpmcEvaluation` and `PpmcSearchResult` were strongly self-consistent content-integrity artifacts, but their hashes were not proof that the artifact had actually been issued by `DataHubAgentPpmcAuthority`.

A validation-only TDD commit demonstrated the consequence on the exact Phase 7 branch: a library caller could modify the PPMC search transcript commitment, recompute `PpmcSearchResult.result_sha256`, recompute `TrustedAgentPpmcEvaluation.evaluation_sha256`, and pass that self-consistent reconstructed artifact to `DataHubAgentPreExecutionProofAuthority`. The pre-execution proof authority accepted it and could then mint genuine downstream Agent provenance over the reconstructed PPMC metadata.

The red Ground Truth run intentionally failed with `DID NOT RAISE`, proving that content hashes alone were not authority authenticity at this downstream handoff.

## New boundary

`DataHubAgentPpmcHandoffAuthority` composes the existing `DataHubAgentPpmcAuthority` and returns `AgentPpmcEvaluationCapsule` rather than exposing the raw PPMC evaluation as a proof-authority input.

The capsule:

1. contains the exact `TrustedAgentPpmcEvaluation` issued by the existing security-owned PPMC authority;
2. commits the exact evaluation, PPMC result, F6 clearance, and evidence expiry;
3. authenticates the complete capsule using the existing Agent-provenance integrity key under a distinct HMAC domain;
4. rejects wrong-key validation, post-issuance mutation, and nested polymorphic model substitution;
5. does not authorize execution.

`DataHubAgentPreExecutionProofAuthority` now accepts only the authenticated PPMC capsule. A raw `TrustedAgentPpmcEvaluation`, even when every internal hash has been recomputed consistently, is rejected as `AGENT_PROOF_PPMC_AUTHORITY_UNTRUSTED`.

The proof authority authenticates the capsule before any serialization of the nested PPMC evaluation, then continues its existing independent checks for proposal/evaluation alignment, PPMC safety status, disclosure state, grammar, SQL/query plan, F6 bindings, package policy, evidence freshness, and proof construction.

## Key separation

Phase 7 adds no fourth authority key.

The PPMC handoff uses the existing Agent-provenance integrity key under the domain:

`toxicjoin:agent-ppmc-evaluation-handoff:v1`

That domain is distinct from the Agent proof-provenance HMAC domain. The privacy-proof integrity key and execution-authorization key remain separately controlled.

## Generic PPMC remains available

The existing `DataHubAgentPpmcAuthority` and generic PPMC primitives remain available for staged analysis and testing. Their output remains a content-integrity artifact, not an execution capability.

Only the PPMC-to-proof boundary requires `AgentPpmcEvaluationCapsule`. This avoids falsely upgrading every PPMC result into an authenticated execution artifact while closing the exact downstream trust gap proven by the Phase 7 regression.

## Claim boundary

This phase does not:

- modify `ToxicJoinPipeline`;
- modify `/api/execute-safe` or add an Agent endpoint;
- make `ProofBoundExecutionAuthorizer` the canonical product authority;
- give the planning Agent an HMAC key;
- give the Agent execution, disclosure-state, or DataHub mutation authority;
- make a PPMC capsule sufficient for SQL execution;
- replace strict proof-HMAC, Agent provenance, current-state, or execution-capability verification.

The canonical runtime truth remains `docs/security-architecture.md` until a later phase explicitly wires and proves the proof-bound product path.
