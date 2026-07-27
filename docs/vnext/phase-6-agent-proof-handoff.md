# Phase 6 — Authenticated Governed-Agent Proof Handoff

## Status

This phase adds a **staged security-owned handoff primitive**. It does not change the current HTTP/product execution path, which still uses the pipeline-owned legacy `ExecutionAuthorizer` and supplies no privacy proof.

## Boundary

`DataHubAgentProofHandoffAuthority` composes the existing `DataHubAgentPreExecutionProofAuthority` and exposes only `issue(...)`.

The authority:

1. builds the exact `PreExecutionPrivacyProof` through the existing security-owned proof authority;
2. independently requires the proof content commitment to recompute exactly;
3. requires authentic Governed-Agent PPMC provenance under the existing Agent-provenance trust root;
4. seals the **entire proof object** into `AgentPreExecutionProofCapsule` under a separate HMAC domain using that provenance key;
5. returns the capsule rather than exposing a raw-proof construction method on the handoff authority.

The capsule commits the exact proof, proof commitment, Agent-provenance binding, authenticated request-identity commitment, issuance time, and expiry. Its content hash and handoff HMAC fail closed on proof substitution or capsule mutation.

## Key separation

Phase 6 does **not** add a fourth authority key.

The handoff capsule uses the existing Agent-provenance integrity key under a distinct HMAC domain. The privacy-proof integrity key remains separate, and the strict execution-authorization key remains separate.

Therefore the handoff verifier can establish that the exact content-consistent proof was endorsed by the Agent-provenance authority without receiving the privacy-proof HMAC key. It cannot, by itself, establish proof-HMAC authenticity or execution authorization.

## Mandatory downstream verification

An authenticated capsule is not sufficient to execute SQL.

A future product bridge that accepts this capsule must still pass its contained proof into the strict `ProofBoundExecutionAuthorizer`, which independently verifies:

- the privacy-proof HMAC;
- Agent provenance;
- exact SQL/query plan;
- authenticated request identity;
- governed context and governance binding;
- policy decision;
- disclosure commitment when required;
- proof lifetime and execution capability bindings.

No capsule validation result may be interpreted as an execution capability.

## Claim boundary

This phase does not:

- make proof-bound execution canonical;
- modify `ToxicJoinPipeline` proof production;
- add an Agent proof HTTP endpoint;
- give the planning Agent access to proof/provenance keys;
- give the Agent execution, disclosure-state, or DataHub mutation authority;
- claim that capsule HMAC validation replaces proof-HMAC validation;
- change current release claims for `/api/execute-safe`.

The canonical runtime truth remains `docs/security-architecture.md` until a later phase explicitly wires and proves the proof-bound product path.
