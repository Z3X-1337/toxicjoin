# Phase 8 — Authenticated Agent Proposal Evaluation Handoff

Status: **staged vNext security boundary; not canonical product runtime wiring**.

## Proven gap

The Phase 8 TDD head first demonstrated that `TrustedAgentProposalEvaluation` was a
content-integrity artifact, not an authority-authenticity capability.

A caller could take a legitimate proposal evaluation, replace the trusted
`authorized_task_purpose`, deterministically rebuild the corresponding policy input and
PolicyEngine decision, recompute every affected content hash, and obtain a fully valid
`TrustedAgentProposalEvaluation`. The raw `DataHubGovernanceTrustAuthority` accepted that
self-reconstructed artifact because its model hashes proved consistency but not that the
trusted request scope came from `DataHubAgentProposalAuthority`.

The red test therefore distinguishes two properties:

- content integrity: fields and hashes are internally consistent;
- authority authenticity: the artifact was actually issued by the security-owned proposal authority.

Only the second property is sufficient for promotion into the authenticated downstream chain.

## Security boundary

`DataHubAgentProposalHandoffAuthority` composes the existing
`DataHubAgentProposalAuthority` and immediately seals its exact evaluation into
`AgentProposalEvaluationCapsule`.

The capsule binds the exact proposal evaluation and execution-relevant commitments, including:

- proposal, goal, and planning-context hashes;
- source snapshot and evidence root/expiry;
- trusted authorized-task-purpose commitment;
- subject key and query plan;
- grounded governance context;
- deterministic policy input and decision.

The complete capsule is authenticated with the existing Agent-provenance integrity key under a
separate HMAC domain:

`toxicjoin:agent-proposal-evaluation-handoff:v1`

No fourth authority key is introduced.

## Downstream use

`DataHubAgentGovernanceTrustHandoffAuthority` requires a valid proposal-evaluation capsule before
calling the existing `DataHubGovernanceTrustAuthority`.

`DataHubAgentPpmcHandoffAuthority` also requires the authenticated proposal capsule before it can
run PPMC and issue the Phase 7 authenticated PPMC capsule. A raw
`TrustedAgentProposalEvaluation` therefore cannot be promoted directly into the authenticated
PPMC → proof chain.

The underlying raw proposal, GovernanceTrust, F6, and PPMC primitives remain available for staged
analysis and rollback-safe testing. Their raw artifacts are not sufficient to enter the authenticated
proof/execution chain.

## Why GovernanceTrust is not separately MACed here

Phase 8 does not add an independent HMAC to `GovernanceTrustBinding`. The F6 authority already
reconstructs the expected governance requirements and EvidenceTrust resolutions from the exact
evaluation evidence and package-owned Evidence Policy, then compares them before producing its
state-bound clearance. Adding another signature at that layer would duplicate verification without
closing the proposal-authority gap proven by the TDD test.

## Adversarial invariants

The Phase 8 tests require fail-closed behavior for:

- self-reconstructed trusted request purpose and recalculated model hashes;
- wrong Agent-provenance key;
- post-issuance capsule mutation;
- HMAC-domain confusion with the Phase 7 PPMC handoff;
- polymorphic proposal-evaluation models before virtual serialization;
- raw proposal evaluation supplied directly to authenticated PPMC handoff;
- constructor traceback/local secret retention.

The existing positive chain remains covered through authenticated proposal evaluation →
GovernanceTrust → authenticated PPMC → pre-execution proof → strict proof-bound authorizer.

## Claim boundary

Phase 8 does **not**:

- make proof-bound execution canonical;
- wire the Governed Agent into the current HTTP/product pipeline;
- change `ToxicJoinPipeline`, the current canonical legacy `ExecutionAuthorizer`, or the API surface;
- give the planning Agent any provenance/proof/execution key;
- give the Agent DisclosureState mutation or DataHub write authority;
- make a proposal capsule, GovernanceTrust binding, or PPMC capsule sufficient to execute SQL.

`docs/security-architecture.md` remains the canonical product-runtime truth until a later explicit
migration phase changes the runtime wiring.
