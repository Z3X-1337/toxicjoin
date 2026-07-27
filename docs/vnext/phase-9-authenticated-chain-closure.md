# Phase 9 — Authenticated Agent Chain Closure

Status: **assurance-only vNext boundary validation; no production runtime change**.

## Purpose

Phases 6–8 added authenticated authority handoffs where testing proved real gaps:

- security-owned pre-execution proof handoff;
- authenticated PPMC handoff into proof issuance;
- authenticated proposal-evaluation handoff into GovernanceTrust/PPMC.

Phase 9 tests the remaining transitions before leaving the Agent/evidence trust workstream. The rule
for this phase is deliberately conservative: do not add another MAC, capsule, or authority unless a
caller-controlled artifact can actually cross an existing security boundary.

## F6 → PPMC result

No caller-supplied F6 clearance path exists in `DataHubAgentPpmcAuthority`.

The PPMC authority constructs `DataHubF6GovernanceAuthority` inside its own security boundary and
issues a fresh F6 clearance from the exact proposal evaluation, DataHub GovernanceTrust binding,
and DisclosureState. It then checks evaluation, state, purpose, governance, evidence, grammar, and
freshness bindings before invoking the prospective checker.

The Phase 9 surface test locks out direct caller inputs for:

- `f6_clearance`;
- prospective `governance_binding`;
- `local_oracle`.

A separate authenticated F6 capsule would therefore duplicate an authority boundary that is not
externally injectable.

## PPMC → pre-execution proof result

`DataHubAgentPreExecutionProofAuthority` accepts an authenticated
`AgentPpmcEvaluationCapsule` and verifies its authority HMAC before serializing the nested PPMC
evaluation.

The remaining raw inputs are treated only as preimages and must match commitments already carried
by the authenticated PPMC capability.

Phase 9 adds explicit regressions proving that proof issuance rejects:

- a fully self-consistent reconstructed proposal evaluation whose `evaluation_sha256` differs from
  the one authenticated inside the PPMC capsule;
- a different but internally valid DisclosureState whose `state_sha256` is not the PPMC-bound state;
- a different but internally valid FutureActionGrammar whose `grammar_sha256` is not the one bound
  into the PPMC result.

The proof-authority API also remains locked against raw caller-supplied F6 clearance, raw PPMC
result, GovernanceTrust binding, or local policy oracle.

## Test finding

The first Phase 9 CI run had one failure caused by the test fixture itself: a provisional
`DisclosureState` was constructed from JSON dictionaries, so the state hash helper encountered a
plain dictionary where a typed `DisclosureScope` was required. The production trust boundary was
not reached.

The fixture was corrected to derive the alternate state from the typed immutable model, recompute
the canonical state hash, and validate it as a fully valid but different DisclosureState. With that
correction, all new chain-continuity tests pass.

## Security conclusion

No new authority-authenticity bypass was demonstrated in Phase 9. Therefore this phase adds no
production authority, no new key, and no new cryptographic capsule.

The staged authenticated chain is:

1. Governed Agent proposal (planning only)
2. security-owned proposal evaluation
3. authenticated proposal-evaluation capsule
4. GovernanceTrust resolution
5. internal fresh F6 clearance
6. security-owned PPMC evaluation
7. authenticated PPMC capsule
8. security-owned pre-execution privacy proof + Agent PPMC provenance
9. authenticated proof handoff
10. strict proof-bound execution authorizer (staged, not yet canonical product wiring)

Each raw artifact that still appears at a downstream boundary is used only as a preimage and must
match a cryptographic commitment carried by an already authenticated upstream capability.

## Claim boundary

Phase 9 does **not**:

- make proof-bound execution the canonical HTTP/product path;
- modify `ToxicJoinPipeline`, the current canonical legacy `ExecutionAuthorizer`, or API behavior;
- add an F6 authority key, proof-handoff key, or any fourth/fifth trust root;
- give the planning Agent any proof, execution, disclosure-state mutation, or DataHub write authority;
- claim that successful bounded PPMC means universal future safety beyond the declared model/bound.

`docs/security-architecture.md` remains the canonical current-runtime truth until a later explicit
migration phase changes product wiring.
