# Phase 13 — PPMC Resource-Safety Verification

## Scope

Phase 13 hardens only the execution-eligible Governed-Agent PPMC path. It does not change the generic bounded model checker, forbidden-predicate semantics, PolicyEngine decisions, DataHub privileges, or the canonical HTTP/product execution path.

The target invariant is:

> A caller may supply governed model inputs, but cannot select the amount of synchronous PPMC work performed by the authenticated authority chain that can mint a pre-execution proof.

## Proven gap

Before this phase, `DataHubAgentPpmcHandoffAuthority.check()` accepted a caller-provided `PpmcSearchConfig`. That authenticated handoff is the authority-authenticity path that can feed PPMC output into `DataHubAgentPreExecutionProofAuthority`.

The downstream proof verifier constrained the PPMC profile only after the bounded search had already run. The old `p0-preexec-v1` profile also treated any legal bound from 3 through 5 as proof-eligible and imposed no execution-specific state ceiling beyond the generic PPMC hard maximum.

The red TDD head `9e06114e14536373b793141e207acbfda179e06d` added one boundary assertion requiring the authenticated handoff not to expose `config`. Python 3.11 failed exactly that assertion with:

- `1 failed, 821 passed`
- `DataHubAgentPpmcHandoffAuthority.check` still exposed `config: PpmcSearchConfig | None`

Python 3.12 failed the same regression.

This was an authority/resource-ownership gap, not a prospective-safety false negative: state-budget exhaustion already fails closed. The risk was that an execution-capable caller could enlarge deterministic synchronous work before proof rejection.

## Fix

### Security-owned authenticated search configuration

`DataHubAgentPpmcHandoffAuthority.check()` no longer accepts `config`.

The handoff now constructs its PPMC configuration internally through `build_preexecution_ppmc_search_config()` and forwards only that security-owned configuration to the lower-level PPMC authority.

The generic/raw `DataHubAgentPpmcAuthority` and generic PPMC API remain configurable for offline analysis and testing. Resource ownership is tightened only at the authenticated proof-producing boundary.

### PPMC pre-execution profile v2

The execution-proof profile is versioned as:

`p0-preexec-v2`

V2 defines:

- exact search depth: `bound = 3`
- authenticated runtime state budget: `max_states = 256`
- proof-eligible state ceiling: `max_states <= 256`
- exact canonical configuration-hash binding

Bounds 4 and 5 remain legal generic PPMC configurations but are not pre-execution-proof eligible. Generic state budgets above 256 remain legal for offline PPMC but are not pre-execution-proof eligible.

A smaller state budget may still verify as profile-compatible because insufficient state capacity cannot silently certify safety: PPMC returns explicit `FAIL_CLOSED / STATE_BUDGET_EXHAUSTED` when the reachable model exceeds the budget. The authenticated Agent path itself always emits the fixed 256-state budget.

### Versioning

The previous identifier `p0-preexec-v1` is not silently redefined. Proof and Agent-provenance models now bind to `p0-preexec-v2`, and the profile verifier explicitly rejects the legacy v1 identifier.

Pre-execution proofs already have a maximum lifetime of 60 seconds, so this security-profile version transition does not create a long-lived proof migration problem.

## Deterministic work envelope

The current Future Action Grammar is finite and permits at most 32 actions per state. With the authenticated state ceiling of 256, the pre-execution path has a conservative upper bound of:

`256 states × 32 actions/state = 8,192 action considerations`

The depth horizon remains exactly three. Independent Twin/grammar budgets also remain in force, including state-atom, inference-rule, grammar-action, and finite-context limits.

This phase deliberately uses deterministic semantic/resource budgets instead of a wall-clock timeout. Wall-clock cutoffs would make proof behavior host/load dependent and would weaken reproducibility of evidence.

## Regression coverage

Phase 13 covers:

- the authenticated PPMC handoff surface does not expose `config`;
- the authenticated Agent proof chain emits the fixed v2 bound and state budget;
- deeper generic bounds 4/5 are rejected for proof eligibility;
- generic state budgets above the execution ceiling are rejected for proof eligibility;
- legacy `p0-preexec-v1` is rejected;
- canonical configuration-hash rebinding is rejected;
- smaller completed-search budgets remain profile-compatible while exhaustion semantics remain fail closed;
- proof-key metadata rebinding is still caught by Agent provenance even when the forged alternate budget remains inside the approved v2 envelope;
- proposal-handoff negative tests use the new authority surface rather than the removed caller configuration parameter;
- generic PPMC configurability remains available outside the authenticated execution-proof path.

## Claim boundary

Phase 13 does **not** claim:

- unbounded prospective privacy safety;
- a global wall-clock or memory guarantee for arbitrary Python execution;
- that all generic PPMC configurations are execution-proof eligible;
- changes to DataHub read/write credentials or Agent privileges;
- changes to PolicyEngine or disclosure-ledger semantics;
- canonical proof-bound execution in the current HTTP/product path;
- DataHub decision write-back or cross-agent inheritance.

Those product-level integrations remain subsequent phases. The next highest-leverage target is a judge-visible canonical Governed-Agent runtime that composes the already hardened DataHub context, proposal authority, governance trust, PPMC v2, pre-execution proof, and strict execution authorization chain without giving the planning Agent security authority.
