# ADR-0001: Preserve the Existing Local Policy Kernel

Status: Accepted for vNext P0

Date: 2026-07-25

## Context

ToxicJoin already has a deterministic local policy engine, semantic SQL analysis, stateful disclosure controls, governance snapshot binding, single-use execution authorization, and post-execution release verification.

vNext introduces Evidence Layer semantics and prospective bounded disclosure reachability. A central design choice is whether PPMC should be embedded directly into the existing `PolicyEngine` or remain a separate security stage.

## Decision

Keep the existing `PolicyEngine` as the deterministic **local safety oracle**.

Implement the prospective layer as a separate security-authoritative stage after successful local evaluation and before pre-execution proof/authorization.

Conceptually:

```text
local semantic/evidence evaluation
    -> local policy result
    -> disclosure-state construction
    -> PPMC
    -> optional CPCC + complete local revalidation
    -> proof commitment
    -> existing authorization/verifier/execution path
```

PPMC success is never direct execution authority.

## Rationale

### Minimize Trusted Computing Base expansion

Embedding a state-space search engine into `PolicyEngine` would combine local rule semantics and prospective transition semantics into one larger component, making review and rollback harder.

### Preserve causal evaluation

Keeping the current local kernel stable allows evaluation to isolate whether PPMC provides value beyond current query/current-history enforcement.

### Preserve rollback safety

The already-validated runtime remains a coherent fallback. vNext can be removed/disabled without requiring a redesign of the local policy semantics.

### Maintain independent verification

The existing verifier/authorization path already re-analyzes and re-resolves security context before execution. vNext should strengthen the pre-authorization decision without weakening this independent boundary.

## Consequences

Positive:

- smaller P0 change surface;
- clearer ablation design;
- easier threat-model separation;
- straightforward fail-closed feature gating;
- current policy behavior remains a stable baseline.

Negative:

- some context may be transformed between local policy input and prospective state input;
- additional canonical commitments are required to prove both stages reasoned over compatible state;
- pipeline orchestration becomes more explicit.

## Required invariant

A candidate must satisfy every applicable authority stage. A local `ALLOW` does not imply prospective `ALLOW`, and a PPMC no-counterexample result does not imply execution authorization.

## Revisit criteria

This ADR may be revisited only if implementation demonstrates a concrete security inconsistency or unacceptable duplicated semantics that cannot be resolved through shared canonical models/interfaces. Aesthetic consolidation is not sufficient reason.
