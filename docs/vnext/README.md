# ToxicJoin vNext Research Index

This directory is the pre-implementation research/design authority for ToxicJoin vNext.

Tracking issue: #72

Baseline `main` when this work began: `c25d73b2266a639cf1ef49022373b0bffff26fe2`.

No runtime implementation is authorized to contradict these contracts silently. A material change requires an explicit ADR/spec update and corresponding threat/evaluation impact review.

## Documents

- [`technical-spec.md`](technical-spec.md) — system boundaries, Evidence Layer, Disclosure Digital Twin, PPMC, CPCC, proof model, persistence, testing, performance and rollout.
- [`preregistration.md`](preregistration.md) — hypotheses, baselines, ablations, held-out split, metrics, no-peeking rules and Day-8 gate.
- [`prior-art.md`](prior-art.md) — current claim boundary and known adjacent work.
- [`threat-model-delta.md`](threat-model-delta.md) — new vNext assets, trust boundaries, threats, controls and residual risks.
- [`adr/0001-preserve-local-policy-kernel.md`](adr/0001-preserve-local-policy-kernel.md) — keep the current PolicyEngine as the local safety oracle.
- [`adr/0002-use-bounded-bfs-before-smt.md`](adr/0002-use-bounded-bfs-before-smt.md) — implement P0 PPMC with deterministic bounded BFS before considering symbolic solvers.

## P0 execution order

```text
Evidence Layer
  -> Disclosure Digital Twin
  -> Future Action Grammar
  -> PPMC
  -> Day-8 reproducible counterexample gate
  -> CPCC
  -> Privacy Proof Capsule/verifier
  -> proof-to-authorization binding
  -> Governed Agent MVP
  -> real DataHub end-to-end
  -> frozen held-out evaluation
  -> red-team closure
```

## Hard constraints

- `main` remains rollback-safe.
- Small auditable PRs only.
- Agent never owns execution authority.
- Weak/contested/incomplete/agent-only evidence cannot increase authority.
- PPMC budget exhaustion fails closed.
- `NO_COUNTEREXAMPLE_WITHIN_BOUND` is not global proof of safety.
- CPCC optimum is only within the committed finite remediation/cost space.
- No vNext percentage or benchmark result is reported before reproducible evidence exists.
- P1/P2 stay out of the governed submission path unless their proof gates are actually completed.
