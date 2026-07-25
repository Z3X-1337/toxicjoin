# ADR-0002: Use Deterministic Bounded BFS for PPMC P0

Status: Accepted for vNext P0

Date: 2026-07-25

## Context

PPMC must answer a bounded operational question: after admitting the current candidate, can a declared forbidden disclosure state become reachable through a declared finite grammar of future analytical actions?

Candidate implementation strategies include:

1. direct bounded graph search;
2. SMT/SAT model encoding (for example Z3-backed);
3. graph database plus generic rule engine;
4. LLM-generated adversarial future plans.

## Decision

Implement P0 PPMC using deterministic bounded breadth-first search (BFS) over canonical immutable disclosure states and a finite security-owned action grammar.

Do not introduce an SMT solver into P0 unless a later measured requirement proves the bounded explicit-state design insufficient.

## Rationale

### Counterexample quality

BFS naturally returns a shortest-depth counterexample under deterministic action ordering, which improves replay and judge/security evidence.

### Auditability

The transition relation, pruning, canonical hashing, and bound are explicit application code rather than solver encoding assumptions.

### Dependency and TCB control

P0 does not need a new heavyweight solver dependency, solver configuration, or solver-model translation layer.

### Development-window fit

The 17-day submission window favors a small model that can be aggressively tested for soundness within its declared scope.

### Scientific honesty

A finite grammar + explicit bound makes the claim boundary obvious. The implementation cannot accidentally be marketed as verification of arbitrary SQL.

## Search requirements

- canonical immutable state representation;
- deterministic canonical action ordering;
- visited-state deduplication by security-complete canonical identity;
- explicit depth, state, and action budgets;
- fail-closed budget exhaustion;
- deterministic trace reconstruction;
- independent counterexample replay;
- metrics for nodes, transitions, frontier size, and deduplicated states.

## Rejected alternatives for P0

### SMT/SAT first

Advantages:

- expressive symbolic constraints;
- possible compact exploration for some state spaces.

Reasons rejected for P0:

- additional dependency and Trusted Computing Base;
- encoding bugs become part of privacy semantics;
- harder to explain exact operational coverage;
- unnecessary until explicit-state measurements demonstrate a real limitation.

### Generic graph database/rule engine

Reasons rejected:

- persistence and operational complexity without a demonstrated P0 requirement;
- harder deterministic evidence/reproduction story;
- disclosure history is already persisted by the existing ledger.

### LLM adversarial rollout

Reasons rejected:

- non-deterministic/incomplete search;
- Agent/LLM would influence the security model;
- counterexample absence would have no strong meaning.

An LLM may later propose research scenarios but cannot define the authoritative PPMC search result.

## Consequences

Positive:

- simple implementation and evidence chain;
- deterministic shortest-depth counterexamples;
- precise performance metrics;
- easy ablation and replay.

Negative:

- explicit state explosion;
- limited expressiveness;
- finite grammar may miss real actions;
- more sophisticated symbolic reasoning may later be needed.

These negatives are represented as declared model limits, not hidden.

## Revisit criteria

Consider symbolic/SMT techniques only if all are true:

1. the explicit PPMC semantics and Day-8 counterexample gate are already validated;
2. measured state explosion prevents useful declared scenarios within acceptable budgets;
3. a symbolic encoding can preserve deterministic replay and claim boundaries;
4. the added solver TCB/dependency cost is justified by measured coverage or performance improvement.
