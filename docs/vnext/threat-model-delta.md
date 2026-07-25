# ToxicJoin vNext Threat-Model Delta

Status: pre-implementation security contract

Date: 2026-07-25

This document extends the current ToxicJoin threat model for vNext. It does not replace the existing production threat model.

## 1. New assets

vNext adds security-relevant assets beyond the current runtime:

- evidence claims and their canonical commitments;
- Evidence Policy and trust-state resolution;
- disclosure-state/model commitments;
- Future Action Grammar and instantiated future actions;
- forbidden-state predicate definitions;
- PPMC search result and counterexample traces;
- CPCC remediation space and cost model;
- selected repair identity;
- pre-execution privacy proof;
- final Privacy Proof Capsule;
- P1 proof-dependency/revocation state if implemented.

## 2. New trust boundaries

1. DataHub/raw metadata -> Evidence Layer.
2. Agent-proposed context/metadata -> quarantined evidence state.
3. Evidence Layer -> local policy input.
4. Current disclosure ledger -> Disclosure Digital Twin.
5. Security-owned grammar -> PPMC instantiated transitions.
6. PPMC result -> CPCC or pre-execution proof.
7. CPCC candidate -> complete existing analysis/governance/policy path.
8. Pre-execution privacy proof -> single-use execution authorization.
9. Final verification -> final proof capsule.
10. P1 governance changes -> proof dependency/revocation graph.

## 3. New adversaries and failure modes

### TJ-VN-001 — Fresh but false metadata

An authenticated, fresh DataHub claim is semantically wrong.

Threat:

- freshness/provenance is mistaken for truth and increases authority.

Required control:

- authorization uses explicit Evidence Policy states;
- documentation states that `TRUSTED` means trusted under the declared evidence policy, not objectively proven true.

Residual risk:

- a wrong authoritative source may still satisfy the evidence policy. P0 does not solve objective metadata truth.

### TJ-VN-002 — Conflicting governance assertions

Two admissible sources provide incompatible classifications, mappings, or lineage claims.

Threat:

- arbitrary source ordering selects the less restrictive fact.

Required control:

- deterministic `CONTESTED` resolution;
- critical contested context cannot increase authority;
- canonical conflict evidence retained in the proof input/evidence root.

### TJ-VN-003 — Incomplete lineage mistaken for absence

Observed lineage contains no dangerous edge, but the acquisition is incomplete/truncated or an expected edge is missing.

Threat:

- absence of observed evidence is interpreted as evidence of absence.

Required control:

- explicit `INCOMPLETE` state when incompleteness is positively known;
- existing DataHub truncation/incomplete checks remain fail closed;
- no claim that complete API retrieval proves globally complete real-world lineage.

### TJ-VN-004 — Agent governance self-authorization

An Agent writes a favorable governance assertion and later reads it to obtain authority.

Required control:

- Agent-authored evidence resolves to `AGENT_ASSERTED`/quarantined state;
- Agent assertions cannot directly transition to `TRUSTED`;
- security-critical trust elevation requires an independently authorized path.

### TJ-VN-005 — Current-safe, future-unsafe disclosure sequence

A candidate is locally admissible but admitting it creates a bounded future sequence that reaches a declared forbidden disclosure state.

Required control:

- Disclosure Digital Twin + PPMC before proof/authorization when prospective mode is enabled;
- deterministic replayable counterexample;
- local `ALLOW` is necessary but insufficient.

### TJ-VN-006 — Future Action Grammar blind spot

The real attacker/Agent uses a future action outside the declared finite grammar.

Threat:

- a `NO_COUNTEREXAMPLE_WITHIN_BOUND` result is overclaimed as global safety.

Required control:

- grammar version/hash included in evidence/proof;
- result language always names the bound/grammar;
- no global-safety claim;
- adversarial grammar-gap analysis before final freeze.

Residual risk:

- out-of-grammar behavior remains outside the PPMC guarantee.

### TJ-VN-007 — State explosion / resource exhaustion

A candidate creates too many modeled states/actions for bounded search.

Threat:

- fail-open timeout or availability exhaustion.

Required control:

- explicit depth/state/action budgets;
- deterministic accounting;
- budget exhaustion returns a stable fail-closed reason;
- external request/resource budgets remain in force.

### TJ-VN-008 — Unsound canonicalization/deduplication

Two security-distinct disclosure states hash to the same canonical representation because relevant semantics were omitted.

Threat:

- PPMC prunes a dangerous path as a duplicate.

Required control:

- canonical state schema is strict/versioned;
- collision is not treated as the primary risk; semantic omission is;
- mutation tests vary each security-relevant field and assert state identity changes when required;
- explicit negative tests ensure irrelevant aliases/formatting do not change state identity.

### TJ-VN-009 — Transition-function underapproximation

A modeled action's state transition omits an information atom/inference consequence.

Threat:

- PPMC reports no counterexample because the transition model is unsound for the declared grammar.

Required control:

- each action class has positive/negative semantic transition tests;
- transition outputs cross-check against existing `DisclosureSemanticRelease` derivation where applicable;
- planted end-to-end counterexamples and action permutation tests.

### TJ-VN-010 — Counterexample fabrication or non-replayability

Displayed trace does not reproduce the claimed terminal state/forbidden predicate.

Required control:

- canonical action/state commitments;
- independent trace replay function;
- proof verifier recomputes trace semantics rather than trusting presentation text.

### TJ-VN-011 — Repair removes one path but creates another

CPCC fixes the discovered trace while introducing a different local or prospective disclosure path.

Required control:

- every repair goes through complete parse -> governance/evidence -> local policy -> disclosure state -> full PPMC;
- CPCC never treats syntactic transformation success as safety.

### TJ-VN-012 — Repair cost manipulation

Attacker-controlled input influences cost ordering so an unsafe/overbroad candidate is preferred.

Required control:

- remediation operators and costs are security-owned/versioned;
- cost model is committed into proof/evaluation manifests;
- deterministic tie-breaker uses canonical candidate identity;
- user/Agent text cannot directly set security cost weights.

### TJ-VN-013 — Proof substitution

A valid proof from query/state A is attached to authorization/query/state B.

Required control:

- pre-execution proof commits to exact effective SQL/query plan, governance binding, evidence root, disclosure state, policy/model versions, grammar, bound, and selected repair;
- execution authorization binds the exact proof commitment before end-to-end proof binding is claimed;
- verifier recomputes commitments.

### TJ-VN-014 — Proof/evidence TOCTOU

Governance/evidence changes after PPMC/proof generation but before execution.

Required control:

- preserve existing governance-binding freshness/drift verification;
- proof commits to that exact governance/evidence identity;
- authorization consumption revalidates required current bindings;
- any mismatch fails closed.

Residual risk:

- as in the current runtime, no distributed transaction exists across DataHub and DuckDB. The remaining window is minimized but not eliminated.

### TJ-VN-015 — Agent bypass of prospective path

Agent attempts to call an execution path that skips Evidence/PPMC/proof checks.

Required control:

- Agent receives proposal/adaptation capability only;
- production execution authority remains centralized in deterministic ToxicJoin runtime;
- direct-library and HTTP bypass tests;
- PPMC/proof requirement enforced below Agent orchestration, not merely in the Agent prompt.

### TJ-VN-016 — Proof verifier trusts mutable presentation fields

Human-readable explanation differs from committed machine semantics.

Required control:

- verifier uses canonical machine fields only;
- optional LLM/human explanations are non-authoritative and excluded from safety decisions.

### TJ-VN-017 — P1 revocation false negative

A governance claim changes but a dependent proof remains marked currently valid.

Required control if P1 is built:

- explicit dependency DAG;
- deterministic transitive invalidation;
- positive/negative graph mutation tests;
- historical `VALID_AT_EXECUTION` remains distinct from current validity.

### TJ-VN-018 — P1 revocation overreach

Unrelated governance change revokes proofs that do not depend on the changed claim.

Required control if P1 is built:

- dependency edges are canonical and explicit;
- tests measure both false negatives and false positives.

## 4. Required new invariants

- `Agent != Security Authority`.
- No non-`TRUSTED` critical evidence may increase authority.
- PPMC success cannot directly authorize execution.
- PPMC exhaustion cannot become `ALLOW`.
- Counterexamples are independently replayable.
- CPCC repairs are not trusted until the complete security pipeline accepts them.
- A proof is valid only for its exact committed query/state/evidence/model configuration.
- Existing result quarantine and post-execution release verification remain mandatory.
- Historical proof validity and current-governance validity are separate concepts.

## 5. Required negative/adversarial coverage

Before a vNext feature can enter the governed runtime, tests must cover relevant subsets of:

- classification flip;
- conflicting classifications;
- lineage edge addition;
- lineage edge deletion;
- lineage truncation/incomplete acquisition;
- stale evidence;
- Agent-authored favorable classification;
- Agent-authored false lineage;
- future-query permutation;
- modeled snapshot transition;
- state canonicalization mutation;
- grammar hash/version mutation;
- PPMC bound mutation;
- counterexample trace mutation;
- remediation-cost mutation;
- repaired-SQL mutation after PPMC;
- proof field substitution;
- governance/evidence drift before authorization;
- direct execution bypass attempts.

## 6. Claim discipline

Security documentation and judge-facing material must distinguish:

- `NO_COUNTEREXAMPLE_WITHIN_BOUND` from `PROVEN_SAFE`;
- `TRUSTED_UNDER_EVIDENCE_POLICY` from `TRUE`;
- `MINIMUM_COST_IN_DECLARED_SPACE` from `GLOBALLY_OPTIMAL`;
- `ZERO_UNSAFE_EXECUTIONS_IN_FROZEN_CORPUS` from universal detection/security.

Any implementation that cannot preserve these distinctions must remain experimental or be removed from the submission claim.
