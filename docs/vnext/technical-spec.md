# ToxicJoin vNext Technical Specification

Status: **frozen design candidate**

Date: 2026-07-25

Research tracking issue: #72

Baseline `main` at vNext branch creation: `c25d73b2266a639cf1ef49022373b0bffff26fe2`

Frozen runtime merge from PR #68: `ee4991a93070c148e41dd158c952d5f1e9a6ed2c`

Exact security-tested runtime provenance: `536c37c34de7b36495d33f63095585f72e5f4b46`

## 1. Scope and claim boundary

ToxicJoin vNext extends the existing DataHub-grounded deterministic compositional privacy firewall into an **evidence-aware prospective privacy runtime for AI data agents**.

The target contribution is deliberately narrower than universal privacy verification:

> Evidence-conditioned prospective compositional privacy authorization for AI-generated analytical SQL, using bounded disclosure-state reachability over a declared finite future-action grammar and deterministic minimum-cost repair over a declared finite remediation space.

The runtime MUST NOT claim:

- universal privacy;
- formal verification of arbitrary SQL;
- Differential Privacy;
- universal re-identification prevention;
- globally optimal SQL repair;
- complete future-action coverage;
- that absence of a bounded counterexample proves global safety;
- that fresh or authenticated metadata is necessarily true in the real world.

A successful PPMC result is stated only as:

> No declared forbidden disclosure state was reachable within bound `B` under Future Action Grammar `G`, Evidence Policy `E`, and the committed disclosure state.

## 2. Architectural decision

The existing `PolicyEngine` remains the deterministic **local safety oracle**. PPMC MUST NOT be implemented inside `PolicyEngine`.

The prospective layer sits between successful local evaluation and the existing execution-authorization/verifier path:

```text
USER GOAL
  -> GOVERNED AGENT (discover / plan / propose only)
  -> DATAHUB CONTEXT ACQUISITION
  -> EVIDENCE RESOLVER
  -> TRUSTED CONTEXT
  -> SQL ANALYSIS
  -> EXISTING LOCAL PRIVACY KERNEL
  -> DISCLOSURE DIGITAL TWIN
  -> PPMC
       | no counterexample within bound
       | counterexample -> CPCC -> full revalidation -> PPMC
  -> PRE-EXECUTION PRIVACY PROOF
  -> EXISTING SINGLE-USE AUTHORIZATION
  -> EXISTING VERIFIER
  -> READ-ONLY DUCKDB EXECUTION
  -> POST-EXECUTION QUARANTINE / RELEASE VERIFICATION
  -> FINAL PRIVACY PROOF CAPSULE
  -> DISCLOSURE LEDGER FINALIZATION
  -> DATAHUB DECISION WRITE-BACK
```

This preserves the existing rollback-safe kernel and minimizes expansion of the Trusted Computing Base.

## 3. System and trust boundaries

### 3.1 Security-authoritative components

The following components are security-authoritative once implemented and validated:

- SQL parser/analyzer and semantic exposure plan;
- Evidence Resolver and Evidence Policy;
- existing deterministic PolicyEngine;
- disclosure-state builder and deterministic inference closure;
- PPMC transition system and search implementation;
- CPCC candidate enumerator, cost ordering, and candidate validator;
- privacy-proof builder/verifier;
- existing execution authorizer;
- existing post-execution verifier;
- existing disclosure ledger.

### 3.2 Conditionally trusted external context

- DataHub OSS;
- official DataHub MCP server and configured credentials;
- human-authored governance assertions;
- warehouse/snapshot identity supplied by a supported trusted integration.

These are evidence sources. Their output is not automatically security truth.

### 3.3 Untrusted

- LLM outputs;
- agent planning;
- natural-language goals;
- agent-proposed SQL;
- agent-authored metadata;
- fuzzy matching/inference;
- caller explanations/rationales;
- candidate remediations proposed outside the deterministic CPCC implementation.

## 4. Agent authority model

The Governed Agent may:

- discover catalog assets;
- inspect schema/lineage/governance available through its read surface;
- plan a task;
- propose SQL;
- receive structured ToxicJoin feedback;
- adapt toward the legitimate task goal.

The Agent MUST NOT:

- authorize execution;
- execute directly through the governed runtime;
- mark evidence as trusted;
- modify the policy kernel;
- mutate disclosure history;
- choose or shrink the PPMC future-action grammar;
- validate its own proof;
- make an agent-authored governance assertion immediately increase authority.

`AGENT != SECURITY AUTHORITY` remains a hard invariant.

## 5. Evidence Layer

### 5.1 Evidence dimensions

Source and derivation are separate dimensions.

Representative `EvidenceSource` values:

- `DATAHUB_MCP`
- `WAREHOUSE_RUNTIME`
- `STATIC_MANIFEST`
- `SQL_ANALYZER`
- `HUMAN_GOVERNANCE`
- `AGENT`

Representative `DerivationKind` values:

- `RUNTIME_OBSERVED`
- `EXPLICIT_MAPPING`
- `SQL_DERIVED`
- `STRICT_NAME_MATCH`
- `FUZZY_INFERRED`
- `HUMAN_ASSERTED`
- `AGENT_ASSERTED`

### 5.2 Evidence claim

A security-relevant claim MUST be representable canonically with at least:

```text
EvidenceClaim<T> {
  claim_id
  subject
  predicate
  value
  source
  derivation
  source_identity
  observed_at
  expires_at?
  effective_from?
  effective_until?
  supporting_claim_ids[]
  content_sha256
}
```

### 5.3 Deterministic trust states

P0 trust states:

- `TRUSTED`
- `CONTESTED`
- `UNKNOWN`
- `STALE`
- `INCOMPLETE`
- `AGENT_ASSERTED`

No arbitrary probability or confidence percentage is permitted in P0.

Security rule:

> A security-critical fact may increase authority only when its resolved state is `TRUSTED` under the versioned Evidence Policy.

`CONTESTED`, `UNKNOWN`, `STALE`, `INCOMPLETE`, and `AGENT_ASSERTED` fail closed when the fact is required for authorization.

Weak evidence may remove authority; weak evidence MUST NOT create authority.

### 5.4 Metadata truth boundary

`TRUSTED` means **trusted under the declared evidence policy**, not objectively proven true in the real world.

Freshness, authentication, completeness of an API response, and lack of observed conflict do not prove semantic truth.

## 6. Disclosure Digital Twin

The existing disclosure ledger remains the persistence source of released semantic history. vNext MUST NOT create a competing privacy ledger.

The Disclosure Digital Twin is a deterministic projection/closure over:

- current candidate semantic exposure;
- previously released semantic information;
- principal/agent/subject privacy scope;
- task-purpose commitment;
- governance commitment;
- evidence-root commitment;
- warehouse/snapshot identity when available.

Canonical state:

```text
DisclosureState {
  scope
  purpose_commitment
  governance_commitment
  evidence_root_sha256
  warehouse_snapshot?
  released_atoms[]
  derived_atoms[]
  state_sha256
}
```

### 6.1 Hypergraph semantics

Information is represented as canonical `DisclosureAtom` nodes.

Inference rules are deterministic hyperedges:

```text
{A, B, C} -> D
```

After each transition the knowledge state is the deterministic least fixed point of prior knowledge, newly released atoms, and the declared inference rules.

No LLM participates in inference closure.

## 7. Forbidden-state predicates

P0 defines a finite, versioned set rather than attempting a universal definition of privacy.

Initial predicate families:

1. `DIRECT_SENSITIVE_LINKAGE`
2. `STABLE_LINKABLE_SENSITIVE_DISCLOSURE`
3. `SMALL_COHORT_SENSITIVE_DISCLOSURE`
4. `CROSS_RELEASE_COMPOSITION`
5. `TEMPORAL_DIFFERENCE_SIGNAL`
6. `UNTRUSTED_GOVERNANCE_AUTHORIZATION`

Every predicate MUST have:

- a canonical identifier/version;
- explicit required atoms/facts;
- positive tests;
- negative tests;
- adversarial/bypass tests;
- a claim boundary.

## 8. Prospective Privacy Model Checker (PPMC)

### 8.1 Formal-ish model

Let:

- `S` be the finite set of canonical disclosure states reachable under the instantiated bounded model;
- `A` be the finite instantiated Future Action Grammar;
- `T: S x A -> S | REJECT` be the deterministic transition function;
- `F(S)` be the declared forbidden-state predicate;
- `L(action, state)` be the existing local safety oracle plus required evidence checks;
- `B` be the configured search depth.

For candidate action `q0`, after constructing candidate state `s1`, PPMC asks whether there exists a sequence `a1..an`, `n <= B`, such that every modeled action is locally admissible and the resulting state satisfies a declared forbidden predicate.

### 8.2 Search algorithm

P0 uses deterministic bounded BFS.

Reasons:

- naturally returns a shortest-depth counterexample;
- simple deterministic implementation;
- no solver dependency;
- auditable transition semantics;
- easier replay and evidence generation.

P0 MUST NOT introduce Z3/SMT solely to implement PPMC.

### 8.3 Canonical state hashing

State identity MUST exclude irrelevant nondeterminism such as timestamps, random IDs, SQL formatting, and output aliases.

State identity MUST commit to relevant canonical semantics including:

- scope;
- purpose commitment;
- governance/evidence root;
- snapshot identity when modeled;
- released semantic atoms;
- derived atoms;
- model/predicate versions required to interpret the state.

### 8.4 Resource exhaustion

Search budgets are part of the security model. Exhaustion MUST fail closed.

Initial engineering targets, to be pre-registered and then measured honestly:

- default depth: `3`;
- hard configurable maximum depth: `5`;
- default maximum states: `10,000`;
- hard maximum states: `50,000`;
- default instantiated actions per state: `<= 32`.

These are targets/limits, not benchmark results.

## 9. Future Action Grammar

The Agent MUST NOT own the grammar.

The grammar is security-owned, finite, versioned, and instantiated from governed schema plus declared task/policy scope.

P0 action classes may include:

- semantic replay;
- add/remove one governed projection from a finite relevant set;
- add/remove a group key from a finite relevant set;
- change an aggregate among a fixed allowlist when valid;
- apply a declared cohort-variant family;
- apply a modeled snapshot transition.

P0 MUST NOT perform unrestricted arbitrary SQL generation or arbitrary literal synthesis during model checking.

The exact grammar and parameters are frozen before held-out evaluation.

## 10. Counterexample trace

A PPMC counterexample MUST be deterministically replayable and contain at least:

```text
CounterexampleTrace {
  initial_state_sha256
  candidate_action_commitment
  future_actions[]
  terminal_state_sha256
  violated_predicates[]
  bound
  depth
  grammar_version
  grammar_sha256
  trace_sha256
}
```

## 11. Counterfactual Privacy Cut Compiler (CPCC)

CPCC runs only after a PPMC counterexample.

P0 performs exhaustive deterministic search over a finite remediation space.

Initial operator families:

- remove stable identifier;
- remove sensitive projection;
- remove a declared projection;
- coarsen a quasi-identifier using a pre-declared trusted transformation;
- aggregate a sensitive field using a pre-declared operator;
- add a minimum distinct-subject threshold;
- increase an existing trusted subject threshold.

An unavailable trusted transformation means that remediation operator is unavailable; the system MUST NOT ask an LLM to invent one and trust it.

Every candidate repair MUST be:

```text
GENERATE
-> REPARSE
-> REGROUND
-> REBUILD EVIDENCE
-> LOCAL POLICY EVALUATION
-> REBUILD DISCLOSURE STATE
-> PPMC
```

Only a candidate that passes the complete chain is eligible.

### 11.1 Optimization claim

CPCC may claim only:

> Minimum-cost safe intervention among the enumerated remediation candidates under the committed remediation space, cost model, and prospective model.

It MUST NOT claim globally optimal SQL repair.

### 11.2 Cost model

P0 uses deterministic integer/tuple costs, not ML or post-hoc fuzzy utility.

Recommended canonical comparison:

```text
(goal_loss, information_loss, structural_change, canonical_candidate_hash)
```

The actual weights/ranks are pre-registered before held-out evaluation.

## 12. Privacy Proof Capsule

The proof artifact is machine-verifiable evidence for ToxicJoin's declared model; it is not a general mathematical proof of privacy.

### 12.1 Pre-execution proof

At minimum commits to:

- request/principal identity commitment;
- intent/task-purpose commitment;
- original and effective SQL commitments;
- query-plan commitment;
- governance binding;
- Evidence Policy and evidence-root commitment;
- disclosure-state commitment;
- policy version/config commitment;
- Future Action Grammar version/hash;
- PPMC bound/result;
- counterexample commitment when present;
- remediation-space/cost-model/selected-repair commitments when used;
- proof content hash.

### 12.2 Execution binding

The existing single-use execution authorization MUST eventually bind the exact pre-execution privacy-proof commitment before vNext can claim end-to-end proof binding.

PPMC success by itself MUST NEVER be accepted as execution authority.

### 12.3 Final capsule

After execution/release verification, the final capsule may additionally bind:

- execution authorization commitment;
- post-execution verification checks;
- execution query commitment;
- disclosure commitment/finalization;
- receipt identifier/content commitment;
- DataHub Decision write-back commitment when performed;
- capsule content hash and keyed integrity protection.

P0 reuses the existing HMAC trust model with explicit domain separation unless a later threat model proves a need for public-key attestation.

## 13. Persistence model

P0:

- existing disclosure SQLite remains authoritative for release history;
- existing receipt store remains authoritative for decision/execution receipts;
- PPMC search graph is ephemeral;
- proof capsules are canonical append-only artifacts with restrictive filesystem permissions;
- evidence claims may remain request-local while their canonical evidence root and security-relevant summaries are committed into proof artifacts;
- no new graph database is introduced.

Persisted PPMC evidence contains metrics and commitments, not the full in-memory search graph unless an explicit evidence case requires a bounded trace.

## 14. Proposed module boundaries

```text
src/toxicjoin/
  evidence/
    models.py
    policy.py
    resolver.py
    canonical.py
  prospective/
    atoms.py
    state.py
    inference.py
    grammar.py
    transition.py
    counterexample.py
    ppmc.py
  repair/
    models.py
    operators.py
    cost.py
    compiler.py
  proofs/
    models.py
    canonical.py
    builder.py
    verifier.py
  agent/
    models.py
    planner.py
    runtime.py
```

Existing modules are not moved merely for aesthetic refactoring.

## 15. Threat-model delta summary

vNext adds at least these threat classes:

- metadata poisoning that is fresh/authenticated but semantically wrong;
- conflicting governance authorities;
- Agent self-authorization through metadata writes;
- future-query composition not unsafe at the current local step;
- modeled-grammar blind spots;
- PPMC state explosion / resource exhaustion;
- repair that removes one counterexample but creates another disclosure path;
- proof/candidate/state substitution;
- evidence/proof TOCTOU before execution;
- incomplete proof-revocation propagation in P1.

The complete delta is maintained in `docs/vnext/threat-model-delta.md`.

## 16. Security invariants

1. Agent never authorizes governed execution.
2. Non-`TRUSTED` security-critical evidence cannot increase authority.
3. Local `ALLOW` is necessary but not sufficient for prospective `ALLOW` when PPMC is enabled.
4. PPMC result is bound to exact state, evidence root, policy/model, grammar, and bound.
5. PPMC/model-checking exhaustion fails closed.
6. Every counterexample is replayable.
7. Every CPCC repair is fully reparsed, regrounded, reevaluated, and prospectively rechecked.
8. Execution authorization binds the exact accepted proof state before end-to-end proof binding is claimed.
9. Existing post-execution verification remains the final result-release gate.
10. Historical validity at execution is immutable; P1 current-governance validity is a separate revocable status.

## 17. Test strategy

Every security feature requires:

- positive test;
- negative test;
- bypass test;
- adversarial test;
- regression test;
- threat-model delta;
- deterministic evidence artifact;
- explicit claim boundary;
- ablation when causality is part of the claim.

New adversarial families include:

- classification mutation/conflict;
- lineage addition/deletion/truncation;
- stale context;
- agent-authored false governance;
- future-query permutations;
- modeled snapshot changes;
- proof-state and grammar-hash substitution;
- repair-cost tampering;
- rewrite mutation after checking;
- purpose/intent drift where purpose becomes security relevant.

## 18. Scientific evaluation

The evaluation protocol is pre-registered in `docs/vnext/preregistration.md` before runtime implementation begins.

Mandatory comparison configurations:

- current baseline;
- baseline + Evidence Layer;
- Evidence + PPMC where counterexample means blunt BLOCK;
- full P0 with CPCC and proof path.

Mandatory ablations include removal of:

- DataHub lineage;
- sensitivity governance;
- evidence-state resolution (metadata present => trusted);
- disclosure history;
- PPMC;
- CPCC;
- proof-to-authorization binding once implemented.

Primary security target:

> zero unsafe effective executions within the frozen declared evaluation corpus.

This is not a real-world universal accuracy claim.

## 19. Performance budgets

Initial pre-registered engineering targets, not measured results:

- Evidence resolution excluding external network latency: p95 <= 25 ms;
- disclosure state + deterministic closure: p95 <= 25 ms;
- default PPMC bound: p95 <= 500 ms;
- proof verification: p95 <= 100 ms;
- CPCC: p95 <= 2 s.

LLM and external network/DataHub latency are reported separately from deterministic kernel latency.

## 20. Rollout and rollback

`main` remains the rollback-safe baseline.

vNext is developed through small reviewable branches/PRs. No monolithic runtime rewrite is permitted.

Recommended sequence:

1. research/specification freeze;
2. Evidence Layer;
3. Disclosure Digital Twin;
4. Future Action Grammar;
5. PPMC;
6. hard counterexample gate;
7. CPCC;
8. Privacy Proof Capsule + verifier;
9. proof commitment -> authorization binding;
10. Governed Agent MVP;
11. full real DataHub path;
12. frozen evaluation;
13. red-team closure;
14. final feature freeze.

P1/P2 functionality that does not satisfy its proof gate remains experimental or out of the submission runtime.

## 21. Day-8 hard gate

Before CPCC or P1 can be treated as justified scope, ToxicJoin MUST demonstrate at least one reproducible scenario satisfying all of the following:

1. the current/local safety evaluation allows the candidate;
2. existing current-state/history controls do not already block it for the same reason;
3. after admitting the candidate, a sequence within the declared bounded grammar reaches a declared forbidden disclosure state;
4. PPMC returns a deterministic replayable counterexample trace;
5. the scenario is plausible enough to represent a meaningful modeled agent/data workflow rather than a contrived tautology.

If this gate fails, the project MUST revise the state/grammar model before proceeding to CPCC or reduce the vNext claim. Feature count is not a substitute for this result.
