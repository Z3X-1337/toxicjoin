# ToxicJoin vNext Scientific Pre-registration

Status: **pre-implementation research contract**

Date frozen: 2026-07-25

Tracking issue: #72

This document exists to prevent post-result metric selection, threshold tuning, corpus relabeling, or claim inflation.

No vNext experimental result is recorded in this file. All numeric results must come from reproducible artifacts generated after implementation.

## 1. Research question

Does adding deterministic evidence-state resolution and bounded prospective disclosure-state reachability to the existing ToxicJoin runtime detect and safely remediate security-relevant cases that the current local/current-history authorization path cannot identify, while preserving a measurable amount of legitimate task utility?

## 2. Fixed claim boundary

The evaluation concerns only:

- the declared ToxicJoin SQL/policy profile;
- the declared synthetic/live DataHub test topology;
- the frozen scenario corpus;
- the declared Future Action Grammar;
- the declared PPMC bound and resource budgets;
- the declared finite CPCC remediation space and cost model.

Results do not establish universal privacy, arbitrary-SQL verification, Differential Privacy, complete future-action coverage, or real-world detection accuracy outside the declared corpus.

## 3. Hypotheses

### H1 — Evidence-state enforcement

When security-relevant governance/lineage context is intentionally poisoned, contested, stale, incomplete, or available only as an Agent assertion, the Evidence Layer prevents that context from being treated as trusted authorization truth.

Primary H1 failure condition:

- any planted non-trusted critical claim causes an execution that depends on treating that claim as trusted.

### H2 — Prospective reachability

For planted scenarios in which the current candidate is locally admissible but a declared forbidden disclosure state is reachable through a modeled future-action sequence within the frozen bound, PPMC returns a deterministic replayable counterexample.

Primary H2 failure conditions:

- a planted in-grammar forbidden path exists within the bound but no counterexample is returned;
- returned trace cannot be replayed to the same forbidden predicate/state commitments.

### H3 — Counterfactual repair utility

On the same PPMC-counterexample cases, CPCC preserves more legitimate task utility than a policy that always converts a PPMC counterexample directly into `BLOCK`, while remaining safe under the same frozen local-policy and PPMC model.

H3 is evaluated only inside the declared finite remediation and cost space.

Primary H3 failure conditions:

- CPCC selects a candidate that does not survive full reparse/reground/local-policy/PPMC validation;
- selected candidate is not the deterministic minimum according to the frozen cost ordering;
- CPCC produces no utility improvement over blunt `BLOCK` on the held-out repairable cases.

### H4 — Agent authority separation

An unsafe, malformed, prompt-injected, or strategically adversarial Agent proposal cannot bypass the deterministic ToxicJoin authorization chain.

Primary H4 failure condition:

- any tested Agent-controlled field or plan transition reaches effective execution without the required security-authoritative checks.

### H5 — Proof revocation propagation (P1 only)

If Living Proofs are implemented, changing a security-relevant evidence/governance claim invalidates every and only proof reachable from that claim in the declared dependency DAG.

H5 is not required for P0 success and MUST NOT be reported as implemented unless P1 is actually completed and evaluated.

### H6 — DataHub causal necessity

For scenarios intentionally constructed to require DataHub governance or lineage, removing or mutating that dependency changes the relevant trusted context and therefore changes the decision/proof state or causes deterministic fail-closed behavior.

Primary H6 failure condition:

- an ablation removes the relevant DataHub dependency but the supposedly dependency-sensitive case remains indistinguishable because ToxicJoin actually did not require that context.

## 4. Systems under comparison

The evaluation will preserve the same scenario inputs when comparing configurations.

### B0 — Current baseline

Current ToxicJoin runtime without vNext prospective features.

### B1 — Evidence only

B0 + deterministic Evidence Layer.

### B2 — Prospective blunt-block baseline

B1 + Disclosure Digital Twin + PPMC. Any PPMC counterexample becomes `BLOCK`; CPCC disabled.

### B3 — Full P0

B2 + CPCC + Privacy Proof Capsule path.

The existing local policy kernel is not rewritten merely to improve vNext results.

## 5. Mandatory ablations

Ablations are causal tests, not marketing variants.

- A1: remove DataHub column lineage from the relevant decision context;
- A2: remove sensitivity governance from the relevant decision context;
- A3: replace Evidence Policy with unsafe `metadata-present => trusted` behavior in an isolated evaluation-only variant;
- A4: remove prior disclosure history from the prospective state;
- A5: disable PPMC while retaining other applicable vNext components;
- A6: retain PPMC but disable CPCC and blunt-block counterexamples;
- A7: remove proof-to-authorization commitment binding once that binding exists.

Ablation code MUST NOT enter the production execution path except through explicit evaluation-only configuration/test harnesses.

## 6. Corpus split

### 6.1 Development corpus

A mutable development corpus is used for implementation, debugging, and model/grammar construction.

Development results are not headline security results.

### 6.2 P0 held-out corpus

Before the first held-out execution, a manifest MUST be committed containing:

- exactly 30 held-out P0 scenarios;
- stable scenario IDs;
- expected security labels/forbidden predicates;
- exact metadata mutation instructions;
- exact modeled future-action seeds or generation constraints;
- exact repairability labels;
- corpus content SHA-256;
- Future Action Grammar version/hash;
- forbidden-predicate version/hash;
- Evidence Policy version/hash;
- PPMC bound and resource limits;
- CPCC remediation-space and cost-model version/hash.

The 30 cases are allocated before results are opened across the P0 research questions as follows:

- 6 evidence trust/conflict/incompleteness cases;
- 6 prospective future-disclosure cases;
- 6 CPCC repair cases;
- 6 Agent authority/bypass cases;
- 6 DataHub causal-dependency/ablation cases.

A scenario may exercise more than one mechanism, but its primary allocation and expected outcome are fixed in the manifest.

### 6.3 P1 held-out corpus

If P1 Living Proofs is implemented, its evaluation receives a separate frozen manifest before P1 held-out execution. P1 results do not modify or replace P0 results.

## 7. No-peeking rule

After the P0 held-out manifest is committed and its hash recorded:

- held-out expected outcomes MUST NOT be changed in response to observed runtime behavior;
- Future Action Grammar MUST NOT be tuned against held-out failures and then rerun under the same evaluation version;
- PPMC bound/cost model/remediation weights MUST NOT be changed and silently reported as the original evaluation;
- scenario deletion after failure is prohibited.

If a legitimate implementation defect requires a change after held-out opening, the original result is retained and a new evaluation version/corpus hash is created. The old failure is not erased.

## 8. Primary safety metric

```text
unsafe_effective_executions
```

Target invariant:

> `unsafe_effective_executions == 0` within the frozen declared evaluation corpus.

An unsafe effective execution is any case labeled `MUST_NOT_EXECUTE` or equivalent by the frozen oracle that reaches effective released execution.

This target is corpus-scoped and MUST NOT be restated as 100% real-world protection.

## 9. Additional metrics

### Security/evidence

- planted critical evidence conflicts detected;
- planted stale/incomplete/agent-only critical evidence rejected;
- planted bounded future counterexamples detected;
- counterexample replay success;
- Agent bypass attempts reaching execution;
- proof verification failures by mutation type;
- revocation false negatives/false positives if P1 is evaluated.

### Utility

- task completion rate under B0/B1/B2/B3;
- repair success count/rate on frozen repairable cases;
- deterministic repair cost;
- legitimate tasks converted to BLOCK;
- effective ALLOW/REWRITE/BLOCK counts.

### Search complexity

- PPMC nodes explored;
- PPMC transitions evaluated;
- maximum frontier size;
- deduplicated state count;
- CPCC candidates enumerated;
- CPCC candidates fully evaluated;
- resource-budget exhaustion count.

### Performance

Report deterministic p50/p95 separately for:

- Evidence resolution excluding external network latency;
- disclosure state/closure;
- PPMC;
- CPCC;
- proof verification;
- existing local kernel where useful for comparison.

LLM, DataHub network, and other external network latency MUST be reported separately and MUST NOT be blended into deterministic-kernel latency.

## 10. Pre-registered engineering budgets

These are engineering targets and fail-closed limits, not measured claims:

- Evidence resolution excluding external network: p95 target <= 25 ms;
- disclosure state + closure: p95 target <= 25 ms;
- default PPMC bound: p95 target <= 500 ms;
- proof verification: p95 target <= 100 ms;
- CPCC: p95 target <= 2 s;
- default PPMC depth: 3;
- hard PPMC depth ceiling: 5;
- default PPMC state ceiling: 10,000;
- hard PPMC state ceiling: 50,000;
- default instantiated action ceiling per state: 32.

A model-checking budget exhaustion is a fail-closed security outcome, not a safe result.

## 11. Day-8 hard gate

PPMC is justified as a flagship contribution only if, by the gate, at least one reproducible development/evidence scenario demonstrates:

1. current/local ToxicJoin admits the candidate;
2. the existing current-state/history control does not already block the same case for the same reason;
3. after admitting the candidate, a sequence in the declared finite grammar reaches a declared forbidden state within the bound;
4. PPMC emits a deterministic replayable counterexample;
5. the scenario represents a meaningful modeled agent/data workflow rather than a tautological construction.

If this gate fails:

- CPCC does not proceed as a flagship feature;
- P1 does not start;
- the state model/grammar is revised or the research claim is reduced.

## 12. CPCC success criteria

For each held-out case labeled repairable:

- selected repair is in the frozen remediation space;
- reparsing succeeds;
- governance/evidence are rebuilt from the repaired query;
- local policy is satisfied;
- PPMC returns no declared counterexample within the same frozen model/bound;
- the selected repair has the minimum frozen deterministic cost among all eligible safe candidates;
- final execution still passes the existing independent authorization/verifier/release path.

## 13. Determinism protocol

For deterministic components, repeated runs over the same committed inputs MUST reproduce:

- evidence-state resolution;
- canonical disclosure-state hash;
- instantiated action ordering;
- PPMC result and counterexample trace hash;
- CPCC selected candidate and cost;
- proof verification result.

Variable wall-clock timing is measured but MUST NOT participate in semantic/proof identity.

## 14. Evidence artifact requirements

Each evaluation artifact MUST identify at least:

- exact Git commit SHA;
- policy version/hash;
- Evidence Policy version/hash;
- grammar version/hash;
- forbidden-predicate version/hash;
- PPMC bound/resource budgets;
- remediation/cost-model version/hash when applicable;
- corpus manifest hash;
- scenario count and IDs;
- raw aggregate counts required to recompute reported rates;
- sanitized failure details sufficient for reproduction without raw sensitive rows.

## 15. Statistical reporting

The planned held-out corpus is a deterministic security/evaluation corpus, not a random sample of all real-world agent behavior.

Therefore:

- exact counts and corpus-scoped rates are primary;
- no population-generalized confidence claim is made unless a later sampling design justifies it;
- percentages MUST always be accompanied by numerator/denominator when reported;
- no significance test is added post hoc merely to make a result appear stronger.

## 16. Reporting failures

Failures remain part of the evidence record.

A failed hypothesis may cause scope reduction, but the project MUST NOT:

- relabel the failure as success;
- delete difficult held-out scenarios;
- hide unsafe executions;
- merge experimental code solely to improve the demo;
- claim a mechanism was proven when its preregistered gate failed.
