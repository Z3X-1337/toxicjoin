# CPCC Core — P0 Finite Remediation Contract

This slice introduces only the deterministic search/selection core of the Counterfactual Privacy Cut Compiler. It does not yet mutate SQL and does not enter execution authorization.

## Finite operator set

P0 recognizes only these remediation families:

- `REMOVE_STABLE_IDENTIFIER`
- `REMOVE_SENSITIVE_PROJECTION`
- `REMOVE_PROJECTION(field)`
- `COARSEN_QI(field, trusted_transform)`
- `AGGREGATE_SENSITIVE(field, trusted_aggregate)`
- `ADD_MINIMUM_GROUP_THRESHOLD(k)`
- `INCREASE_MINIMUM_GROUP_THRESHOLD(k)`

Trusted QI transformations are currently restricted to the security-owned enum `DATE_TO_MONTH` and `DATE_TO_YEAR`. Trusted sensitive aggregates are restricted to `COUNT` and `COUNT_DISTINCT`. The later SQL compiler may reject an otherwise declared action when the target SQL/type/shape cannot be transformed without ambiguity.

## P0 candidate width and budget

A committed remediation space contains at most 32 atomic actions. P0 enumerates every one-action and every two-action candidate, for a hard maximum of 528 candidates.

The two-action limit is part of this P0 model, not a claim that wider interventions are unnecessary. Any future increase changes the committed remediation model/version and requires separate validation.

CPCC performs no hidden compatibility pruning. Semantically incompatible pairs remain part of the enumerated space and must be rejected explicitly by the future compiler/validator at the `GENERATE` stage. This makes the optimization claim auditable.

## Frozen ordinal cost model

P0 uses the lexicographic tuple `(goal_loss, information_loss, structural_change, candidate_sha256)`.

Atomic costs are:

| Operator | goal_loss | information_loss | structural_change |
| --- | ---: | ---: | ---: |
| `ADD_MINIMUM_GROUP_THRESHOLD` | 0 | 1 | 1 |
| `INCREASE_MINIMUM_GROUP_THRESHOLD` | 0 | 1 | 1 |
| `COARSEN_QI` | 1 | 2 | 1 |
| `AGGREGATE_SENSITIVE` | 2 | 3 | 2 |
| `REMOVE_STABLE_IDENTIFIER` | 3 | 4 | 1 |
| `REMOVE_PROJECTION` | 4 | 4 | 1 |
| `REMOVE_SENSITIVE_PROJECTION` | 5 | 5 | 1 |

Two-action costs are component-wise sums. The canonical candidate SHA-256 is the final tie-breaker.

These are declared ordinal engineering costs for this P0 experiment. They are not learned utility, user preference, or a claim of globally correct semantic value.

## Mandatory validation artifact

The core accepts a candidate as `ELIGIBLE_SAFE` only when the security-authoritative validator commits the complete chain:

`GENERATE -> REPARSE -> REGROUND -> REBUILD_EVIDENCE -> LOCAL_POLICY -> REBUILD_DISCLOSURE_STATE -> PPMC`

An eligible candidate must carry commitments for generated SQL, reparsed plan, regrounded governance, evidence root, local PolicyEngine decision, rebuilt Twin state, and PPMC result. The local decision must be `ALLOW` and PPMC must be `NO_COUNTEREXAMPLE_WITHIN_BOUND`.

Any validator exception, malformed validation artifact, or candidate-hash mismatch makes the entire CPCC run `FAIL_CLOSED` rather than silently skipping that candidate.

## Exhaustive selection semantics

CPCC evaluates the complete committed candidate list before selection; it does not stop when it finds an apparently cheap safe repair. After all candidates are validated, it selects the eligible candidate with minimum declared lexicographic cost.

The supported claim is therefore only:

> Minimum-cost safe intervention among the fully enumerated and fully validated candidates under the committed P0 remediation space, cost model, and prospective model.

This is not globally optimal SQL repair.

## Next slice

The next CPCC slice must implement the constrained SQL compiler and a real full-chain validator. It must reuse the existing fail-closed minimum-group rewriter where applicable, must not accept arbitrary LLM-generated transformations, and must reparse/reground/rebuild evidence/re-evaluate PolicyEngine/rebuild the Twin/re-run PPMC for every candidate.
