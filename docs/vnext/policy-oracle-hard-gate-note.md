# PolicyEngine Oracle + Day-8 PPMC Hard Gate — P0 Boundary Note

This slice binds the PPMC local-admissibility boundary to the unchanged existing `PolicyEngine` and produces an explicit machine-readable Day-8 hard-gate artifact.

## Why semantic-only reconstruction is insufficient

`DisclosureSemanticRelease` intentionally drops SQL aliases and raw values, but it also does not carry `ColumnContext.lineage_sources`. The existing `PolicyEngine` computes effective categories from both the governed column and its lineage. Reconstructing policy input from the semantic release alone could therefore understate risk.

The adapter instead requires a trusted, alias-insensitive `PolicyOracleGovernanceContext` built from normalized resolver output. It preserves tags, glossary terms, dataset URNs, categories, and full classified lineage. Every semantic column must match this trusted governance context before the adapter invokes `PolicyEngine`.

## Local admissibility

For release actions:

1. the exact action must belong to the bound `FutureActionGrammar`;
2. the current Twin state must match the grammar scope/purpose/governance/evidence commitments and a reachable declared snapshot;
3. semantic columns must match the trusted governance context;
4. a provider-neutral `PolicyInput` is reconstructed deterministically;
5. the unchanged `PolicyEngine.evaluate()` is called;
6. only `Decision.ALLOW` is locally admissible.

`REWRITE` and `BLOCK` are not treated as admissible releases. A rewritten release would need to exist as a separately modeled semantic action and be re-evaluated.

`SNAPSHOT_ADVANCE` is not a data release and is not presented as a PolicyEngine decision. It is locally admissible only as the exact security-owned directed transition already committed by the grammar.

## Day-8 hard-gate experiment

The deterministic fixture starts from real SQL analysis and fixture governance:

```sql
SELECT COUNT(diagnosis) AS diagnosis_count
FROM patients
HAVING COUNT(DISTINCT customer_id) >= 20
```

The canonical policy currently requires minimum group size 20. The existing local `PolicyEngine` returns `ALLOW` for this thresholded aggregate. The adapter independently reconstructs the same governed semantics and also obtains `ALLOW`.

PPMC is then given one declared warehouse transition from snapshot A to snapshot B. The identical aggregate replay at snapshot B is again individually `ALLOW` under the existing local kernel. Nevertheless, bounded BFS finds the two-step path:

`SNAPSHOT_ADVANCE -> REPLAY`

and terminates with F5 `TEMPORAL_DIFFERENCING` matched.

The gate passes only if:

- the direct pipeline-style current PolicyEngine decision is `ALLOW`;
- the adapter decision for the current identical replay matches that local decision;
- the future replay at snapshot B is also `ALLOW`;
- PPMC returns `PROSPECTIVE_UNSAFE`;
- the shortest counterexample depth is exactly 2;
- the trace action kinds are exactly `SNAPSHOT_ADVANCE, REPLAY`;
- the terminal matched predicates include F5;
- the trace replay step carries the same local-oracle commitment independently checked against the PolicyEngine replay decision.

CI writes `ppmc-hard-gate.json` plus its SHA-256 commitment and uploads them as the `toxicjoin-ppmc-hard-gate` artifact. Failure to demonstrate any condition makes the CI generation step fail.

## Claim boundary

A passing artifact demonstrates the preregistered systems claim for this exact declared model: an action can be locally acceptable under the existing deterministic kernel while a bounded future composition is unsafe. It does **not** prove global privacy, arbitrary future SQL coverage, universal metadata truth, Differential Privacy, or completeness beyond the declared grammar and bound.

This slice still does not connect PPMC to execution authorization. Authorization integration remains a later gate.
