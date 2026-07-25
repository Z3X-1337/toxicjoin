# CPCC Constrained Compiler + Full Validator — P0 Boundary Note

This slice implements the second Day-9 CPCC layer: a conservative SQL compiler plus a real security-side candidate validator that replays the entire frozen validation chain.

## Compiler profile

The compiler accepts only one root `SELECT`, no wildcard projection, and only transformations represented by the committed CPCC candidate. Field-scoped operations bind `(DataHub dataset URN, field_path)` to exactly one single-source root projection using the original fully resolved governance context.

Supported transforms in compiler v0.1:

- `REMOVE_STABLE_IDENTIFIER`
- `REMOVE_SENSITIVE_PROJECTION`
- `REMOVE_PROJECTION(field)`
- `AGGREGATE_SENSITIVE(field, COUNT|COUNT_DISTINCT)` when the target is the only root projection
- `ADD_MINIMUM_GROUP_THRESHOLD(k)` using the existing fail-closed rewriter
- `INCREASE_MINIMUM_GROUP_THRESHOLD(k)` using the existing fail-closed rewriter

`COARSEN_QI` remains part of the committed remediation grammar but is deterministically `GENERATE`-ineligible in compiler v0.1. The current normalized governance model does not preserve trusted field-type provenance; emitting `DATE_TRUNC` from category alone could create SQL that parses but fails bind/runtime. P0 therefore refuses to guess.

Likewise, `AGGREGATE_SENSITIVE` rejects mixed root projections rather than fabricating GROUP BY semantics. A multi-action candidate may first remove other projections and then aggregate the remaining sensitive projection because compiler phases are security-owned and deterministic.

## Full candidate chain

`DataHubCpccCandidateValidator` owns the trusted inputs. Candidate content never supplies governance, evidence, policy decisions, Twin state, or PPMC results.

For every candidate it performs:

1. `GENERATE`: constrained compiler using original trusted governance only for exact target binding;
2. `REPARSE`: `analyze_sql` on generated SQL;
3. `REGROUND`: fresh resolution through the exact bound `DataHubSnapshotContextResolver`;
4. `REBUILD_EVIDENCE`: rebuild `DataHubEvidenceBundle` from the exact trusted snapshot/settings and independently replay-validate the derivation bundle;
5. `LOCAL_POLICY`: reconstruct `PolicyInput` from the new resolution and invoke the unchanged `PolicyEngine`; only `ALLOW` proceeds;
6. `REBUILD_DISCLOSURE_STATE`: rebuild semantic release, scope, composition, and immutable Twin from the supplied disclosure history;
7. `PPMC`: instantiate a new grammar from the repaired state and rerun bounded PPMC with the real `PolicyEngineLocalOracle`.

Before running PPMC, the validator independently checks that a grammar `REPLAY` of the repaired semantic release produces the same PolicyEngine decision/reason codes as the direct local-policy stage. Drift is `FAIL_CLOSED`.

## Evidence and governance boundary

DataHub evidence is rebuilt for every candidate, even though candidates using the same frozen snapshot may produce the same evidence root. Rebuilding is deliberate: the full-chain artifact proves each candidate traversed the declared stage instead of inheriting a caller-provided hash.

The PPMC governance trust bit is a constructor-level security-side input, never a candidate/agent field. Its trust-evidence commitment binds the replay-validated DataHub derivation validation. This remains an internal model assertion, not execution authorization and not a claim that DataHub metadata is objectively true.

## Candidate outcomes

- deterministic compiler non-applicability is `INELIGIBLE / GENERATE`;
- local `REWRITE` or `BLOCK` is `INELIGIBLE / LOCAL_POLICY` with the real decision commitment;
- PPMC `PROSPECTIVE_UNSAFE` is `INELIGIBLE / PPMC` with the PPMC result commitment;
- any unexpected compiler failure, parse failure, governance/evidence uncertainty, state rebuild failure, oracle drift, PPMC exception, or PPMC `FAIL_CLOSED` makes that candidate `FAIL_CLOSED`, which causes the entire CPCC run to fail closed.

Only a candidate with local `ALLOW` and PPMC `NO_COUNTEREXAMPLE_WITHIN_BOUND` receives `ELIGIBLE_SAFE`.

## Optimization boundary

The compiler/validator does not change the CPCC core claim. The selected intervention is only minimum declared cost among the complete finite candidate set that this exact compiler and full validation model can deterministically resolve as safe. Unsupported compiler profiles are explicit ineligible candidates; uncertain security validation aborts selection.

This slice does not execute repaired SQL and does not connect CPCC to authorization. Existing execution verifier/quarantine/release verification remain unchanged.
