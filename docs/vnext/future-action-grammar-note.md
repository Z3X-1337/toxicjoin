# Future Action Grammar — P0 Boundary Note

This slice implements the finite security-owned Future Action Grammar and deterministic `T(S, A) -> S' | REJECT` transition function required by the frozen vNext design. It does **not** implement BFS/PPMC yet and does not enter runtime authorization.

## No arbitrary future SQL or literals

The prospective layer never asks an LLM or Agent to invent future SQL, predicates, identifiers, field names, aggregate names, cohort literals, or warehouse snapshots.

The grammar is instantiated from a canonical trusted context containing:

- one validated initial `DisclosureState` commitment and its scope/purpose/governance/evidence universe;
- one complete base semantic release;
- canonical composition metadata only when the base release is protected;
- an optional trusted cohort seed commitment for variants that may become protected;
- a finite governed set of projection fields;
- a finite governed quasi-identifier set for possible group keys;
- a fixed supported aggregate universe narrowed by a security-owned allowlist;
- finite predeclared cohort commitments for an already-protected base release;
- finite directed warehouse snapshot edges.

The context, every action, and the complete grammar are canonically hashed. `FutureActionGrammar` does not trust a supplied action list merely because its hash is internally consistent: validation regenerates the expected action set from the committed context and requires exact equality.

## Action semantics

P0 currently instantiates these complete semantic release variants:

- `REPLAY`;
- `ADD_PROJECTION` for a governed declared field;
- `REMOVE_PROJECTION` for a single-source raw/linkable projection when at least one output remains;
- `ADD_GROUP_KEY` for a declared governed quasi-identifier;
- `DROP_GROUP_KEY` when the resulting release still has an output;
- `CHANGE_AGGREGATE` within the fixed `AVG/COUNT/MAX/MIN/SUM` universe and the declared allowlist;
- `COHORT_VARIANT` for a predeclared cohort commitment on an already-protected base release;
- `SNAPSHOT_ADVANCE` only across an explicitly declared directed `from -> to` snapshot edge.

Actions are complete semantic variants, not free-form deltas. This keeps transition semantics deterministic and auditable.

## Composition and cohort boundary

Canonical runtime semantics are preserved:

- an unprotected release carries `composition=None`;
- a protected release requires composition whose family hash matches the semantic release;
- a protected base uses its existing cohort HMAC as the cohort seed;
- an unprotected base may provide a trusted cohort seed separately if a declared future variant could become protected;
- if a future variant becomes protected but no trusted cohort seed exists, grammar instantiation fails closed rather than inventing a cohort;
- cohort-variant actions are not available for an unprotected base.

## Twin model-universe binding

The grammar context commits the initial state hash, privacy scope hash, purpose commitment, governance commitment, evidence root, base warehouse snapshot, and exact direct-atom set of the base release.

A transition rejects a state outside this universe. Successor states remain usable because disclosure knowledge is monotonic and must retain the base release atoms. Directed snapshot transitions are validated for reachability from the base snapshot and each `SNAPSHOT_ADVANCE` action requires the current state snapshot to equal its declared source.

## Security-owned grammar boundary

The Agent may propose or adapt a task, but it does not choose the final grammar authority. The finite governed field set, group-key set, aggregate allowlist, cohort commitments, snapshot graph, cohort seed, and model-universe commitments must come from trusted deterministic components.

A valid grammar or action hash is an integrity commitment, not an authenticated capability and not an execution authorization. The later PPMC layer must consume a trusted grammar instance and the existing local policy oracle must still determine whether each action is locally admissible.

## Resource bound

P0 allows at most 32 distinct instantiated actions. Exceeding the action budget raises `FutureActionGrammarError`; actions are never silently truncated.

This slice does not modify `Pipeline`, `PolicyEngine`, execution authorization, the disclosure ledger, `EvidencePolicy`, DataHub MCP behavior, or the existing verifier.