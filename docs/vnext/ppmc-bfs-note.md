# PPMC Bounded BFS — P0 Boundary Note

This slice implements the frozen P0 Prospective Privacy Model Checker as deterministic bounded breadth-first search over the existing finite Future Action Grammar.

## Result semantics

The checker returns only:

- `PROSPECTIVE_UNSAFE` with a replayable shortest-depth `CounterexampleTrace`;
- `NO_COUNTEREXAMPLE_WITHIN_BOUND` after exhaustive exploration of the declared locally-admissible model within the committed bound;
- `FAIL_CLOSED` when the checker cannot justify either result because a security predicate is indeterminate, the state budget is exhausted, the local oracle fails, an unexpected transition fails, or forbidden-state evaluation fails.

`NO_COUNTEREXAMPLE_WITHIN_BOUND` is not a proof of global privacy or complete future-action coverage.

## Search bounds

P0 keeps the preregistered limits:

- default depth `3`;
- hard maximum depth `5`;
- default maximum search nodes `10,000`;
- hard maximum search nodes `50,000`;
- Future Action Grammar remains capped at `32` actions.

Budget exhaustion fails closed.

## Path-sensitive state identity

F5 temporal differencing is path-sensitive. Two paths may reach the same `DisclosureState.state_sha256` while carrying different sensitive-release/snapshot knowledge. PPMC therefore deduplicates on:

`(DisclosureState.state_sha256, temporal_signature_sha256)`

where the temporal signature commits the canonical set of observed `(sensitive release semantic SHA-256, warehouse snapshot SHA-256)` pairs. The configured state budget therefore counts effective path-sensitive search nodes, not only unique Twin hashes.

Repeated identical release observations at the same snapshot do not create a new temporal search identity.

## Historical temporal provenance

The existing disclosure ledger does not preserve a warehouse snapshot for each historical release. If the initial Twin contains a historical sensitive output outside the committed base release, PPMC does not fabricate temporal provenance: F5 is evaluated with missing path context and the run fails closed as indeterminate unless another already-known forbidden predicate is sufficient to establish `PROSPECTIVE_UNSAFE`.

## Local policy boundary

PPMC consumes local admissibility through a trusted in-process `LocalAdmissibilityOracle`. Each decision binds the exact pre-state and action plus canonical reason codes. The decision hash is an integrity commitment only; it is not authentication and a serialized caller-provided decision is not security authority.

This slice deliberately does **not** implement the production adapter to the existing `PolicyEngine`, and therefore does not satisfy or claim the Day-8 flagship gate yet. The next slice must bind this oracle interface to the real local privacy kernel and demonstrate an actual case where the existing local kernel returns `ALLOW` while PPMC finds a reproducible bounded future counterexample.

## Runtime boundary

This slice does not modify Pipeline, PolicyEngine, execution authorization, verifier, disclosure persistence, EvidencePolicy, DataHub MCP behavior, or post-execution release verification. PPMC remains prospective analysis only until a later explicitly validated integration slice.
