# Phase 16 — Shared Disclosure State Topology Verification

## Scope

Phase 16 begins the shared-state roadmap by making the cumulative disclosure-state topology explicit and fail closed. It does **not** replace the proven SQLite ledger or claim that ToxicJoin already has a horizontally authoritative privacy store.

The target invariant is:

> A deployment must not present replica-local disclosure histories as one authoritative cumulative privacy history. If stateful privacy is declared across more than one application replica, the configured disclosure backend must provide shared-authoritative semantics.

## Proven gap

The existing SQLite disclosure ledger provides strong local semantics:

- append-only hash-chained history;
- `BEGIN IMMEDIATE` serialization for cumulative evaluation and append;
- two-phase `PENDING -> RELEASED | ABORTED` state;
- authorization-claim binding;
- restart persistence and cohort-key integrity.

Those guarantees apply to callers that share one SQLite state store.

The red head `e034bc9526d59463b2a964f9e66f04fe1db20774` constructed two replica-local SQLite databases with:

- the same cohort HMAC key;
- the same authenticated principal and Agent;
- the same governed subject scope;
- conflicting protected cohorts (`alpha`, then `beta`).

Replica A saw an empty local history and authorized `alpha` as `FIRST_PROTECTED_RELEASE`. Replica B independently saw another empty local history and also authorized `beta` as `FIRST_PROTECTED_RELEASE`.

A control ledger using the same cohort key and globally composed history authorized `alpha` and rejected `beta` with `CUMULATIVE_VARIATION_BLOCK`.

Python 3.11 recorded:

- `1 failed, 835 passed`;
- the only new failure proved that replica B authorized a protected variation that the globally composed history blocks.

Python 3.12 failed the same regression.

This is a horizontal state-partition gap, not a defect in SQLite transaction isolation. Each local database made a correct decision from an incomplete history.

## Fix

### Explicit disclosure-state topology

Phase 16 introduces two topology classes:

- `SINGLE_NODE`
- `SHARED_AUTHORITATIVE`

The current SQLite implementation remains the internal, proven single-node primitive.

The public `toxicjoin.disclosure.DisclosureLedger` is now a topology-aware composition boundary that declares `SINGLE_NODE` and validates the deployment replica count before opening the SQLite state authority.

### Fail-closed replica declaration

The public SQLite authority accepts one replica only.

A caller may provide `deployment_replica_count` explicitly. If omitted, the value is resolved from:

`TOXICJOIN_REPLICA_COUNT`

with a conservative default of `1`.

Any declared replica count greater than one fails closed with:

`multi-replica stateful privacy requires a shared authoritative disclosure backend`

Malformed, boolean, zero, negative, non-ASCII, whitespace-padded, or unreasonably large replica declarations are rejected rather than normalized ambiguously.

This is an operator/deployment declaration, not replica auto-discovery. A horizontally scaled restricted/LIVE deployment must declare its topology accurately.

### Raw SQLite boundary remains explicit

`toxicjoin.disclosure.secure_ledger.DisclosureLedger` remains the internal SQLite primitive. Its replica-partition behavior is retained in security coverage as evidence of why it must not be presented as shared-authoritative state.

The public package export now points to the topology-aware wrapper.

### Evidence gate

`Disclosure Sequence Evidence` now runs the Phase 16 topology regressions in addition to the existing cumulative-disclosure and execution-binding suites.

The existing sequence benchmark remains unchanged and continues to prove the single-authoritative-store `ALLOW -> BLOCK` behavior for changed protected cohorts.

## Why Phase 16 does not implement fake distributed SQLite

The gap cannot be solved honestly by a process-local mutex, a second local file, or by hashing/copying the cohort key. Those mechanisms do not create one serializable privacy history across hosts.

Phase 16 therefore closes the unsupported-deployment boundary first instead of weakening the claim or introducing a host-local coordinator that would fail under real horizontal scaling.

The `SHARED_AUTHORITATIVE` topology is reserved for a backend that can make cumulative evaluation and append against one shared transactional history. A subsequent phase can implement that backend, with PostgreSQL as the natural first candidate.

## Regression coverage

Phase 16 covers:

- raw replica-local SQLite histories demonstrably partition the same cumulative privacy scope;
- a single authoritative SQLite history blocks the same conflicting second cohort;
- the public SQLite authority declares `SINGLE_NODE`;
- explicit multi-replica use of the public SQLite authority fails closed;
- `TOXICJOIN_REPLICA_COUNT > 1` also fails closed;
- single-replica use remains supported;
- the topology contract accepts a future `SHARED_AUTHORITATIVE` backend for multiple replicas;
- malformed replica declarations fail closed;
- existing cumulative disclosure evidence remains green.

## Claim boundary

Phase 16 does **not** claim:

- multi-replica cumulative privacy support;
- PostgreSQL or another shared state backend;
- automatic replica discovery;
- distributed transactions across DataHub, warehouse execution, receipts, and disclosure state;
- Redis-backed global rate limiting;
- horizontally shared receipt storage or key custody.

It makes the current topology truthful and safe: local SQLite is supported as single-node state only, and a declared multi-replica deployment cannot silently inherit a false cumulative-privacy guarantee.

The next shared-state phase should implement and test a real `SHARED_AUTHORITATIVE` disclosure backend before removing this deployment restriction.