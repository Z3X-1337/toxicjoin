# Disclosure Digital Twin — P0 Boundary Note

This slice implements the vNext Disclosure Digital Twin as an immutable deterministic projection over the existing disclosure-ledger semantics. It does **not** create a second ledger, database, or persistence path.

## Inputs and lifecycle semantics

The builder consumes:

- one privacy `DisclosureScope`;
- a complete per-scope audit-history snapshot of validated `DisclosureRecord` objects plus their lifecycle state;
- the current candidate semantic release and its composition metadata whenever the semantic release is protected;
- purpose, governance, evidence-root, and optional warehouse-snapshot commitments.

`RELEASED` and `PENDING` history are projected as active knowledge. `PENDING` is intentionally active because the existing secure ledger already counts pending reservations during cumulative evaluation to prevent concurrent requests from racing around the privacy gate. `ABORTED` records remain audit history but are excluded from active disclosure knowledge.

The current candidate is projected as hypothetically released. This produces the post-candidate state that the later prospective model checker will inspect.

Protected semantics are composition-complete or fail closed. If `is_protected_release(semantic)` is true, missing composition metadata is rejected. Supplied composition must bind the exact semantic release family and its `protected_release` flag must agree with deterministic classification. This prevents legacy/malformed protected history from silently losing cohort information in the prospective state.

## Atomic history snapshot requirement

This PR intentionally does not add a convenience adapter that calls `list_for_scope()` and then queries lifecycle states one record at a time. Such a read sequence would not be an atomic ledger snapshot and could introduce a TOCTOU boundary between audit history and release lifecycle.

Before the Twin is connected to a runtime authorization path, the secure ledger must expose or internally construct an atomic, validated history+lifecycle snapshot under one database read transaction. Until then, `DisclosureHistoryEntry` is a trusted caller boundary and is not accepted from an Agent or serialized request.

## Knowledge boundary

Direct atoms preserve semantic structure such as source datasets, output exposure kinds, referenced/join/group columns, aggregate functions, minimum group size, and protected cohort commitments.

Structural use is not automatically treated as released knowledge:

- a column that is only referenced or joined does not establish `CATEGORY_PRESENCE`;
- `FILTER_ONLY` and `JOIN_ONLY` output exposure kinds do not establish released category knowledge;
- aggregate-derived sensitive knowledge can establish sensitive category presence, but it does not by itself establish raw/linkable identifier-sensitive coexposure.

The first inference families are deliberately small and versioned:

1. category presence from revealing output exposure;
2. identifier-sensitive coexposure only from linkable output exposure kinds;
3. protected cohort variation from at least two distinct cohort commitments in the same release family.

These derived atoms are model facts, not yet the final forbidden-state predicates. The later forbidden-predicate layer must retain explicit claim boundaries and may inspect the underlying direct atoms rather than treating every derived signal as a block condition.

## Canonical state identity

`DisclosureState.state_sha256` commits to:

- privacy scope hash;
- model and inference versions;
- purpose commitment;
- governance commitment;
- evidence-root commitment;
- optional warehouse snapshot commitment;
- canonical direct/released atom hashes;
- canonical derived atom hashes;
- inference-rule-set commitment.

It intentionally excludes ledger record IDs, receipt IDs, timestamps, SQL formatting, raw SQL, raw rows, and caller-controlled output aliases.

## Resource bounds and fail-closed behavior

P0 bounds the Twin to 4,096 direct atoms, 4,096 derived atoms, and 8,192 instantiated inference rules. Budget exhaustion raises `DisclosureTwinError`; it does not silently truncate knowledge.

This slice does not modify `Pipeline`, `PolicyEngine`, execution authorization, the disclosure ledger schema, or `EvidencePolicy`.