# Threat-Model Delta — P2-B Cumulative Composition Authorization

Date: 2026-07-24

## Scope

P2-B makes the P2-A disclosure history authoritative at the execution boundary. It closes the release-blocking cross-query differencing gap by adding a conservative controlled-query composition policy, an atomic evaluate-and-commit transaction, and an execution capability that is cryptographically bound to the resulting disclosure commitment.

The change affects persistent privacy state, verification, execution authorization, receipts, authenticated API startup, and readiness. It therefore requires negative sequence tests plus the normal CI, Governance, Adversarial, Ablation, Live DataHub, and frozen external replay gates.

## Security objective

A sequence of individually request-local `ALLOW` queries must not allow an authenticated principal/agent to gain additional protected information by varying cohort predicates or protected output semantics across requests while keeping the same governed subject namespace.

The canonical regression is an `ALLOW` aggregate count over one cohort followed by another request-local `ALLOW` count over a different cohort. The second query must be blocked before DuckDB execution authorization and must release no rows.

## Controlled-query composition model

P2-B intentionally does **not** claim general SQL set-relation inference or differential privacy. The enforcement rule is deliberately conservative:

1. Every aggregate release is treated as protected because counts and other aggregates can participate in membership/differencing inference.
2. A non-aggregate release is protected when projected governed lineage includes a direct identifier, stable pseudonym, quasi-identifier, or sensitive attribute.
3. The first protected release for one privacy scope may commit.
4. A later protected release in the same scope may commit only when both its semantic release family and its keyed cohort identity are identical to all previously committed protected releases in that scope.
5. A different protected cohort or semantic family is blocked with `CUMULATIVE_DISCLOSURE_RISK` before execution authorization.
6. Unprotected public/non-aggregate releases do not consume the protected family/cohort allowance.
7. Protected legacy P2-A history without composition metadata causes future protected releases to fail closed with `LEGACY_HISTORY_BLOCK`; history is never silently reset or guessed.

This rule intentionally permits false positives. False-positive blocking is preferable to under-composing a history whose relationship cannot be proven safe.

## Privacy scope

The P2-A privacy scope remains authoritative:

- authenticated `principal_id`;
- authenticated `agent_id` when present, otherwise principal-only sentinel;
- governed subject namespace derived from identifier field path + governed identifier category.

`credential_id` and caller-controlled `session_id` do not partition history. Credential/session rotation therefore cannot reset the cumulative gate. Dataset/domain audit metadata also does not partition the subject namespace.

P2-B does not change the P2-A residual risk that two differently named governed identifiers may represent the same real-world subject. Canonical cross-name subject equivalence remains future hardening work and must fail conservatively where equivalence is not proven.

## Semantic release family

The existing governed semantic SHA is used as the release-family identity. It covers:

- governed source dataset URNs;
- projected exposure kinds and governed source lineage;
- all referenced governed columns;
- join columns;
- grouping keys;
- normalized aggregate functions;
- trusted minimum-group metadata.

Caller-selected output aliases are not persisted and do not affect the family identity.

## Keyed cohort identity

Cohort membership is represented by an HMAC-SHA256, not by raw SQL or a public raw-query hash.

Before HMAC calculation:

- SQL is parsed as exactly one DuckDB `SELECT`;
- the root output list is replaced with a constant because output semantics are tracked separately;
- root `ORDER BY` is removed because presentation order does not change cohort membership;
- predicates and other membership-shaping structure remain, including `WHERE`, `JOIN`, CTEs, `HAVING`, `QUALIFY`, `DISTINCT`, `GROUP BY`, `LIMIT`, `OFFSET`, and literal predicate values.

The canonical SQL exists only in memory long enough to calculate HMAC. The ledger stores only the resulting keyed digest. Raw SQL, literals, task prompts, API keys, aliases, and session IDs remain absent from disclosure state.

The 32-byte cohort HMAC key is stored separately from the SQLite ledger with owner-only (`0600`) permissions and symlink rejection. SQLite immutable metadata stores the SHA-256 fingerprint of that key. On schema-v2 restart:

- a missing key fails closed;
- a key with the wrong fingerprint fails closed;
- key replacement cannot silently create a new privacy-history namespace.

The fingerprint is an integrity binding, not a secret.

## Atomic privacy decision

`DisclosureLedger.evaluate_and_commit()` performs under one `BEGIN IMMEDIATE` writer transaction:

1. recompute candidate keyed composition metadata;
2. load and validate the full privacy-scope history and hash chain;
3. resolve receipt idempotency;
4. evaluate the controlled-query composition rule;
5. on BLOCK, rollback with no new record;
6. on ALLOW, append the release and commit;
7. return an opaque `DisclosureCommitment` bound to record ID, receipt ID, scope SHA, event SHA, and content SHA.

Concurrent different protected cohorts therefore cannot both observe an empty history and both commit. One writer wins; the second evaluates against the newly committed history and blocks.

## Commitment-before-capability rule

The privacy commitment is created **before** execution capability issuance. This ordering is intentional:

- the verifier must commit the allowed release before calling the executor authority;
- `ExecutionAuthorizer.issue()` independently reconstructs the governed event from the fresh resolver/policy state and verifies the exact commitment;
- the commitment is embedded inside the HMAC-authenticated single-use `ExecutionAuthorization`;
- `ExecutionAuthorizer.verify_and_consume()` repeats governance/policy and disclosure-commitment verification immediately before execution;
- missing, forged, stale, SQL-mismatched, subject-mismatched, identity-mismatched, ledger-mismatched, or tampered commitments cannot produce a valid capability.

The executor also binds the disclosure ledger and the `require_disclosure_commitment` flag as part of its authority identity. Rebinding to a different ledger or disabling stateful privacy after the executor is bound is rejected.

## Receipt identity binding

The pipeline allocates the final `tj_...` receipt ID at request start. The same ID is used by:

- the disclosure event/commitment;
- the verifier;
- the execution capability through its nested commitment;
- the final immutable decision receipt.

This prevents an execution release from being committed under one privacy record and later audited under an unrelated receipt identifier.

## Crash semantics

Once a protected release is committed, a later executor failure, post-execution quarantine, process crash, or receipt-write failure does **not** remove that commitment.

This can conservatively consume a privacy-history slot even when rows were never ultimately released. The resulting false positive is deliberate: forgetting a possibly authorized disclosure after a crash would recreate a differencing window. Automatic rollback of a committed privacy event is therefore prohibited.

## Provider-neutral governance

P2-B does not derive runtime disclosure state from fixture-only metadata. It builds the candidate event from the same `ContextResolver` snapshot used by policy verification. This works with fixture snapshots and `DataHubSnapshotContextResolver`.

A synthetic metadata-only subject probe resolves the governed subject field across participating datasets. SQL aliases are intentionally ignored when reconciling duplicate governance evidence; category, dataset URN, tags, glossary terms, resolution state, dataset name, and field path must still match. Actual governance disagreement fails closed.

## API and readiness boundary

- LIVE mode cannot explicitly disable stateful privacy.
- Any authenticated/restricted API surface with an explicit pipeline requires an enabled disclosure ledger before startup.
- A default authenticated API constructs the default ledger with stateful privacy enabled.
- The unauthenticated fixture judge remains deterministic and does not make cross-request privacy state release-blocking by default.
- `/api/ready` becomes degraded when a required disclosure database or cohort key disappears after startup, without expanding the public readiness response schema.

## Stable failure behavior

P2-B adds two stable reason codes:

- `CUMULATIVE_DISCLOSURE_RISK` — valid state proves the candidate is an unsafe protected variation;
- `DISCLOSURE_STATE_UNAVAILABLE` — the required state, identity, key, commitment, or integrity proof cannot be validated safely.

Both fail closed before row release. Internal exception text is not required in public API output.

## Negative security tests

Coverage includes:

- two request-local `ALLOW` aggregate cohorts where the first executes and the second different cohort is `BLOCK` before execution;
- identical cohort + alias change remaining repeatable;
- protected release-family variation being blocked;
- credential/session rotation not resetting history;
- two concurrent different protected cohorts not both committing;
- restart preserving history and cohort-key identity;
- missing or replaced cohort key failing closed;
- protected P2-A legacy history blocking new protected release;
- commitment SQL mutation failing verification;
- event/policy mutation failing commitment verification;
- forged commitment hashes failing authorization;
- direct `ExecutionAuthorizer` use without required commitment being rejected;
- executor authority substitution to a different ledger or disabled requirement being rejected;
- required state missing in the pipeline producing `DISCLOSURE_STATE_UNAVAILABLE` and no execution;
- restricted API startup without stateful privacy being rejected;
- readiness degrading after cohort-key loss;
- raw SQL and literal markers remaining absent from persisted disclosure SQLite state;
- exact-head sequence evidence proving changed-cohort `ALLOW -> BLOCK`, no execution attempted/released, restart persistence, and safe repeat behavior.

## Residual risk and explicit non-goals

- **No differential privacy guarantee.** There is no epsilon/delta privacy accountant and no formal DP noise mechanism.
- **No general predicate theorem.** P2-B does not prove subset, complement, overlap, or arbitrary relational equivalence between SQL predicates. It blocks protected variation instead.
- **False positives are expected.** Two analytically benign but different protected cohorts/families in the same scope can be blocked.
- **Agent scope remains part of privacy partitioning.** Cross-agent collusion for one principal is not newly solved by P2-B; identity semantics remain an explicit deployment/governance responsibility.
- **Different subject field names may describe the same people.** P2-B inherits the P2-A canonical-subject-name residual risk.
- **Single authoritative writer state is required.** Local SQLite cannot protect independent active replicas with separate ledgers. A multi-replica deployment must use one authoritative shared state store or single-writer routing before claiming cumulative protection.
- **Privileged filesystem compromise is outside application integrity guarantees.** A privileged attacker able to rewrite the database, key, triggers, and immutable metadata together can defeat local unkeyed record-chain checks. OS-level access control remains required.
- **Commit-before-execute can over-count.** A committed authorization followed by execution/receipt failure remains in privacy history intentionally.
- **The unauthenticated judge fixture is not the secure deployment profile.** Stateful enforcement is mandatory on restricted/authenticated and LIVE API surfaces, not on the deterministic public judge surface.
