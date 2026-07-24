# Threat-Model Delta — P2-A Disclosure Ledger Foundation

Date: 2026-07-24

## Scope

P2-A introduces the persistent state and governed semantic representation required for cumulative-disclosure enforcement. It deliberately does **not** yet make an ALLOW/BLOCK decision from prior history. Cross-query composition policy and atomic evaluate-and-append authorization remain P2-B release-blocking work.

This phase changes persistent state and cross-request behavior primitives, so it is security-sensitive under the permanent Definition of Done.

## New persistent state

ToxicJoin gains a local SQLite-backed append-only disclosure ledger. A record contains only governed/audit metadata:

- principal and optional agent privacy scope;
- administrator-controlled credential ID as audit metadata only;
- governed subject namespace metadata;
- receipt ID for linkage to the separate decision audit trail;
- policy version;
- governed semantic output lineage, source datasets, referenced/join/group columns, aggregate functions, and threshold metadata;
- event/content hashes and the previous content hash for the same privacy scope;
- internally generated record ID and UTC creation time.

Raw warehouse rows, result values, SQL text, SQL-derived hashes, SQL literals, API keys, task prompts, output aliases, and caller-controlled session identifiers are intentionally absent.

The exact SQL hash already belongs to the decision receipt. P2-A deliberately does **not** duplicate a raw-SQL-derived hash into the disclosure ledger because low-entropy predicate literals could otherwise be susceptible to offline dictionary guessing after ledger compromise. A future cohort/predicate identity used by P2-B/P2-C must be deliberately designed for composition semantics rather than reusing a raw-query hash.

## Privacy scope boundary

The privacy scope is keyed by:

1. authenticated `principal_id`;
2. authenticated `agent_id` when present, otherwise a principal-only sentinel;
3. a governed subject namespace derived from the identifier field path and its governed identifier category.

`credential_id` and `session_id` are intentionally excluded from the scope key. Rotating an API credential or session must not reset cumulative privacy history. Only the administrator-controlled credential ID is retained for audit; the caller-controlled session ID is not persisted in the disclosure ledger.

Dataset URNs and DataHub domain URNs are retained as audit evidence but are also excluded from the privacy key. The same governed `customer_id` namespace therefore composes across `customers`, `orders`, and other governed datasets rather than allowing dataset/domain rotation to partition history.

The subject key must:

- belong to a query source dataset;
- exist in the governed catalog;
- be classified as `DIRECT_IDENTIFIER` or `STABLE_PSEUDONYM`;
- have no conflicting identifier category across participating source datasets.

This is intentionally conservative and can over-compose identically named identifier fields. False-positive composition is safer than history partitioning.

## Semantic release identity

The semantic fingerprint records governed information rather than prior SQL strings. It covers:

- governed source dataset URNs;
- exposure kinds and governed source lineage for projected outputs;
- all referenced governed columns;
- join columns;
- grouping keys;
- normalized aggregate functions;
- minimum group-size metadata.

Output aliases/names are not persisted at all. They are caller-controlled SQL identifiers and could otherwise be abused as a storage channel. Alias renaming therefore neither changes the semantic fingerprint nor changes persisted disclosure content.

P2-A stores no raw-query-derived fingerprint. The receipt ID is the linkage to the immutable decision receipt, which remains the authoritative place for exact SQL identity evidence.

## Persistence and concurrency boundary

The ledger uses SQLite with:

- a schema version gate;
- `BEGIN IMMEDIATE` for every append, serializing writers;
- unique receipt IDs for idempotency/replay control;
- internally generated UUID4 record IDs with 128 bits of randomness;
- internally generated UTC creation times;
- a per-scope previous-content hash chain;
- deterministic event and record content hashes;
- database triggers that reject `UPDATE` and `DELETE` operations;
- owner-only (`0600`) database creation/permissions from the first file creation operation;
- symbolic-link target rejection;
- fail-closed validation of persisted payloads against indexed columns and hashes.

The append API does not accept a caller-supplied record ID or timestamp.

The serialized writer transaction is intentionally chosen so P2-B can perform history read + composition evaluation + accepted append under one writer lock. P2-A itself exposes only append/read/verify operations and therefore does not yet close a time-of-check/time-of-use race around privacy authorization.

## Threats reduced

- **Credential rotation bypass:** credential IDs do not partition privacy history.
- **Session rotation bypass:** session IDs do not partition privacy history and are not persisted.
- **Dataset/domain rotation bypass for the same governed identifier name:** dataset/domain audit metadata does not partition the subject namespace.
- **Alias-based semantic identity/storage bypass:** output aliases are neither fingerprint inputs nor persisted metadata.
- **Low-entropy raw-query hash guessing:** the disclosure ledger contains no raw-SQL-derived hash.
- **Caller-controlled record identity/time:** record IDs and timestamps are generated only inside the ledger.
- **Lost concurrent appends:** SQLite writer transactions serialize concurrent append operations.
- **Receipt replay ambiguity:** re-appending the identical receipt/event is idempotent; reusing a receipt ID for different content fails closed.
- **Accidental history mutation:** application-level `UPDATE` and `DELETE` operations are blocked by SQLite triggers.
- **Naive at-rest tampering:** record hashes, index/payload cross-checks, and per-scope chaining detect payload or chain modification.
- **Sensitive ledger content:** raw SQL, raw-query hashes, literals, rows, result values, API keys, task prompts, aliases, and session IDs are not persisted.
- **Symlink redirection:** a ledger path that is a symbolic link is rejected.

## Negative security tests

Coverage includes:

- credential and session rotation retaining the same privacy scope;
- cross-dataset `customer_id` rotation retaining the same privacy scope;
- different principal or agent producing a distinct scope;
- non-identifier subject keys failing closed;
- subject keys outside query sources failing closed;
- conflicting governed subject categories failing closed;
- alias changes preserving semantic identity while aliases remain absent from persisted content;
- governed sensitive/group/join/reference metadata being captured;
- disclosure events excluding raw SQL hash, alias, and session metadata;
- identical receipt replay remaining idempotent;
- receipt ID reuse with different content failing closed;
- caller attempts to inject record ID or creation time being rejected by the Python API;
- concurrent append stress with no lost records and a valid hash chain;
- direct SQLite `UPDATE` and `DELETE` attempts being rejected;
- simulated out-of-band payload/chain tampering being detected;
- raw SQL, raw-query-hash field names, literal markers, alias markers, and session markers never appearing in the SQLite file;
- owner-only database permissions and symlink rejection;
- missing ledger storage after initialization failing closed.

## Residual risk and explicit non-goals

- **No cumulative authorization yet.** P2-A does not inspect history before policy authorization and does not block differencing attacks by itself. P2-B must implement atomic history read + composition decision + append before execution authorization can be released.
- **No differential privacy claim.** No formal epsilon/delta privacy budget is implemented.
- **Different identifier field names can still represent the same real-world subject.** P2-B must introduce a governed canonical subject-alias/namespace policy or fail closed where equivalence cannot be proven.
- **Local SQLite is a single-state-store primitive, not a distributed privacy ledger.** A multi-replica secure/live deployment must use one shared authoritative ledger or enforce single-writer routing before P2 protection can be considered complete.
- **Hashes are not signatures.** An attacker with sufficient filesystem control could drop triggers and recompute unkeyed hashes. Keyed/asymmetric authenticity remains aligned with the broader receipt/state integrity roadmap.
- **Filesystem replacement by a privileged local attacker is not prevented by application checks.** The deployment must protect the ledger directory and process account; application hash/chain validation detects content inconsistency but is not a substitute for OS-level access control.
- **SQLite availability is fail-closed only once the ledger is wired into authorization.** P2-A does not yet change runtime execution paths.
- **Predicate/cohort relation reasoning is not complete.** P2-A captures governed referenced-column semantics but intentionally does not claim that it can infer set-difference relationships. P2-B/P2-C must add the controlled-query/composition model and adversarial sequence corpus.
