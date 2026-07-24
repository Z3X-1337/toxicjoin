# Threat-Model Delta — P3-B DataHub Freshness and TOCTOU

Date: 2026-07-25
Tracking: TJ-SEC-013

## Scope

P3-B closes the trust gap between the DataHub governance snapshot that produced a policy
decision and the snapshot that is authoritative when ToxicJoin authorizes and executes the
query.

This change does not add a product feature. It strengthens the existing live DataHub trust
boundary and makes governance provenance explicit in authorization, receipts, and readiness.

## Security objective

A live request must never silently combine governance state from different DataHub snapshots.
The request is bound to one `GovernanceContextBinding` from initial context resolution through
rewrite verification, execution authorization, execution-time revalidation, and the immutable
receipt.

The protected flow is:

```text
DataHub snapshot A
    -> atomic ContextResolution + GovernanceContextBinding(A)
    -> initial policy decision
    -> optional rewrite
    -> final context must still be A
    -> verifier must still be A
    -> ExecutionAuthorization HMAC binds A
    -> pre-execution revalidation must still be A
    -> execution
    -> receipt records A
```

If the active snapshot changes to B at any protected boundary, ToxicJoin fails closed with
`DATAHUB_CONTEXT_DRIFT`. If the bound snapshot exceeds its freshness SLA, ToxicJoin fails
closed with `DATAHUB_CONTEXT_STALE`.

## Governance binding

`GovernanceContextBinding` contains:

```text
source
snapshot_sha256
catalog_version
observed_at
expires_at
```

The DataHub snapshot fingerprint is deterministic over governed snapshot content. Wall-clock
observation time is intentionally excluded from `snapshot_sha256`; two fresh observations of
identical governance content therefore retain the same content fingerprint while receiving new
`observed_at` / `expires_at` values.

The default snapshot freshness SLA is 300 seconds. Configuration is hard-capped at 3600
seconds.

## Atomic resolution

`DataHubSnapshotContextResolver.resolve_with_governance_binding()` acquires the resolver lock
and returns the normalized `ContextResolution` and its `GovernanceContextBinding` from the same
snapshot atomically.

`replace_snapshot()` also uses the same lock, so an in-process refresh cannot partially mutate
the catalog used by a resolution.

## Pipeline binding

The pipeline captures the initial binding with the initial policy context.

For a rewrite, the rewritten query is resolved again and its binding must equal the initial
binding before the final policy decision is accepted. This prevents silent combinations such
as:

```text
initial decision: snapshot A
rewrite decision: snapshot B
execution: snapshot C
```

The verifier receives the initial pipeline binding as an expected binding. A mismatch is a
security failure, not a refresh opportunity inside the current request.

## Verifier binding

The governance-aware verifier captures context and binding atomically, pins that binding for
the verification invocation, and injects the exact binding into execution-authorization
issuance.

The underlying DuckDB executor remains bound to the stable application resolver rather than a
per-request wrapper. This preserves the existing anti-authority-substitution invariant while
still requiring the request-specific governance binding at authorization issuance.

Fixture and replay resolvers remain binding-free and continue through the provider-neutral
verification path.

## Execution authorization

`ExecutionAuthorization` now includes the governance binding inside the HMAC-authenticated
capability.

Authorization issuance:

1. re-analyzes the exact SQL;
2. resolves context and governance binding atomically;
3. requires equality with the verifier/pipeline binding;
4. recomputes the deterministic policy decision;
5. revalidates that the current resolver binding has not changed;
6. signs the exact governance binding with the rest of the execution capability.

Authorization consumption repeats current-state resolution and binding comparison before the
single-use authorization is consumed. Snapshot replacement after authorization therefore
blocks execution.

Tampering with the embedded binding invalidates the authorization MAC.

## Receipt provenance

Receipt schema `1.2` includes the governance binding. The binding participates in the receipt
content hash.

LIVE receipts require governance provenance. This includes fail-closed receipts created because
a snapshot is stale: a stale snapshot is not authority for execution, but its identity is still
recorded so the rejection can be audited.

Changing receipt governance provenance after persistence causes the receipt integrity check to
fail.

## Readiness semantics

Liveness and readiness remain intentionally separate:

```text
/api/health -> process liveness only
/api/ready  -> execution dependencies and governance freshness
```

A stale DataHub snapshot does not make the process dead. `/api/health` remains `200` with the
minimal `{"status":"ok"}` response, while `/api/ready` returns `503`, `status=degraded`, and
`governance_ready=false`.

## Threats reduced

### Governance snapshot substitution

An ALLOW derived from snapshot A cannot silently execute against resolver snapshot B.

### Verification-to-authorization TOCTOU

The verifier binding is explicitly passed into authorization issuance rather than allowing the
authorizer to select an unrelated current snapshot.

### Rewrite mixed-snapshot decisions

Initial and final policy decisions within one request must share one binding.

### Stale governance execution

Resolvers reject snapshots after `expires_at`; authorizer and verifier map the failure to stable
fail-closed reason codes.

### Receipt provenance ambiguity

LIVE receipts identify the exact observed governance snapshot used or rejected.

### Evidence tampering

Authorization HMAC and receipt content hashing cover governance provenance.

## Negative security evidence

Permanent tests cover at least:

- expired snapshot -> no execution;
- snapshot replacement during verifier flow -> no authorization/execution;
- snapshot replacement between initial and rewritten context -> BLOCK;
- snapshot replacement after authorization -> authorization consumption rejected;
- same governance content with a new fresh observation -> valid new binding;
- governance binding tampering -> invalid authorization MAC;
- LIVE receipt without governance provenance -> schema rejection;
- receipt governance tampering -> integrity failure;
- stale DataHub snapshot -> readiness degraded while liveness remains healthy.

## Concurrency model

Snapshot reads and replacements are serialized through the resolver `RLock`. A request retains
an immutable binding value and compares it at each protected boundary. A concurrent refresh may
cause a request to fail closed, but it cannot make the request silently adopt the new snapshot.

This is deliberate: availability is sacrificed instead of mixing governance authority.

## Residual risks

### External DataHub changes before local refresh

ToxicJoin executes against an explicitly observed snapshot, not a distributed transaction with
DataHub. If governance changes in DataHub after the local snapshot was observed but before the
next refresh, ToxicJoin cannot know that change until refresh. The freshness SLA bounds this
risk but does not provide push invalidation or linearizable DataHub reads.

### Final external TOCTOU window

The application revalidates the local governance binding immediately before authorized DuckDB
execution. It cannot atomically lock external DataHub governance and the DuckDB statement in one
distributed transaction. The remaining window is bounded by the snapshot/refresh model and the
read-only execution contract.

### Clock integrity

Freshness depends on a trusted monotonic progression of the host wall clock used to compare UTC
observation and expiry timestamps. Host-level clock compromise is outside the application trust
boundary.

### Snapshot acquisition correctness

The binding proves which normalized snapshot ToxicJoin used. It does not independently prove
that a compromised DataHub server or compromised MCP read process returned truthful metadata.
P3-A credential/process separation and live evidence reduce this risk but do not eliminate a
fully compromised upstream authority.

## Release impact

P3-B changes context, verification, execution authorization, receipts, and readiness trust
semantics. It is therefore release-blocking and requires exact-head evidence from:

```text
Python 3.11
Python 3.12
Web
Container
Governance Dependency Evidence
Adversarial Mutation Evidence
Compositional Ablation Evidence
Disclosure Sequence Evidence
Live DataHub Evidence
Frozen external 24-task replay
```

P3-B must not merge until all required gates are green against the same PR head and the external
replay provenance identifies that exact candidate SHA.

No Devpost submission state is changed by P3-B.
