# Phase 7 Acceptance — Release Manifest Gate Completeness

Phase 7 passes only when one generated manifest verifies every release-critical gate against one
exact candidate SHA and fails closed for missing, stale, skipped, expired, malformed, or
inapplicable evidence.

## Required gates

The manifest must verify CI, the 30-case benchmark, the PPMC hard gate, CodeQL, supply-chain
security, governance/adversarial/ablation security evidence, the hardened production container,
Linux/Windows portability, real Live DataHub, production Browser E2E, artifact integrity, and the
canonical disclosure-state topology.

## Exact identity

Candidate mode binds every workflow run, job, and artifact to the exact PR head and to an unchanged
`main` base. It is explicitly not a release identity. Release mode accepts only the exact current
`main` SHA.

## Artifact integrity

Required artifacts must be unique, non-empty, unexpired, have a GitHub SHA-256 digest, match the
downloaded ZIP bytes, contain safe paths, and satisfy their machine-readable schema and embedded
checksums or self-hashes.

## Topology boundary

The canonical disclosure state remains `SINGLE_NODE`. Multi-replica stateful privacy is unsupported
and must fail closed. PostgreSQL and `SHARED_AUTHORITATIVE` remain deferred to Phase 12 and must not
be claimed by the manifest.

## Preserved boundaries

Phase 8 is not started. PR #118/PostgreSQL is not modified. No Vercel, Devpost, tag, release,
ruleset, cleanup, or direct `main` mutation occurs. No immutable release is created in Phase 7.
