# ToxicJoin Historical Pre-vNext Release Evidence

> **Status: historical evidence snapshot.** This file preserves the evidence chain that was presented around the PR #68/#70 release state. It is **not** an authoritative manifest for the repository's current `main` and must not be used to claim that the historical runtime head is the current product revision.

The repository has since reopened for vNext development. Phase 0 of the current hardening/release-truth work established newer exact-revision evidence separately. A generated current release manifest is intentionally handled as a later release-hygiene step; manual documentation must not pretend to be that authority.

## Historical release identity

At the time of the original judge-facing synchronization in PR #70, the repository snapshot was:

```text
e1192edc2deb961ad9d85187ba2985f82296ed53
```

Historical runtime merge from PR #68:

```text
ee4991a93070c148e41dd158c952d5f1e9a6ed2c
```

Exact historical security-remediation runtime head validated before that landing:

```text
536c37c34de7b36495d33f63095585f72e5f4b46
```

PR #68 merged that validated runtime head and the merge introduced no file-tree difference relative to it. PR #70 then changed judge-facing documentation/evidence only. Those statements remain useful provenance for the historical evidence below, but `e1192edc…` and `536c37c…` are **not current repository-head identifiers**.

The deterministic policy version for this historical evidence set is `0.2.0`.

The old release-freeze statement applied to that historical submission candidate. It does not describe the repository after vNext development resumed.

## Historical exact-security-head gates

The following workflows completed successfully on exact historical runtime head `536c37c34de7b36495d33f63095585f72e5f4b46`:

| Gate | Run | Result |
|---|---:|---:|
| CI — Python 3.11 / 3.12, Web, benchmark, hardened Container | `30143510873` | PASS |
| CodeQL | `30143510868` | PASS |
| Supply Chain Security | `30143510883` | PASS |
| Governance Dependency Evidence | `30143510866` | PASS |
| Adversarial Mutation Evidence | `30143510877` | PASS |
| Compositional Ablation Evidence | `30143510871` | PASS |
| Disclosure Sequence Evidence | `30143510867` | PASS |
| Live DataHub Evidence | `30143510876` | PASS |

Python 3.12 pytest reported **309 passed**, with one upstream Starlette/FastAPI deprecation warning.

These results validate that exact historical head. They must not be relabeled as current-main CI evidence.

## Historical 30-case benchmark

Exact-head artifact:

- artifact ID `8615270504`;
- artifact digest `sha256:88737151d88603a0c3994a4e479a1e2c8ee6e0aa909615b9127703d92a128599`;
- policy `0.2.0`;
- data fingerprint `bfeae85c4b238e38012aadc6f4c95d24c7a28bcb1da1c35e8eeef5be28be7d16`;
- 30 cases: 10 ALLOW / 10 REWRITE / 10 BLOCK;
- 30/30 expected initial decisions;
- 30/30 expected effective outcomes;
- 30/30 expected reason codes;
- zero false allows;
- zero unsafe effective allows;
- six rewrites remediated to verified ALLOW;
- four rewrite paths failed closed;
- 16 verified executions;
- report SHA-256 `3e8ea32a802a6b512be42ddc81b774b34ec0234e7f4ca43ca9be65cc1f398a64`.

This is a deterministic regression corpus for the supported SQL/policy profile, not a claim of universal privacy-detection accuracy.

## Historical PR #68 security closure

The pre-vNext audit found and fixed concrete issues including:

- protected conditional aggregate oracle paths such as `COUNT(CASE...)` and filtered counts;
- cohort identity that previously discarded root SELECT predicates/thresholds/targets;
- temporal differencing from repeated protected releases without trusted warehouse snapshot identity;
- disclosure-state poisoning after failed execution;
- unkeyed-only receipt integrity;
- raw protected engine/database error leakage;
- broad default Docker Compose host binding.

The resulting controls included conditional aggregate exposure classification, keyed cohort identity, conservative repeated-release semantics, append-only `PENDING -> RELEASED | ABORTED` disclosure state, HMAC-authenticated receipts, fail-closed receipt-key handling, sanitized protected execution errors, and loopback-only default Compose publication.

These controls remain part of project history, but current runtime claims must be established from current code and current evidence rather than inferred from this historical section.

## Historical exact-image black-box validation

Validation-only PR #69 reran the independent production-image harness against the historical exact security head. The validation branch was never merged.

Run `30145592349`: **24/24 PASS**.

- artifact ID `8615893443`;
- artifact digest `sha256:347c1cb66116367183a15e70a1ea892881cdfcf98321db581fbf10db5ae75d0a`;
- exact target `536c37c34de7b36495d33f63095585f72e5f4b46`;
- report SHA-256 `c857cf8856e1850124f5d0c6bff2a2cdcbf1baa01ea21372db5bcb9fbb8d6dd3`;
- failed probes `0`.

Coverage included authentication/scope separation, request limits, rate limiting, fail-closed mutation and compositional sensitive export, legitimate low-risk execution, receipt ownership isolation, receipt mode `0600`, persisted-receipt tamper detection, restricted production API surface, TrustedHost, non-root/read-only container boundaries, capability drop, no-new-privileges, localhost exposure, and response/log leakage checks.

See [`final-security-blackbox.md`](final-security-blackbox.md) and [`final-security-blackbox.json`](final-security-blackbox.json).

## Historical Live DataHub OSS + official MCP evidence

Historical exact-security-head run `30143510876`: **PASS**.

Evidence artifact:

- artifact ID `8615316211`;
- digest `sha256:18552f336e1e0a785bb2a19c984726b175902f16323ad8092323959d8a6e1dd2`.

Diagnostics artifact:

- artifact ID `8615316546`;
- digest `sha256:4ecb6e0843e5804ac4c1f477b86e095e5398cbefb345573675a9f82f8e488922`.

That run proved:

- 5 datasets;
- 19 governed fields;
- 10 controlled tags;
- 7 glossary terms;
- 4 lineage writes;
- official `mcp-server-datahub==0.6.0`;
- role-separated read-only snapshot -> isolated writer -> fresh read-only read-back;
- raw upstream writer inventory retained honestly;
- effective ToxicJoin writer inventory exactly `save_document` through a mandatory allowlist;
- independent Decision read-back verified;
- 3 upstream lineage relationships;
- 2 lineage-bound fields;
- 6 normalized lineage sources;
- zero unclassified lineage sources.

Historical seed report SHA-256: `538eef1abc7a02d1a0bcc939a51195831e78e8e6cb161400fbc3abf223f5f3b1`.

Historical spike report SHA-256: `6f295f0c399474834d66413353b5218af5c098fdb6f9875088b43011bcd6f292`.

See [`datahub-live.md`](datahub-live.md), [`datahub-live-seed.json`](datahub-live-seed.json), and [`datahub-live-spike.json`](datahub-live-spike.json).

## Frozen external 24-task validation

Validation-only PR #38 reused the unchanged frozen tasks, SQL proposals, risk labels, expected execution semantics, baseline artifact, and UCI warehouse fingerprint.

Run `30137303763`: PASS.

- artifact `8613263087`;
- digest `sha256:b3988c8f9a43e7cdafe53384279eda91d3c04c92751dd4c93c918c234a3e422a`;
- 24 tasks;
- 1 ALLOW / 23 BLOCK;
- E01 executes;
- E18 / E20 / E24 BLOCK and never execute;
- zero unsafe MUST_NOT_EXECUTE executions;
- zero unsafe grouped-sensitive executions;
- no patient rows in sanitized evidence;
- report SHA-256 `beb02e39ad2fe4838f78def0c8d0e5d8d396876845c29a758223d87464ff2cf9`.

This remains frozen external validation of an earlier deep-security baseline. It is deliberately not regenerated or relabeled as current-main evidence.

## Retired public surface

An earlier static browser surface and its repository integration were retired before the `v0.2.0`
candidate. It is not a supported product URL or release gate. The current browser path is the
same-origin Render application documented in [`../deploy-public.md`](../deploy-public.md).

## Historical supply-chain posture

The historical release lineage retained:

- committed Python and npm lockfiles consumed by CI/Docker;
- Python and npm dependency audits;
- Bandit SAST;
- CodeQL `security-extended`;
- CycloneDX SBOMs;
- immutable GitHub Action SHA pins;
- digest-pinned Docker base images;
- Dependabot.

A narrow machine-validated upstream-constrained `setuptools` exception remains documented under `docs/security/`. Its current validity and expiry must be evaluated from the machine-readable exception and current dependency audits, not inferred from this historical file.

## Current-repository claim boundary

This file is intentionally **not** the current release authority.

It supports statements about exact historical SHAs, runs, artifacts, and the bounded Phase 0 replay revalidation recorded above. It does not support statements that:

- `e1192edc…` is current `main`;
- `536c37c…` is the current runtime head;
- historical CI/DataHub/black-box runs validate later vNext source changes;
- a historical browser artifact is generated from current `main`;
- historical release freeze remains active.

Current release identity should be derived from exact repository state and machine-generated release evidence. Manual documentation is downstream explanatory material, not the source of revision truth.

ToxicJoin continues not to claim differential privacy, universal SQL repair, universal re-identification detection, formal verification, or legal-compliance certification. Unsupported SQL, unresolved/ambiguous lineage, missing/stale governance, failed rewrite, failed verification, integrity failure, or incomplete evidence fail closed.
