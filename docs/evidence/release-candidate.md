# ToxicJoin Final Release Evidence

This is the authoritative judge-facing release index.

## Release identity

Current judge-facing `main` HEAD after PR #70 documentation/evidence synchronization:

```text
e1192edc2deb961ad9d85187ba2985f82296ed53
```

Frozen runtime merge from PR #68:

```text
ee4991a93070c148e41dd158c952d5f1e9a6ed2c
```

Exact security-remediation runtime head validated before landing:

```text
536c37c34de7b36495d33f63095585f72e5f4b46
```

PR #68 merged that exact validated runtime head into `main`; the runtime merge introduced no file-tree difference relative to it. PR #70 landed afterward and changed only judge-facing README/documentation/evidence. It did not change runtime source, policy, parser, rewriter, executor, verifier, authentication, disclosure implementation, dependencies, Docker runtime, or workflow definitions. Therefore `e1192edc…` is the current repository HEAD presented to judges, while `536c37c…` remains the exact runtime provenance for the security and DataHub evidence below. Policy version remains `0.2.0`.

No new feature, refactor, dependency, or policy change is authorized during release freeze unless a proven release blocker requires reopening the candidate.

## Exact final-security-head gates

All release/security workflows below completed successfully on `536c37c34de7b36495d33f63095585f72e5f4b46`:

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

Python 3.12 pytest artifact: **309 passed**, with one upstream Starlette/FastAPI deprecation warning only.

## Final 30-case benchmark

Exact-head CI artifact:

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

## Security closure in PR #68

The final audit found and fixed concrete issues before submission:

- protected conditional aggregate oracle paths such as `COUNT(CASE...)` and filtered counts;
- cohort identity that previously discarded root SELECT predicates/thresholds/targets;
- temporal differencing from repeated protected releases without trusted warehouse snapshot identity;
- disclosure-state poisoning after failed execution;
- unkeyed-only receipt integrity;
- raw protected engine/database error leakage;
- broad default Docker Compose host binding.

The resulting controls include:

- conditional aggregate exposure classification and fail-closed policy;
- keyed cohort identity that preserves projection expressions while ignoring cosmetic aliases;
- conservative one-new-protected-release semantics until trusted snapshot identity exists;
- append-only `PENDING -> RELEASED | ABORTED` disclosure state;
- receipt schema 1.5 with content SHA-256 plus HMAC-SHA256 authenticity;
- fail-closed receipt-key handling and filename/payload identity checks;
- stable public authorization errors with sanitized protected execution failures;
- loopback-only default Compose publication.

Regression coverage includes threshold/subject mutation, concurrent reservations, aborted release handling, receipt semantic/ID/timestamp/governance tampering, attacker recomputation of public SHA without the HMAC key, wrong/missing HMAC key handling, execution-error sanitization, and secure deployment defaults.

## Final exact-image black-box validation

Validation-only PR #69 reran the independent production-image harness against the exact final security head. The validation branch itself was never merged.

Run `30145592349`: **24/24 PASS**.

- artifact ID `8615893443`;
- artifact digest `sha256:347c1cb66116367183a15e70a1ea892881cdfcf98321db581fbf10db5ae75d0a`;
- exact target `536c37c34de7b36495d33f63095585f72e5f4b46`;
- report SHA-256 `c857cf8856e1850124f5d0c6bff2a2cdcbf1baa01ea21372db5bcb9fbb8d6dd3`;
- failed probes `0`.

Coverage includes authentication/scope separation, request limits, rate limiting, fail-closed mutation and compositional sensitive export, legitimate low-risk execution, receipt ownership isolation, receipt mode `0600`, persisted-receipt tamper detection, restricted production API surface, TrustedHost, non-root/read-only container boundaries, capability drop, no-new-privileges, localhost exposure, and response/log leakage checks.

See [`final-security-blackbox.md`](final-security-blackbox.md) and [`final-security-blackbox.json`](final-security-blackbox.json).

## Final Live DataHub OSS + official MCP

Exact final security-head run `30143510876`: **PASS**.

Evidence artifact:

- artifact ID `8615316211`;
- digest `sha256:18552f336e1e0a785bb2a19c984726b175902f16323ad8092323959d8a6e1dd2`.

Diagnostics artifact:

- artifact ID `8615316546`;
- digest `sha256:4ecb6e0843e5804ac4c1f477b86e095e5398cbefb345573675a9f82f8e488922`.

The exact-head run proved:

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

Final exact-head seed report SHA-256: `538eef1abc7a02d1a0bcc939a51195831e78e8e6cb161400fbc3abf223f5f3b1`.

Final exact-head spike report SHA-256: `6f295f0c399474834d66413353b5218af5c098fdb6f9875088b43011bcd6f292`.

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

This is retained as frozen external validation of the earlier deep-security baseline. The final security head has separate exact-head CI, semantic/security regression, Live DataHub, and black-box evidence above; we do not relabel the historical external run as if it were regenerated.

## Supply-chain posture

The release lineage retains:

- committed Python and npm lockfiles consumed by CI/Docker;
- Python and npm dependency audits;
- Bandit SAST;
- CodeQL `security-extended`;
- CycloneDX SBOMs;
- immutable GitHub Action SHA pins;
- digest-pinned Docker base images;
- Dependabot.

One narrow machine-validated upstream-constrained exception remains documented under `docs/security/`: the current DataHub dependency profile constrains `setuptools` below the upstream fixed version. The exception is temporary, scoped, non-runtime-applicability justified, and expiring; it is not described as a full fix.

## Honest deployment modes

The hosted browser experience at `https://toxicjoin-replay.vercel.app/` is intentionally labeled **Deterministic Replay**. It is not represented as live DuckDB execution or a live DataHub mutation.

The Docker/FastAPI package is the executable product path. Real DataHub OSS/MCP behavior is proven independently by the exact-head gate above.

## Claim boundaries

ToxicJoin does not claim differential privacy, universal SQL repair, universal re-identification detection, formal verification, or legal-compliance certification. Unsupported SQL, unresolved/ambiguous lineage, missing/stale governance, failed rewrite, failed verification, integrity failure, or incomplete evidence fail closed.

Devpost remains **NOT SUBMITTED** until the final public demo video and explicit owner review/approval are complete.
