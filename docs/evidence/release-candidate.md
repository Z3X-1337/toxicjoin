# ToxicJoin Final Release Candidate Evidence

This page is the authoritative judge-facing index for the release-frozen ToxicJoin runtime candidate.

## Exact runtime candidate

```text
fe4f8da2579e09bdbfb1d998b92dfea86549733b
```

That commit was promoted to `main` by non-forced fast-forward after validation, so no new production SHA was introduced at promotion time. Subsequent release-close work may advance `main` with documentation/evidence-only commits; those commits do not alter the audited runtime tree. All production and independent-validation results below refer to `fe4f8da2579e09bdbfb1d998b92dfea86549733b` exactly.

Policy version: `0.2.0`.

## Exact-head production gates

All of these workflows completed successfully against the candidate above:

| Gate | Run |
|---|---:|
| CI — Python 3.11 / 3.12, Web, hardened Container | `30136824481` |
| CodeQL | `30136824457` |
| Governance Dependency Evidence | `30136824433` |
| Adversarial Mutation Evidence | `30136824442` |
| Compositional Ablation Evidence | `30136824435` |
| Disclosure Sequence Evidence | `30136824441` |
| Supply Chain Security | `30136824509` |
| Live DataHub Agent Registry | `30136824472` |
| Live DataHub Evidence | `30136824466` |
| Verify Hosted Replay | `30136824439` |

## Balanced benchmark

Final CI artifact:

- artifact ID `8613113482`;
- artifact digest `sha256:4f46fdf293e2e6fc8174a30cfa7b825e4e65028483808db6f2732607360363a5`;
- policy `0.2.0`;
- 30 cases: 10 ALLOW / 10 REWRITE / 10 BLOCK;
- 30/30 expected initial decisions;
- 30/30 expected effective outcomes;
- 30/30 expected reason codes;
- zero false allows;
- zero unsafe effective allows;
- six rewrites remediated to verified ALLOW;
- four rewrite paths failed closed;
- 16 verified executions;
- report SHA-256 `3aadc0b357db50641c8ffdc0525dde0e3d9159f933abf62a31a6a74b777d1b08`.

See [`benchmark.md`](benchmark.md) and [`benchmark-summary.json`](benchmark-summary.json).

## Adversarial mutation gate

Final artifact:

- run `30136824442`;
- artifact ID `8613091317`;
- artifact digest `sha256:cffba65a8394ddb6fc497f6e93d3934d1a12cc20f5e08e82b1e28bf775cb8a65`;
- policy `0.2.0`;
- 144/144 initial BLOCK;
- 144/144 effective BLOCK;
- 144/144 intended `COMPOSITIONAL_REIDENTIFICATION_RISK`;
- zero database executions;
- zero unsafe initial/effective allows;
- report SHA-256 `86011fc74ef6ca03e7b83d21e8770037fb32ddb22d41b750abc09aeabe443565`.

See [`adversarial-mutations.md`](adversarial-mutations.md).

## Compositional interaction ablation

Final artifact:

- run `30136824435`;
- artifact ID `8613091689`;
- artifact digest `sha256:b89575b68e927cc5edb7c7072bfbed926c0e3feeb511d4b2ff53ddd63e247fcf`;
- evaluation version `2.0`, policy `0.2.0`;
- shipped policy blocks 144/144 unsafe mutations;
- targeted interaction ablation allows 144/144 unsafe mutations;
- all 20 ALLOW/REWRITE controls remain unchanged;
- report SHA-256 `14d7fb64be2c838966fffe0e8f20273cba3877255da767e99f04df980f4f5cdf`.

See [`compositional-ablation.md`](compositional-ablation.md).

## Governance dependency

Final artifact:

- run `30136824433`;
- artifact ID `8613089999`;
- artifact digest `sha256:a73eafdd701019f36eac27a1fcc5a81df52f697bfe66e5961295ab77d6bcb690`;
- policy `0.2.0`;
- complete governance: REWRITE -> ALLOW -> verified execution;
- unclassified field: BLOCK, no execution;
- missing field: BLOCK, no execution;
- missing governed dataset: BLOCK, no execution;
- zero unsafe effective allows under degraded governance;
- report SHA-256 `25c1b7c189a8ca248723138df2065ddb0669a9f4f46f6e7abe8f81b7b1a48d9f`.

See [`governance-dependency.md`](governance-dependency.md).

## Live DataHub OSS + official MCP

Final Live DataHub run `30136824466` validated the same release candidate.

Evidence artifact:

- artifact ID `8613145981`;
- digest `sha256:b90596ffc15f298511abd1e79c97e987f92f5fdb820bf9525a7ac3fc0bce27f8`.

Verified seed:

- 5 datasets;
- 19 governed fields;
- 10 controlled tags;
- 7 glossary terms;
- 4 lineage writes;
- seed report SHA-256 `161788c3f70caa37ddaa5972759eb498f10dae6631e9bb4f74fc22893dfd9e47`.

Verified MCP spike schema `1.3`:

- role-separated read-only snapshot -> isolated writer -> fresh read-only read-back;
- effective writer tool inventory exactly `save_document`;
- independent Decision read-back verified;
- 3 upstream lineage relationships;
- 2 lineage-bound fields;
- 6 normalized lineage sources;
- zero unclassified lineage sources;
- flagship upstream source keys include `location_activity.activity_count`, `location_activity.precise_area`, `orders.purchase_amount`, `support_cases.case_category`, and `support_cases.sensitivity_level`;
- spike report SHA-256 `d3650b38505870e0cb864913c1f9dfa56665a209f9c95cee637f32b003cf3b5e`.

See [`datahub-live.md`](datahub-live.md), [`datahub-live-seed.json`](datahub-live-seed.json), and [`datahub-live-spike.json`](datahub-live-spike.json).

## Frozen external 24-task replay

Validation-only PR #38 reused the original frozen E01–E24 tasks, SQL proposals, risk labels, expected execution semantics, baseline artifact, and UCI warehouse fingerprint without resampling or post-result edits.

Run `30137303763`: PASS.

- artifact ID `8613263087`;
- digest `sha256:b3988c8f9a43e7cdafe53384279eda91d3c04c92751dd4c93c918c234a3e422a`;
- exact target PR `54`;
- exact candidate `fe4f8da2579e09bdbfb1d998b92dfea86549733b`;
- 24 tasks;
- effective decisions: 1 ALLOW / 23 BLOCK;
- E01 executes;
- E18 / E20 / E24 BLOCK and never execute;
- zero unsafe MUST_NOT_EXECUTE executions;
- zero unsafe grouped-sensitive executions;
- no patient rows in sanitized evidence;
- report SHA-256 `beb02e39ad2fe4838f78def0c8d0e5d8d396876845c29a758223d87464ff2cf9`.

The validation PR was closed without merge.

## Exact release-candidate black-box pentest

Validation-only PR #55 built the Docker image from the detached exact candidate and interacted with it externally through HTTP and container inspection.

Final run `30138071361`: **24/24 PASS**.

- artifact ID `8613510441`;
- digest `sha256:28dca12c6cab143f5d77e1b0e92c9d66c37af0fa0a1a9aacfb192101d0d25a0e`;
- report SHA-256 `1582cd741818da3d2d9c6de97cd3cec52b7e1ba584b384b6211fdccc10a48b1f`.

The probes covered authentication and scope separation, request limits, rate limiting, fail-closed mutation and sensitive export, legitimate stateful ALLOW, receipt ownership isolation, persisted-receipt tamper detection, restricted API surface, non-root/read-only container boundaries, capability drop, no-new-privileges, and response/log leakage checks.

The validation PR was closed without merge.

## Supply-chain closure

The release candidate also has:

- committed Python and npm lockfiles consumed by CI/Docker;
- Python and npm dependency audits;
- Bandit SAST;
- CodeQL `security-extended`;
- CycloneDX SBOM generation;
- immutable GitHub Action SHA pins;
- digest-pinned Docker base images;
- Dependabot;
- a machine-validated, narrow, expiring upstream-blocked `setuptools` exception documented under `docs/security/`.

## Release state

The runtime product is release-frozen. No feature, refactor, dependency, or policy changes are authorized before submission unless a proven release blocker requires reopening the candidate. Documentation/evidence-only synchronization does not redefine or silently revalidate the runtime candidate.

The hosted browser experience remains a clearly labeled deterministic Replay. The Docker/FastAPI package is the executable path. Devpost submission remains separate from this technical evidence and requires explicit owner approval.