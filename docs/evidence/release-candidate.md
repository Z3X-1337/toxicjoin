# ToxicJoin Final Release Evidence

This is the authoritative judge-facing release index.

## Final runtime candidate

```text
e139fa99bd666505ed83a18188423722405695a2
```

Policy version: `0.2.0`.

The only runtime-source difference from the previously deep-validated baseline `fe4f8da2579e09bdbfb1d998b92dfea86549733b` is `src/toxicjoin/benchmark/evidence.py`: its packaged judge-facing benchmark identity was corrected from stale policy `0.1.0` / old report SHA to the already-measured final policy `0.2.0` / report SHA `3aadc0b357db50641c8ffdc0525dde0e3d9159f933abf62a31a6a74b777d1b08`.

The remaining changes in the release-cleanup PR are documentation/evidence synchronization. No parser, policy rule, rewriter, executor, verifier, authentication, disclosure, DataHub integration, dependency, Docker, or workflow behavior changed.

## Exact-head validation after the correction

The corrected runtime candidate `e139fa99bd666505ed83a18188423722405695a2` passed:

| Gate | Run | Result |
|---|---:|---:|
| CI — Python 3.11 / 3.12, Web, hardened Container | `30140102648` | PASS |
| CodeQL | `30140102673` | PASS |
| Supply Chain Security | `30140102634` | PASS |
| Governance Dependency Evidence | `30140102647` | PASS |
| Adversarial Mutation Evidence | `30140102676` | PASS |
| Compositional Ablation Evidence | `30140102635` | PASS |

The generated benchmark artifact on that exact SHA is:

- artifact ID `8614180997`;
- digest `sha256:3adec180defa9338fe970068f47bc3a479ceae2817941f41b8c7f32c8f4a10d6`;
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

The same exact candidate also reproduced the security evidence without outcome drift:

### Governance dependency

- run `30140102647`;
- artifact `8614165940`;
- digest `sha256:b9bf5e1770b19ad46a597da7ab743ab50536b349f46a7305f661b27687bfe7fb`;
- complete governance: REWRITE -> ALLOW -> verified execution;
- three degraded-governance states: BLOCK, no execution;
- zero unsafe effective allows;
- report SHA-256 `25c1b7c189a8ca248723138df2065ddb0669a9f4f46f6e7abe8f81b7b1a48d9f`.

### Adversarial mutations

- run `30140102676`;
- artifact `8614165343`;
- digest `sha256:41cf4a8203cbb11fb331c3e78630113de7d498e4732d77c0605dd78f0563ebd1`;
- 144/144 initial BLOCK;
- 144/144 effective BLOCK;
- intended compositional-risk reason 144/144;
- zero database executions;
- zero unsafe allows;
- report SHA-256 `86011fc74ef6ca03e7b83d21e8770037fb32ddb22d41b750abc09aeabe443565`.

### Compositional interaction ablation

- run `30140102635`;
- artifact `8614165227`;
- digest `sha256:36a54ac332ab18a343742090fb3c04559b84813d5434d8171500b64972874d1e`;
- evaluation version `2.0`;
- shipped policy blocks 144/144 unsafe mutations;
- targeted interaction ablation allows 144/144;
- all 20 ALLOW/REWRITE controls preserved;
- report SHA-256 `14d7fb64be2c838966fffe0e8f20273cba3877255da767e99f04df980f4f5cdf`.

See [`benchmark.md`](benchmark.md), [`governance-dependency.md`](governance-dependency.md), [`adversarial-mutations.md`](adversarial-mutations.md), and [`compositional-ablation.md`](compositional-ablation.md).

## Deep security / DataHub baseline

Before the judge-facing benchmark-summary correction, runtime baseline `fe4f8da2579e09bdbfb1d998b92dfea86549733b` passed the full P4/P5 closure. The correction does not touch any subsystem exercised below.

Exact-head baseline runs:

| Gate | Run |
|---|---:|
| CI | `30136824481` |
| CodeQL | `30136824457` |
| Governance Dependency Evidence | `30136824433` |
| Adversarial Mutation Evidence | `30136824442` |
| Compositional Ablation Evidence | `30136824435` |
| Disclosure Sequence Evidence | `30136824441` |
| Supply Chain Security | `30136824509` |
| Live DataHub Agent Registry | `30136824472` |
| Live DataHub Evidence | `30136824466` |
| Verify Hosted Replay | `30136824439` |

### Live DataHub OSS + official MCP

Run `30136824466`:

- evidence artifact `8613145981`;
- digest `sha256:b90596ffc15f298511abd1e79c97e987f92f5fdb820bf9525a7ac3fc0bce27f8`;
- 5 datasets;
- 19 governed fields;
- 10 controlled tags;
- 7 glossary terms;
- 4 lineage writes;
- seed report SHA-256 `161788c3f70caa37ddaa5972759eb498f10dae6631e9bb4f74fc22893dfd9e47`;
- spike schema `1.3`;
- role-separated read-only snapshot -> isolated writer -> fresh read-only read-back;
- effective writer inventory exactly `save_document`;
- independent Decision read-back verified;
- 3 upstream lineage relationships;
- 2 lineage-bound fields;
- 6 normalized lineage sources;
- zero unclassified lineage sources;
- spike report SHA-256 `d3650b38505870e0cb864913c1f9dfa56665a209f9c95cee637f32b003cf3b5e`.

See [`datahub-live.md`](datahub-live.md).

### Frozen external 24-task v2

Validation-only PR #38 reused the unchanged frozen tasks, SQL proposals, risk labels, expected execution semantics, baseline artifact, and UCI warehouse fingerprint.

Run `30137303763`: PASS.

- artifact `8613263087`;
- digest `sha256:b3988c8f9a43e7cdafe53384279eda91d3c04c92751dd4c93c918c234a3e422a`;
- exact baseline candidate `fe4f8da2579e09bdbfb1d998b92dfea86549733b`;
- 24 tasks;
- 1 ALLOW / 23 BLOCK;
- E01 executes;
- E18 / E20 / E24 BLOCK and never execute;
- zero unsafe MUST_NOT_EXECUTE executions;
- zero unsafe grouped-sensitive executions;
- no patient rows in sanitized evidence;
- report SHA-256 `beb02e39ad2fe4838f78def0c8d0e5d8d396876845c29a758223d87464ff2cf9`.

PR #38 was closed without merge.

### Exact-image black-box pentest

Validation-only PR #55 built the Docker image from the exact baseline and interacted with it through HTTP and container inspection.

Run `30138071361`: **24/24 PASS**.

- artifact `8613510441`;
- digest `sha256:28dca12c6cab143f5d77e1b0e92c9d66c37af0fa0a1a9aacfb192101d0d25a0e`;
- report SHA-256 `1582cd741818da3d2d9c6de97cd3cec52b7e1ba584b384b6211fdccc10a48b1f`.

Coverage included authentication/scope separation, request limits, rate limiting, fail-closed mutation and sensitive export, legitimate stateful ALLOW, receipt ownership isolation, persisted-receipt tamper detection, restricted API surface, non-root/read-only container boundaries, capability drop, no-new-privileges, and response/log leakage checks.

PR #55 was closed without merge.

## Why the deep baseline remains applicable

The post-P5 source correction changes only the packaged benchmark evidence object returned by the unrestricted fixture judge endpoint `/api/benchmark/summary`. The deep external replay exercises policy/parser/rewrite/verification/execution behavior; the black-box pentest exercises authenticated/restricted security boundaries where `/api/benchmark/summary` is intentionally not exposed; the Live DataHub gate exercises DataHub context/lineage/write-back paths. None of those code paths changed.

The corrected candidate nevertheless reran CI, CodeQL, Supply Chain, Governance Dependency, Adversarial Mutation, and Compositional Ablation on its exact SHA, and all passed.

## Supply-chain posture

The release lineage retains:

- committed Python and npm lockfiles consumed by CI/Docker;
- Python and npm dependency audits;
- Bandit SAST;
- CodeQL `security-extended`;
- CycloneDX SBOMs;
- immutable GitHub Action SHA pins;
- digest-pinned Docker base images;
- Dependabot;
- the narrow, machine-validated, expiring upstream-blocked `setuptools` exception documented under `docs/security/`.

Dependabot update PRs created after freeze were closed without merge; Dependabot remains enabled for post-submission maintenance.

## Release state

`e139fa99bd666505ed83a18188423722405695a2` is the final audited runtime candidate. Later commits in the release-cleanup PR are documentation/evidence-only provenance synchronization and do not alter the runtime tree.

No feature, refactor, dependency, policy, or enforcement change is authorized before submission unless a new proven release blocker requires reopening the candidate.

The hosted browser experience remains a clearly labeled deterministic Replay. The Docker/FastAPI package is the executable path. Devpost remains NOT SUBMITTED pending explicit owner review and approval.