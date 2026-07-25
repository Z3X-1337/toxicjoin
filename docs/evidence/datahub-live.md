# ToxicJoin Live DataHub Evidence

## Verified deep-security baseline

The stable ToxicJoin DataHub integration passed against a real DataHub OSS quickstart on:

```text
fe4f8da2579e09bdbfb1d998b92dfea86549733b
```

GitHub Actions run: `30136824466`.

This is the **deep-security baseline** for final runtime candidate `e139fa99bd666505ed83a18188423722405695a2`. The only later runtime-source correction is the package-owned fixture benchmark evidence constant served by `/api/benchmark/summary`; no DataHub integration, context, lineage, policy-rule, authorization, executor, verifier, dependency, Docker, or workflow code changed.

The final release index documents that relationship explicitly: [`release-candidate.md`](release-candidate.md).

Evidence artifact:

- name `toxicjoin-live-datahub-evidence`;
- artifact ID `8613145981`;
- digest `sha256:b90596ffc15f298511abd1e79c97e987f92f5fdb820bf9525a7ac3fc0bce27f8`.

Diagnostics artifact:

- artifact ID `8613146120`;
- digest `sha256:075d9fb6b01f55013068ec08717bd522af6724898d081540eaf0401521a2872c`.

The sanitized reports from that run are committed beside this document:

- [`datahub-live-seed.json`](datahub-live-seed.json)
- [`datahub-live-spike.json`](datahub-live-spike.json)

## Official DataHub SDK seed

The locked stable DataHub profile created the deterministic ToxicJoin governance graph:

- **5 datasets**;
- **19 governed schema fields**;
- **10 controlled tags**;
- **7 glossary terms**;
- **4 lineage writes**.

Seed report SHA-256:

```text
161788c3f70caa37ddaa5972759eb498f10dae6631e9bb4f74fc22893dfd9e47
```

The seed contains only synthetic ToxicJoin metadata.

## Official MCP role-separated protocol

The official DataHub MCP Server was pinned as:

```text
uvx --from mcp-server-datahub==0.6.0 mcp-server-datahub
```

ToxicJoin executed this authority sequence:

1. launch a **read-only** MCP process;
2. reject mutation-tool exposure in the read process;
3. read the configured dataset entities and all governed schema fields;
4. acquire upstream column lineage and normalize it into one governed snapshot;
5. close the read process;
6. launch an isolated writer using separate write authority;
7. retain the raw upstream writer inventory honestly;
8. wrap that writer with a mandatory ToxicJoin allowlist whose effective inventory is exactly `save_document`;
9. write one sanitized DataHub `Decision`;
10. close the writer process;
11. launch a fresh read-only MCP process;
12. independently verify the persisted Decision marker.

The writer response itself is not accepted as persistence proof.

## Spike schema 1.3

The verified run reports:

- `status = verified`;
- `independent_readback_verified = true`;
- 5 verified dataset entities;
- 3 upstream lineage relationships;
- 2 lineage-bound fields;
- 6 normalized lineage sources;
- 0 unclassified lineage sources;
- read and fresh-read-back inventories contain no mutation tools;
- raw writer inventory contains the upstream mutation surface required by MCP 0.6.x;
- effective ToxicJoin writer inventory is exactly `["save_document"]`.

Flagship upstream source keys for `retention_scores.churn_score`:

```text
location_activity.activity_count
location_activity.precise_area
orders.purchase_amount
support_cases.case_category
support_cases.sensitivity_level
```

Normalized flagship upstream categories:

```text
PUBLIC_OR_LOW_RISK
QUASI_IDENTIFIER
SENSITIVE_ATTRIBUTE
```

Spike report SHA-256:

```text
d3650b38505870e0cb864913c1f9dfa56665a209f9c95cee637f32b003cf3b5e
```

## Why DataHub is on the authorization path

This evidence is not a metadata screenshot. The gate loads a real DataHub snapshot through the read-only MCP boundary and passes normalized governed context into the actual ToxicJoin policy path.

The flagship lineage is asserted before evaluating a known unsafe individual composition, and the policy must return `BLOCK` with `COMPOSITIONAL_REIDENTIFICATION_RISK`.

The governance snapshot is freshness-bounded. Governance provenance is carried through decision, execution authorization, pre-execution revalidation, and receipts so stale or changed metadata cannot silently authorize a different context.

## Upstream writer constraint

`mcp-server-datahub 0.6.x` registers `save_document` inside the broader mutation-registration path. The raw writer server can therefore expose other mutation tools.

ToxicJoin does not hide or misrepresent that constraint. It records the raw inventory and enforces a narrower effective capability through `ToolAllowlistTransport`:

```text
write_discovered_tools == ["save_document"]
```

A broad raw server inventory is an upstream fact. A broad effective ToxicJoin writer inventory is a security failure.

## Sanitization review

The retained evidence contains no:

- DataHub credential value;
- password;
- private/local endpoint value;
- raw warehouse row;
- receipt result row;
- unrelated application secret;
- local filesystem path.

The reports retain only bounded configuration facts, URNs, counts, tool names, lineage evidence, status, and content hashes needed to audit the integration.

## Scope

This proves the stable SDK/MCP integration against a real ephemeral DataHub OSS deployment inside GitHub Actions. It does not claim the temporary DataHub UI or Decision URN is permanently hosted.

The public browser site remains a clearly labeled deterministic Replay. The Docker/FastAPI package remains the executable product path.

For the final runtime candidate, exact-head post-fix gates, frozen external replay, black-box pentest, and applicability notes, see [`release-candidate.md`](release-candidate.md).