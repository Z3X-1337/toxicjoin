# ToxicJoin Live DataHub Evidence

This document records the real DataHub OSS + official MCP validation for the final security-remediated ToxicJoin head.

## Exact final security-head run

Validated production head:

```text
536c37c34de7b36495d33f63095585f72e5f4b46
```

Landed `main` merge commit:

```text
ee4991a93070c148e41dd158c952d5f1e9a6ed2c
```

GitHub Actions run: `30143510876` — **PASS**.

Evidence artifact:

- artifact ID `8615316211`;
- digest `sha256:18552f336e1e0a785bb2a19c984726b175902f16323ad8092323959d8a6e1dd2`.

Diagnostics artifact:

- artifact ID `8615316546`;
- digest `sha256:4ecb6e0843e5804ac4c1f477b86e095e5398cbefb345573675a9f82f8e488922`.

The sanitized reports from this exact run are committed beside this document:

- [`datahub-live-seed.json`](datahub-live-seed.json)
- [`datahub-live-spike.json`](datahub-live-spike.json)

## Official DataHub SDK seed

The locked DataHub profile created the deterministic ToxicJoin governance graph inside a real ephemeral DataHub OSS quickstart:

- **5 datasets**;
- **19 governed schema fields**;
- **10 controlled tags**;
- **7 glossary terms**;
- **4 lineage writes**.

Final security-head seed report SHA-256:

```text
538eef1abc7a02d1a0bcc939a51195831e78e8e6cb161400fbc3abf223f5f3b1
```

The seed contains synthetic ToxicJoin metadata only.

## Official MCP role-separated protocol

The official DataHub MCP Server was pinned as:

```text
uvx --from mcp-server-datahub==0.6.0 mcp-server-datahub
```

ToxicJoin executed this authority sequence:

1. launch a **read-only** MCP process;
2. reject mutation-tool exposure in the read process;
3. read governed dataset entities and schema fields;
4. acquire upstream column lineage and normalize it into one governed snapshot;
5. close the read process;
6. launch an isolated writer using separate write authority;
7. retain the raw upstream writer inventory honestly;
8. wrap the writer with a mandatory ToxicJoin allowlist whose effective inventory is exactly `save_document`;
9. write one sanitized DataHub `Decision` document;
10. close the writer process;
11. launch a fresh read-only MCP process;
12. independently verify the persisted Decision marker.

The writer response itself is not accepted as persistence proof.

## Final spike schema 1.3

The final security-head run reports:

- `status = verified`;
- `independent_readback_verified = true`;
- 5 verified dataset entities;
- 3 upstream lineage relationships;
- 2 lineage-bound fields;
- 6 normalized lineage sources;
- 0 unclassified lineage sources;
- read and fresh-read-back inventories contain no mutation tools;
- raw writer inventory contains the broader upstream mutation surface registered by MCP 0.6.x;
- effective ToxicJoin writer inventory is exactly `['save_document']`.

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

Final security-head spike report SHA-256:

```text
6f295f0c399474834d66413353b5218af5c098fdb6f9875088b43011bcd6f292
```

## Why DataHub is on the authorization path

This is not a decorative metadata screenshot. The gate loads a real DataHub snapshot through the read-only MCP boundary and passes normalized governed context into the actual ToxicJoin policy path.

The flagship lineage is asserted before evaluating a known unsafe individual composition, and the policy must return `BLOCK` with `COMPOSITIONAL_REIDENTIFICATION_RISK`.

Governance provenance is freshness-bounded and carried through decision, execution authorization, pre-execution revalidation, and receipts so stale or changed metadata cannot silently authorize a different context.

## Upstream writer constraint

`mcp-server-datahub 0.6.x` registers `save_document` inside a broader mutation-registration path. The raw writer server can therefore expose additional mutation tools.

ToxicJoin does not hide this constraint. It records the raw inventory and enforces a narrower application-visible capability through `ToolAllowlistTransport`:

```text
write_discovered_tools == ['save_document']
```

A broad raw upstream inventory is a documented dependency fact. A broad effective ToxicJoin writer inventory is treated as a security failure.

## Sanitization review

The retained evidence contains no:

- DataHub credential value;
- password;
- private/local endpoint value;
- raw warehouse row;
- receipt result row;
- unrelated application secret;
- local filesystem path.

The reports retain only bounded configuration facts, URNs, counts, tool names, lineage evidence, status, and hashes needed to audit the integration.

## Scope

This proves the final security head against a real ephemeral DataHub OSS deployment inside GitHub Actions using the official MCP server. It does not claim that the temporary DataHub UI or Decision URN is permanently hosted.

The public browser experience remains a clearly labeled **Deterministic Replay**. The Docker/FastAPI package is the executable product path.

For the complete final release lineage and all exact-head gates, see [`release-candidate.md`](release-candidate.md).
