# ToxicJoin Live DataHub Evidence

## Result

The complete live integration gate passed against a real DataHub OSS quickstart on **July 23, 2026**.

- GitHub Actions run: https://github.com/Z3X-1337/toxicjoin/actions/runs/29975433969
- Tested branch commit: `26a4322130a6f56a7e3fd71e831e27b924bb433d`
- Verified evidence Artifact: `toxicjoin-live-datahub-evidence`
- Artifact ID: `8551281664`
- Artifact digest: `sha256:5d7d8e33b9d47dbd3cab1fa74a29789f3c76268d2cae57896ea94c09bbada0f9`

The retained reports are committed beside this document:

- [`datahub-live-seed.json`](datahub-live-seed.json)
- [`datahub-live-spike.json`](datahub-live-spike.json)

## What was proven

### Official DataHub SDK seed

The official DataHub Python SDK created the deterministic ToxicJoin governance graph:

- **5** datasets;
- **19** governed schema fields;
- **9** controlled tags;
- **7** glossary terms;
- **4** column-lineage writes.

Seed report content hash:

```text
b0141731ffd72f8e33b7e447e80f1f359b6bf795fac9f059dca1e769ec4546d8
```

### Official DataHub MCP read, write, and independent read-back

The official DataHub MCP Server was launched from the pinned Python package:

```text
uvx --from mcp-server-datahub==0.6.0 mcp-server-datahub
```

ToxicJoin then:

1. discovered the runtime MCP tools and validated their input contracts;
2. read the five configured dataset entities;
3. paginated and normalized all governed schema fields;
4. read **3** upstream column-lineage relationships for the flagship `retention_scores.churn_score` field;
5. wrote a DataHub `Decision` document through `save_document`;
6. closed the MCP process that performed the write;
7. opened a fresh MCP process;
8. used `grep_documents` with the returned document URN;
9. found the unique verification marker inside the persisted document content.

Persisted Decision document URN:

```text
urn:li:document:shared-8d25384c-c52d-4864-a103-1203b0c34bf6
```

MCP report content hash:

```text
7ddcfa735d574ecc96c89dc82f357248efc58e96c9fd338be9eb6084b33ddc4b
```

## Hash verification

Both `report_sha256` values are calculated over canonical JSON with the `report_sha256` property removed. UTC timestamps use the same `Z` representation in both the calculated payload and persisted JSON.

A regression test reconstructs each report through its strict Pydantic model, serializes it exactly as persisted, and requires the hash to remain reproducible:

```text
tests/unit/test_datahub_report_hashes.py
```

Manual inspection of the final Artifact independently reproduced both report hashes.

## Sanitization review

The retained evidence does not contain:

- the DataHub token value;
- passwords or unrelated application secrets;
- the local DataHub endpoint;
- raw warehouse rows;
- receipt result rows;
- local filesystem paths.

The report states only that a token was present, the URL scheme, the pinned MCP launch arguments, bounded timeout configuration, governed entity URNs, counts, hashes, and the Decision verification evidence.

## Scope and limitation

This evidence proves ToxicJoin's SDK and MCP integration against a real ephemeral DataHub OSS deployment created inside GitHub Actions. The temporary DataHub UI and Decision URN are not a permanently hosted public DataHub environment.

The public hosted site remains a clearly labeled deterministic Replay for immediate judge access. The Docker/FastAPI package remains the executable ToxicJoin product path. This document must not be used to describe the hosted Replay as a live DataHub session.
