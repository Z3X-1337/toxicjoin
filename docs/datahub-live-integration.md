# Live DataHub Integration

This guide creates the governed ToxicJoin demo graph in DataHub OSS and proves the complete role-separated MCP path:

```text
read-only MCP child
→ DataHub asset/schema/lineage read
→ child closed
→ isolated document-write MCP child
→ Decision document write
→ child closed
→ fresh read-only MCP child
→ persisted Decision marker verification
```

Fixture mode is useful for deterministic testing, but it is never presented as live DataHub evidence. The integration is considered verified only after the final command exits successfully and writes a sanitized report.

## Requirements

- Python 3.11 or 3.12.
- Docker with enough memory for DataHub OSS.
- A local or hosted DataHub Graph Metadata Service endpoint.
- A read-scoped DataHub credential for MCP context acquisition/read-back when authentication is enabled.
- A separately scoped DataHub credential for the short-lived document-write MCP process when authentication is enabled.

## 1. Install the live integration

From the repository root:

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e '.[datahub]'
```

The optional extra pins the DataHub SDK used by the seed process and installs the stable MCP Python SDK. Fixture mode does not require these packages.

## 2. Start DataHub OSS

The official DataHub CLI provides the local quickstart:

```bash
datahub docker quickstart
```

Wait until the DataHub UI and GMS health checks are ready before continuing.

## 3. Configure environment variables

Do not commit populated credential variables.

Linux or macOS:

```bash
export DATAHUB_GMS_URL=http://localhost:8080
# Used by the DataHub SDK seed/bootstrap tooling.
export DATAHUB_GMS_TOKEN=replace-with-sdk-token
# Used only by role-separated MCP children.
export DATAHUB_GMS_READ_TOKEN=replace-with-read-scoped-token
export DATAHUB_GMS_WRITE_TOKEN=replace-with-document-write-scoped-token
export DATAHUB_MCP_COMMAND=uvx
export DATAHUB_MCP_ARGS=mcp-server-datahub
export DATAHUB_MCP_TIMEOUT_SECONDS=30
```

Windows PowerShell:

```powershell
$env:DATAHUB_GMS_URL = "http://localhost:8080"
$env:DATAHUB_GMS_TOKEN = "replace-with-sdk-token"
$env:DATAHUB_GMS_READ_TOKEN = "replace-with-read-scoped-token"
$env:DATAHUB_GMS_WRITE_TOKEN = "replace-with-document-write-scoped-token"
$env:DATAHUB_MCP_COMMAND = "uvx"
$env:DATAHUB_MCP_ARGS = "mcp-server-datahub"
$env:DATAHUB_MCP_TIMEOUT_SECONDS = "30"
```

For an authentication-disabled local quickstart, keep all required token variables explicitly set to a non-secret placeholder. They may contain the same placeholder only because the local server is auth-disabled. A secure deployment must provision distinct server-side scopes for read and document-write credentials. ToxicJoin does not fall back from either MCP role to the legacy ambiguous token.

Do not set broad MCP mutation flags globally for ToxicJoin. The role-bound settings construct the exact child environment and intentionally keep DataHub's broad metadata mutation family disabled in **all** ToxicJoin MCP processes.

## 4. Create the deterministic warehouse

```bash
toxicjoin-seed
```

This writes synthetic DuckDB data under `.toxicjoin/`. It contains no real identities, email addresses, phone numbers, or user data.

## 5. Seed governed DataHub metadata

```bash
toxicjoin-datahub-seed --yes
```

The seed command uses the DataHub SDK rather than the role-separated MCP path. It explicitly upserts:

- the five ToxicJoin datasets;
- 19 schema fields;
- controlled sensitivity tags;
- glossary terms used by the policy engine;
- field-level tag and glossary-term associations;
- four table and column-lineage relationships into `retention_scores`.

It writes a sanitized report to:

```text
.toxicjoin/datahub-seed.json
```

The report contains counts, dataset URNs, and a content hash. It contains no token, password, raw warehouse row, or DataHub URL.

## 6. Run the MCP verification spike

```bash
toxicjoin-datahub-spike --verify
```

The spike performs the following checks:

1. launches a read-only official `mcp-server-datahub` process;
2. keeps broad metadata mutations off and document writes off;
3. validates read contracts and rejects mutation-tool exposure;
4. reads configured entities, governed schema fields, and upstream lineage;
5. closes the read-only process;
6. launches a separate document-write MCP process with the write credential;
7. keeps broad metadata mutations off and enables only the independently controlled `save_document` capability;
8. validates the required `save_document` Decision contract and rejects broad metadata-mutation tool exposure;
9. writes one sanitized DataHub `Decision` with a unique verification marker;
10. closes the writer;
11. launches a fresh read-only MCP process;
12. verifies persisted Decision content through `grep_documents` without trusting the writer response;
13. writes a sanitized evidence report containing separate role settings and discovered-tool inventories.

Successful output is written to:

```text
.toxicjoin/datahub-spike.json
```

A non-zero exit code means the integration is not verified. Do not use a failed or partial run as hackathon evidence.

## 7. Inspect the evidence

The seed report should show:

- `dataset_count: 5`
- `field_count: 19`
- `lineage_count: 4`

The spike report must show:

- `schema_version: 1.1`;
- `status: verified`;
- `independent_readback_verified: true`;
- `read_settings.role: read_only`;
- `write_settings.role: mutation`;
- `read_settings.metadata_mutations_enabled: false`;
- `write_settings.metadata_mutations_enabled: false`;
- `read_settings.document_write_enabled: false`;
- `write_settings.document_write_enabled: true`;
- all five configured dataset URNs;
- `save_document` absent from `read_discovered_tools`;
- `save_document` present in `write_discovered_tools`;
- no broad add/remove/set/update/create/delete/upsert/patch mutation tools in `write_discovered_tools`;
- `save_document` absent from `readback_discovered_tools`;
- a DataHub Decision document URN;
- a valid report SHA-256.

Also inspect the DataHub UI and confirm:

- the datasets and schema fields exist;
- field tags and glossary terms are visible;
- `retention_scores.churn_score` has upstream lineage;
- the verification Decision is linked to the configured assets.

## Security behavior

- Context acquisition and read-back run with read-only role settings.
- Read children explicitly set `TOOLS_IS_MUTATION_ENABLED=false` and `SAVE_DOCUMENT_TOOL_ENABLED=false` while keeping document read tools available.
- The isolated writer also keeps `TOOLS_IS_MUTATION_ENABLED=false`; it enables only `SAVE_DOCUMENT_TOOL_ENABLED=true`.
- The writer fails closed if broad metadata-mutation tools are discovered despite those settings.
- The application client independently prevents a read role from calling `save_decision`, and prevents the writer role from becoming the source of governed policy context.
- Read-only discovery fails closed if any mutation-shaped tools are exposed despite server settings.
- Child processes receive only operating-system/network variables and the selected DataHub credential they require.
- OpenAI, AWS, database, and unrelated application secrets are not forwarded.
- Every MCP initialization, tool discovery, and tool call has a hard timeout.
- Tool names and input contracts are validated at runtime before reads or writes.
- Unknown payload shapes, missing assets, duplicate fields, conflicting sensitivity labels, and incomplete pagination fail closed.
- The final read-back occurs in a fresh read-only MCP process, not from an in-memory write response.

## Troubleshooting

### `save_document` appears in a read-only process

This is a security failure, not a warning. Confirm the read MCP child receives:

```text
TOOLS_IS_MUTATION_ENABLED=false
DATAHUB_MCP_DOCUMENT_TOOLS_DISABLED=false
SAVE_DOCUMENT_TOOL_ENABLED=false
```

Document reads remain enabled so `grep_documents` can perform fresh-process verification; document writes must remain disabled.

### Broad mutation tools appear in the writer

This is also a security failure. The writer does **not** need DataHub's broad metadata mutation family. It must receive:

```text
TOOLS_IS_MUTATION_ENABLED=false
DATAHUB_MCP_DOCUMENT_TOOLS_DISABLED=false
SAVE_DOCUMENT_TOOL_ENABLED=true
```

If tools such as `add_*`, `remove_*`, `set_*`, `update_*`, `create_*`, `delete_*`, `upsert_*`, or `patch_*` are still exposed, treat the upstream MCP configuration as unsafe and do not use the evidence.

### Missing `save_document` in the writer

Confirm `SAVE_DOCUMENT_TOOL_ENABLED=true` for the isolated writer. ToxicJoin still validates the live `save_document` schema and fails if the required Decision contract is absent.

### Asset not returned

Run the seed command again, then confirm that `config/datahub-assets.json` matches the dataset URNs shown in DataHub.

### Unclassified field

Every field used by the policy must have exactly one supported sensitivity classification through a controlled tag or glossary term. Missing classification remains `UNCLASSIFIED` and blocks execution.

### Timeout

Increase `DATAHUB_MCP_TIMEOUT_SECONDS` only after confirming DataHub is healthy. Raising the timeout does not bypass contract or metadata validation.

## Evidence policy

The repository contains deterministic negative tests for credential separation, upstream tool exposure, application capability escalation, and the three-process protocol. A real `.toxicjoin/datahub-spike.json` report must be generated from the final demo environment and must satisfy the Live DataHub Evidence gate. Secrets and private endpoints must never be committed.
