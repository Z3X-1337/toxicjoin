# Live DataHub Integration

This guide creates the governed ToxicJoin demo graph in DataHub OSS and proves the complete role-separated MCP path:

```text
read-only MCP child
→ DataHub asset/schema/lineage read
→ child closed
→ isolated writer MCP child
→ save_document-only ToxicJoin transport
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
- A separately scoped DataHub credential for the short-lived writer when authentication is enabled.

## 1. Install the live integration

```bash
python -m venv .venv
# Linux/macOS: source .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e '.[datahub]'
```

## 2. Start DataHub OSS

```bash
datahub docker quickstart
```

Wait until the DataHub UI and GMS health checks are ready before continuing.

## 3. Configure environment variables

Do not commit populated credential variables.

Linux or macOS:

```bash
export DATAHUB_GMS_URL=http://localhost:8080
# DataHub SDK seed/bootstrap tooling.
export DATAHUB_GMS_TOKEN=replace-with-sdk-token
# Role-separated MCP children.
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

For an authentication-disabled local quickstart, keep all required token variables explicitly set to a non-secret placeholder. They may be equal only because the local server is auth-disabled. A secure deployment must provision distinct server-side scopes for read and write credentials. ToxicJoin does not fall back from either MCP role to the legacy ambiguous token.

Do not set DataHub mutation flags globally. ToxicJoin constructs the child environment per role.

## 4. Create the deterministic warehouse

```bash
toxicjoin-seed
```

This writes synthetic DuckDB data under `.toxicjoin/`.

## 5. Seed governed DataHub metadata

```bash
toxicjoin-datahub-seed --yes
```

The SDK seed path upserts the demo datasets, schema fields, sensitivity governance, glossary associations, and lineage. It writes sanitized evidence to:

```text
.toxicjoin/datahub-seed.json
```

## 6. Run the MCP verification spike

```bash
toxicjoin-datahub-spike --verify
```

The spike performs these checks:

1. launches a read-only `mcp-server-datahub` child;
2. forces `TOOLS_IS_MUTATION_ENABLED=false` and `SAVE_DOCUMENT_TOOL_ENABLED=false`;
3. validates read contracts and rejects mutation-tool exposure;
4. reads configured entities, governed schema fields, and lineage;
5. closes that child;
6. launches a separate writer child with `DATAHUB_GMS_WRITE_TOKEN`;
7. enables the upstream mutation-registration path required by `mcp-server-datahub 0.6.x` to register `save_document`;
8. wraps the raw writer transport in a mandatory allowlist containing only `save_document`;
9. records the raw upstream writer inventory separately from the effective ToxicJoin writer inventory;
10. validates the required `save_document` Decision contract and writes one sanitized Decision;
11. closes the writer child;
12. launches a fresh read-only MCP child;
13. verifies persisted Decision content through `grep_documents` without trusting the writer response;
14. writes a sanitized evidence report.

Successful output is written to:

```text
.toxicjoin/datahub-spike.json
```

A non-zero exit code means the integration is not verified.

## Upstream 0.6.x constraint

In the pinned `mcp-server-datahub 0.6.x` implementation, `save_document` is registered from inside the general mutation-registration path. If `TOOLS_IS_MUTATION_ENABLED=false`, registration returns before `save_document` can be added, even when `SAVE_DOCUMENT_TOOL_ENABLED=true`.

ToxicJoin tested the stronger configuration and retained the failed Live DataHub evidence. The failure was `missing tool save_document` after DataHub startup, metadata seed, and document bootstrap had all succeeded.

Therefore the writer child must enable the upstream mutation-registration path. This means its **raw server tool inventory can contain broad mutation tools**. ToxicJoin does not hide that fact. Instead, the raw inventory is retained in evidence and a mandatory transport allowlist prevents any tool except `save_document` from being discovered or called by ToxicJoin writer code.

## 7. Inspect the evidence

The seed report should show the expected deterministic dataset, field, and lineage counts.

The spike report must show:

- `schema_version: 1.2`;
- `status: verified`;
- `independent_readback_verified: true`;
- `read_settings.role: read_only`;
- `write_settings.role: mutation`;
- `read_settings.document_write_enabled: false`;
- `write_settings.document_write_enabled: true`;
- `read_settings.writer_transport_allowlist: []`;
- `write_settings.writer_transport_allowlist: ["save_document"]`;
- `save_document` absent from `read_discovered_tools`;
- `save_document` present in `write_server_discovered_tools`;
- `write_discovered_tools` exactly equal to `["save_document"]`;
- `write_discovered_tools` is a subset of `write_server_discovered_tools`;
- `save_document` absent from `readback_discovered_tools`;
- a DataHub Decision document URN;
- a valid report SHA-256.

`write_server_discovered_tools` is intentionally the honest raw server inventory. Broad tools there are an upstream constraint, not a successful ToxicJoin capability. Broad tools in `write_discovered_tools` are a security failure.

Also inspect the DataHub UI and confirm the governed datasets, schema fields, lineage, and verification Decision exist.

## Security behavior

- Context acquisition and read-back are server-level read-only processes.
- Read children force metadata mutations off and `save_document` off while preserving document reads such as `grep_documents`.
- The writer uses a distinct credential and process.
- The writer's upstream server registration is broader than the desired operation because of the 0.6.x constraint.
- `ToolAllowlistTransport` filters discovery to `save_document` and rejects every other writer call before delegation.
- The role-bound writer client fails closed if it is accidentally connected directly to an unfiltered broad transport.
- The writer client cannot become the source of governed policy context.
- Child processes receive only the selected DataHub credential plus minimal OS/network environment.
- OpenAI, AWS, database, and unrelated application secrets are not forwarded.
- MCP initialization, discovery, and calls have hard timeouts.
- Unknown payload shapes, missing assets, conflicting classifications, and incomplete pagination fail closed.
- Fresh read-back occurs in a new read-only process.

## Troubleshooting

### `save_document` appears in a read-only process

This is a security failure. The read child must receive:

```text
TOOLS_IS_MUTATION_ENABLED=false
DATAHUB_MCP_DOCUMENT_TOOLS_DISABLED=false
SAVE_DOCUMENT_TOOL_ENABLED=false
```

### `save_document` is missing from the writer

For `mcp-server-datahub 0.6.x`, the writer child requires:

```text
TOOLS_IS_MUTATION_ENABLED=true
DATAHUB_MCP_DOCUMENT_TOOLS_DISABLED=false
SAVE_DOCUMENT_TOOL_ENABLED=true
```

Do not interpret this as permission for ToxicJoin to use the other registered mutation tools. The writer must remain isolated and must be wrapped by the save-only transport allowlist.

### Broad mutation tools appear in `write_server_discovered_tools`

This is expected under the pinned upstream registration model and is retained for transparency. Verify that:

```text
write_discovered_tools == ["save_document"]
```

If a broad tool appears in `write_discovered_tools`, the integration is unsafe and the evidence must be rejected.

### Asset not returned

Run the seed command again and confirm `config/datahub-assets.json` matches the dataset URNs shown in DataHub.

### Unclassified field

Every field used by policy must have exactly one supported sensitivity classification. Missing classification remains `UNCLASSIFIED` and blocks execution.

### Timeout

Increase `DATAHUB_MCP_TIMEOUT_SECONDS` only after confirming DataHub is healthy. Raising the timeout does not bypass contract or authority validation.

## Evidence policy

The repository contains deterministic negative tests for credential separation, read-role mutation exposure, the writer transport allowlist, direct blocked mutation calls, unfiltered-writer misuse, and the three-process protocol. A real `.toxicjoin/datahub-spike.json` report must be generated from the final demo environment and satisfy Live DataHub Evidence. Secrets and private endpoints must never be committed.
