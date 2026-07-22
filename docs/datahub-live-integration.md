# Live DataHub Integration

This guide creates the governed ToxicJoin demo graph in DataHub OSS and proves the complete MCP path:

```text
DataHub asset read
→ governed schema and tag read
→ column-lineage read
→ Decision document write
→ MCP session closed
→ fresh MCP session
→ Decision read-back and marker verification
```

Fixture mode is useful for deterministic testing, but it is never presented as live DataHub evidence. The integration is considered verified only after the final command exits successfully and writes a sanitized report.

## Requirements

- Python 3.11 or 3.12.
- Docker with enough memory for DataHub OSS.
- A local or hosted DataHub Graph Metadata Service endpoint.
- A DataHub access token when authentication is enabled.

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

Copy `.env.example` values into your shell. Do not commit a populated `.env` file.

Linux or macOS:

```bash
export DATAHUB_GMS_URL=http://localhost:8080
export DATAHUB_GMS_TOKEN=replace-with-datahub-token
export DATAHUB_MCP_COMMAND=uvx
export DATAHUB_MCP_ARGS=mcp-server-datahub
export DATAHUB_MCP_TIMEOUT_SECONDS=30
```

Windows PowerShell:

```powershell
$env:DATAHUB_GMS_URL = "http://localhost:8080"
$env:DATAHUB_GMS_TOKEN = "replace-with-datahub-token"
$env:DATAHUB_MCP_COMMAND = "uvx"
$env:DATAHUB_MCP_ARGS = "mcp-server-datahub"
$env:DATAHUB_MCP_TIMEOUT_SECONDS = "30"
```

For an authentication-disabled local quickstart, keep the token variable explicitly set to a non-secret placeholder. ToxicJoin refuses to guess whether a missing token was intentional.

## 4. Create the deterministic warehouse

```bash
toxicjoin-seed
```

This writes synthetic DuckDB data under `.toxicjoin/`. It contains no real identities, email addresses, phone numbers, or user data.

## 5. Seed governed DataHub metadata

```bash
toxicjoin-datahub-seed --yes
```

The command upserts:

- the five ToxicJoin datasets;
- 19 schema fields;
- controlled sensitivity tags;
- glossary terms used by the policy engine;
- field-level tag and glossary-term associations;
- four table and column-lineage relationships into `retention_scores`.

The command is explicit about mutation and writes a sanitized report to:

```text
.toxicjoin/datahub-seed.json
```

The report contains counts, dataset URNs, and a content hash. It contains no token, password, raw warehouse row, or DataHub URL.

## 6. Run the MCP verification spike

```bash
toxicjoin-datahub-spike --verify
```

The spike performs the following checks:

1. launches the official `mcp-server-datahub` process;
2. discovers the available MCP tools at runtime;
3. verifies the required tool input schemas;
4. reads the configured dataset entities;
5. reads all governed schema fields with bounded pagination;
6. reads upstream column lineage for the flagship churn score;
7. writes a DataHub `Decision` document with a unique verification marker;
8. closes the MCP process and session;
9. launches a second independent MCP process and session;
10. reads the Decision entity back and verifies the marker;
11. writes a sanitized evidence report.

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

- `status: verified`
- `independent_readback_verified: true`
- all five configured dataset URNs;
- `save_document` among discovered tools;
- a DataHub Decision document URN;
- a valid report SHA-256.

Also inspect the DataHub UI and confirm:

- the datasets and schema fields exist;
- field tags and glossary terms are visible;
- `retention_scores.churn_score` has upstream lineage;
- the verification Decision is linked to the configured assets.

## Security behavior

- MCP mutations are enabled only in the child process created for this integration.
- The child process receives only operating-system/network variables and the DataHub variables it requires.
- OpenAI, AWS, database, and unrelated application secrets are not forwarded.
- Every MCP initialization, tool discovery, and tool call has a hard timeout.
- Tool names and input contracts are validated at runtime before reads or writes.
- Unknown payload shapes, missing assets, duplicate fields, conflicting sensitivity labels, and incomplete pagination fail closed.
- The final read-back occurs in a fresh MCP process, not from an in-memory write response.

## Troubleshooting

### Missing `save_document`

Confirm the MCP child process has mutation and document tools enabled. ToxicJoin sets:

```text
TOOLS_IS_MUTATION_ENABLED=true
DATAHUB_MCP_DOCUMENT_TOOLS_DISABLED=false
```

The spike still verifies the live tool contract and fails if `save_document` is absent.

### Asset not returned

Run the seed command again, then confirm that `config/datahub-assets.json` matches the dataset URNs shown in DataHub.

### Unclassified field

Every field used by the policy must have exactly one supported sensitivity classification through a controlled tag or glossary term. Missing classification remains `UNCLASSIFIED` and blocks execution.

### Timeout

Increase `DATAHUB_MCP_TIMEOUT_SECONDS` only after confirming DataHub is healthy. Raising the timeout does not bypass contract or metadata validation.

## Evidence policy

The committed repository contains tests of the full protocol over deterministic fake MCP transports. A real `.toxicjoin/datahub-spike.json` report should be generated from the final demo environment and captured in screenshots or video, but secrets and private endpoints must never be committed.
