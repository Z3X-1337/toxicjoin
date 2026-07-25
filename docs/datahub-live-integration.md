# Live DataHub Integration

This guide reproduces the stable ToxicJoin DataHub path using real DataHub OSS and the official MCP Server.

The verified authority sequence is:

```text
read-only MCP child
  -> DataHub entity/schema/lineage snapshot
  -> child closed
isolated writer MCP child
  -> ToxicJoin ToolAllowlistTransport exposes only save_document
  -> Decision document write
  -> child closed
fresh read-only MCP child
  -> persisted Decision marker verification
```

Fixture mode is useful for deterministic judging, but it is never presented as live DataHub evidence.

## Release-tested versions

The final release candidate used:

- Python 3.11 for the live gate;
- `acryl-datahub==1.6.0.15`;
- `mcp-server-datahub==0.6.0`;
- `uv==0.8.4`;
- the committed `uv.lock` with `uv sync --frozen --extra datahub`.

The optional Agent Registry preview uses a separate conflicting dependency profile and is not part of this stable path.

## 1. Install the locked live profile

```bash
python -m pip install --disable-pip-version-check 'uv==0.8.4'
uv sync --frozen --extra datahub
```

Activate `.venv` or invoke commands from `.venv/bin` / `.venv\Scripts` as appropriate.

## 2. Start DataHub OSS

```bash
.venv/bin/datahub docker quickstart
```

On Windows, use the equivalent `.venv\Scripts\datahub.exe` command.

Wait for the DataHub UI and GMS health checks to become ready.

## 3. Configure the role-separated MCP environment

Do not commit populated credentials.

Linux/macOS example:

```bash
export DATAHUB_GMS_URL=http://localhost:8080
export DATAHUB_GMS_TOKEN=replace-with-sdk-token
export DATAHUB_GMS_READ_TOKEN=replace-with-read-scoped-token
export DATAHUB_GMS_WRITE_TOKEN=replace-with-document-write-scoped-token
export DATAHUB_MCP_COMMAND=uvx
export 'DATAHUB_MCP_ARGS=--from mcp-server-datahub==0.6.0 mcp-server-datahub'
export DATAHUB_MCP_TIMEOUT_SECONDS=90
```

PowerShell example:

```powershell
$env:DATAHUB_GMS_URL = "http://localhost:8080"
$env:DATAHUB_GMS_TOKEN = "replace-with-sdk-token"
$env:DATAHUB_GMS_READ_TOKEN = "replace-with-read-scoped-token"
$env:DATAHUB_GMS_WRITE_TOKEN = "replace-with-document-write-scoped-token"
$env:DATAHUB_MCP_COMMAND = "uvx"
$env:DATAHUB_MCP_ARGS = "--from mcp-server-datahub==0.6.0 mcp-server-datahub"
$env:DATAHUB_MCP_TIMEOUT_SECONDS = "90"
```

For an authentication-disabled local quickstart, the required token variables may contain an explicit non-secret placeholder. A secure deployment should provision distinct read and write authority; ToxicJoin does not silently fall back from either role to the legacy ambiguous token.

Do not configure mutation flags globally. ToxicJoin constructs a minimal child environment per role.

## 4. Create the deterministic warehouse

```bash
.venv/bin/toxicjoin-seed
```

The warehouse is synthetic and stored under `.toxicjoin/`, which is ignored by Git.

## 5. Seed governed DataHub metadata

```bash
.venv/bin/toxicjoin-datahub-seed --yes
```

The final release gate expects the deterministic seed to contain:

- 5 datasets;
- 19 governed schema fields;
- 10 controlled tags;
- 7 glossary terms;
- 4 lineage writes.

The sanitized local report is written to:

```text
.toxicjoin/datahub-seed.json
```

## 6. Bootstrap document search when reproducing the CI protocol

The official MCP document-content tools rely on the DataHub document/search path being available. The exact GitHub Actions gate creates and waits for a small synthetic bootstrap document before the MCP verification run.

For authoritative reproduction details, inspect `.github/workflows/datahub-live.yml`. Do not weaken or skip its document-index readiness assertions when collecting release evidence.

## 7. Run the MCP verification spike

```bash
.venv/bin/toxicjoin-datahub-spike --verify
```

The spike:

1. launches a read-only MCP child;
2. forces mutation registration and `save_document` off for that process;
3. validates read tool contracts and rejects mutation-tool exposure;
4. reads the configured entities, all governed schema fields, and lineage;
5. closes the read child;
6. launches a distinct writer child using the write credential;
7. enables the upstream mutation-registration path required by `mcp-server-datahub 0.6.x` to register `save_document`;
8. wraps that raw writer in a mandatory `ToolAllowlistTransport` whose effective surface is exactly `save_document`;
9. records the broader upstream writer inventory separately rather than hiding it;
10. writes one sanitized DataHub `Decision`;
11. closes the writer child;
12. launches a fresh read-only MCP child;
13. verifies the persisted Decision marker using document search/read tooling;
14. writes a sanitized evidence report.

The local spike report is:

```text
.toxicjoin/datahub-spike.json
```

Any non-zero exit status means the live integration is not verified.

## 8. Final spike invariants

The final release candidate produced spike schema `1.3` and required:

- `status: verified`;
- `independent_readback_verified: true`;
- read role `read_only`;
- writer role `mutation`;
- no `save_document` or other mutation tools exposed by read/read-back processes;
- raw writer inventory contains `save_document`;
- effective ToxicJoin writer inventory equals exactly `["save_document"]`;
- effective writer inventory is a subset of the raw upstream writer inventory;
- 3 upstream lineage relationships;
- 2 lineage-bound fields;
- 6 normalized lineage sources;
- 0 unclassified lineage sources;
- a valid DataHub Decision document URN;
- a valid content hash.

For the flagship `retention_scores.churn_score` field, the normalized upstream source keys are:

```text
location_activity.activity_count
location_activity.precise_area
orders.purchase_amount
support_cases.case_category
support_cases.sensitivity_level
```

The normalized upstream categories include:

```text
PUBLIC_OR_LOW_RISK
QUASI_IDENTIFIER
SENSITIVE_ATTRIBUTE
```

## Upstream MCP 0.6.x constraint

In the pinned `mcp-server-datahub 0.6.x`, `save_document` is registered inside the general mutation-registration path. Disabling that path prevents the writer from receiving `save_document` at all.

Therefore the **raw writer MCP process can register broader mutation tools**. ToxicJoin does not claim otherwise.

The security boundary is the mandatory ToxicJoin transport allowlist:

```text
write_discovered_tools == ["save_document"]
```

A broad tool appearing in `write_server_discovered_tools` is an upstream implementation fact. A broad tool appearing in ToxicJoin's effective `write_discovered_tools` is a security failure.

## Security behavior

- Read and fresh-read-back processes are server-level read-only.
- Writer authority uses a separate credential and process.
- The writer client cannot be used as a governed-context source.
- Child processes receive only the selected DataHub credential plus the minimal OS/network environment.
- Unrelated OpenAI, AWS, database, and application secrets are not forwarded.
- MCP initialization, discovery, and calls have hard timeouts.
- Missing assets, conflicting classifications, unknown response shapes, incomplete pagination, incomplete lineage, or stale governance fail closed.
- Live governance is freshness-bounded and bound through authorization/execution to prevent silent metadata drift.
- Fresh read-back never trusts the writer response as proof of persistence.

## Final retained evidence

The exact release candidate `fe4f8da2579e09bdbfb1d998b92dfea86549733b` passed Live DataHub run `30136824466`.

See:

- [`evidence/datahub-live.md`](evidence/datahub-live.md)
- [`evidence/datahub-live-seed.json`](evidence/datahub-live-seed.json)
- [`evidence/datahub-live-spike.json`](evidence/datahub-live-spike.json)
- [`evidence/release-candidate.md`](evidence/release-candidate.md)

## Troubleshooting rule

Do not make the live gate pass by weakening tool exposure, freshness, lineage completeness, or read-back assertions. A failure is evidence to diagnose, not a reason to broaden authority.