# Live DataHub Integration

This guide reproduces the stable ToxicJoin DataHub path using real DataHub OSS and the official MCP Server.

Verified authority sequence:

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

Fixture mode is useful for deterministic judging, but is never presented as live DataHub evidence.

## Release-tested versions

The deep-security baseline used:

- Python 3.11 for the live gate;
- `acryl-datahub==1.6.0.15`;
- `mcp-server-datahub==0.6.0`;
- `uv==0.8.4`;
- committed `uv.lock` with `uv sync --frozen --extra datahub`.

The final runtime candidate `e139fa99bd666505ed83a18188423722405695a2` changes only the package-owned fixture benchmark evidence constant relative to this baseline. No DataHub dependency or integration source changed.

The optional Agent Registry preview uses a separate conflicting dependency profile and is not part of this stable path.

## 1. Install the locked live profile

```bash
python -m pip install --disable-pip-version-check 'uv==0.8.4'
uv sync --frozen --extra datahub
```

Activate `.venv` or invoke commands from `.venv/bin` / `.venv\Scripts`.

## 2. Start DataHub OSS

Linux/macOS:

```bash
.venv/bin/datahub docker quickstart
```

Windows uses the equivalent `.venv\Scripts\datahub.exe` command.

Wait for the DataHub UI and GMS health checks.

## 3. Configure role-separated MCP environment

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

PowerShell:

```powershell
$env:DATAHUB_GMS_URL = "http://localhost:8080"
$env:DATAHUB_GMS_TOKEN = "replace-with-sdk-token"
$env:DATAHUB_GMS_READ_TOKEN = "replace-with-read-scoped-token"
$env:DATAHUB_GMS_WRITE_TOKEN = "replace-with-document-write-scoped-token"
$env:DATAHUB_MCP_COMMAND = "uvx"
$env:DATAHUB_MCP_ARGS = "--from mcp-server-datahub==0.6.0 mcp-server-datahub"
$env:DATAHUB_MCP_TIMEOUT_SECONDS = "90"
```

For an authentication-disabled local quickstart, required token variables may contain an explicit non-secret placeholder. Secure deployment should provision distinct read/write authority; ToxicJoin does not silently fall back from either MCP role to an ambiguous legacy token.

Do not set mutation flags globally. ToxicJoin constructs the child environment per role.

## 4. Create the synthetic warehouse

```bash
.venv/bin/toxicjoin-seed
```

The warehouse is written under ignored `.toxicjoin/`.

## 5. Seed governed DataHub metadata

```bash
.venv/bin/toxicjoin-datahub-seed --yes
```

Verified deterministic counts:

- 5 datasets;
- 19 governed schema fields;
- 10 controlled tags;
- 7 glossary terms;
- 4 lineage writes.

Sanitized local report:

```text
.toxicjoin/datahub-seed.json
```

## 6. Bootstrap document search for the CI protocol

The MCP document-content path must be indexed before the write/read-back test. The exact GitHub Actions gate creates a small synthetic bootstrap document and waits for search readiness.

For authoritative reproduction details, inspect `.github/workflows/datahub-live.yml`. Do not weaken or skip its document-index readiness assertions when collecting release evidence.

## 7. Run the MCP verification spike

```bash
.venv/bin/toxicjoin-datahub-spike --verify
```

The spike:

1. launches a read-only MCP child;
2. forces mutation registration and `save_document` off for that process;
3. validates read contracts and rejects mutation-tool exposure;
4. reads configured entities, governed fields, and lineage;
5. closes the read child;
6. launches a distinct writer with write authority;
7. enables the upstream mutation-registration path needed by MCP 0.6.x to register `save_document`;
8. wraps the raw writer in mandatory `ToolAllowlistTransport` with effective surface exactly `save_document`;
9. records raw upstream writer inventory separately;
10. writes one sanitized DataHub `Decision`;
11. closes the writer;
12. launches a fresh read-only MCP child;
13. verifies the persisted Decision marker independently;
14. writes a sanitized report.

Local report:

```text
.toxicjoin/datahub-spike.json
```

Any non-zero exit status means the live integration is not verified.

## 8. Verified spike invariants

The retained deep-security run produced schema `1.3` and verified:

- `status: verified`;
- `independent_readback_verified: true`;
- read role `read_only`;
- writer role `mutation`;
- no mutation tools exposed by read/read-back processes;
- raw writer inventory contains `save_document`;
- effective ToxicJoin writer inventory exactly `["save_document"]`;
- 3 upstream lineage relationships;
- 2 lineage-bound fields;
- 6 normalized lineage sources;
- 0 unclassified lineage sources;
- valid DataHub Decision URN and content hash.

Flagship `retention_scores.churn_score` upstream source keys:

```text
location_activity.activity_count
location_activity.precise_area
orders.purchase_amount
support_cases.case_category
support_cases.sensitivity_level
```

Normalized upstream categories:

```text
PUBLIC_OR_LOW_RISK
QUASI_IDENTIFIER
SENSITIVE_ATTRIBUTE
```

## MCP 0.6.x writer constraint

In `mcp-server-datahub 0.6.x`, `save_document` is registered inside the general mutation-registration path. Disabling that path prevents registration of `save_document` itself.

Therefore the **raw writer MCP process can register broader mutation tools**. ToxicJoin does not claim otherwise.

The security boundary is the mandatory ToxicJoin transport allowlist:

```text
write_discovered_tools == ["save_document"]
```

A broad raw inventory is an upstream implementation fact. A broad effective ToxicJoin writer inventory is a security failure.

## Security behavior

- Read and fresh-read-back processes are server-level read-only.
- Writer authority uses a distinct credential and process.
- The writer client cannot be a governed-context source.
- Child processes receive only the selected DataHub credential plus minimal OS/network environment.
- Unrelated application secrets are not forwarded.
- MCP initialization/discovery/calls have hard timeouts.
- Missing assets, conflicting classifications, unknown shapes, incomplete pagination, incomplete lineage, or stale governance fail closed.
- Live governance is freshness-bounded and bound through authorization/execution.
- Fresh read-back never trusts the writer response as persistence proof.

## Retained evidence and final-candidate relationship

Deep-security baseline:

```text
fe4f8da2579e09bdbfb1d998b92dfea86549733b
```

passed Live DataHub run `30136824466`.

Final runtime candidate:

```text
e139fa99bd666505ed83a18188423722405695a2
```

adds only the corrected fixture benchmark evidence constant; no DataHub source or dependency changed. The complete applicability argument and exact-head post-fix validation are documented in [`evidence/release-candidate.md`](evidence/release-candidate.md).

See:

- [`evidence/datahub-live.md`](evidence/datahub-live.md)
- [`evidence/datahub-live-seed.json`](evidence/datahub-live-seed.json)
- [`evidence/datahub-live-spike.json`](evidence/datahub-live-spike.json)
- [`evidence/release-candidate.md`](evidence/release-candidate.md)

## Troubleshooting rule

Do not make the live gate pass by weakening tool exposure, freshness, lineage completeness, or read-back assertions. A failure is evidence to diagnose, not a reason to broaden authority.