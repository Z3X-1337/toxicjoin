# Read-Only DataHub Discovery for the Governed Agent — Day-12

This slice connects the planning-only Governed Agent context model to the existing trusted DataHub snapshot loader. It does not connect an LLM provider and does not add any execution, authorization, governance mutation, evidence trust, disclosure-history mutation, PPMC grammar control, or proof-validation authority to the agent.

## Architecture

The security-owned path is:

```text
local DataHubMcpSettings
  -> force mutation_enabled=false on a private copy
  -> official MCP stdio transport
  -> DataHubMcpClient
  -> DataHubSnapshotLoader.load(require_mutations=false)
  -> validated DataHubSnapshot
  -> deterministic sanitized projection
  -> AgentDataContext (security_authoritative=false)
  -> untrusted planner
```

The existing `DataHubSnapshotLoader` remains the ingestion/normalization authority. There is no second DataHub parser for the agent.

## Credential and tool boundary

The planner never receives:

- `DATAHUB_GMS_TOKEN`;
- raw GMS endpoint;
- `DataHubMcpSettings`;
- MCP transport/session/client objects;
- discovered MCP tool definitions;
- callable tools;
- mutation handles.

`DataHubAgentDiscoverer` creates a private revalidated settings copy and always forces `mutation_enabled=false`, which makes the child MCP environment emit `TOOLS_IS_MUTATION_ENABLED=false` regardless of the caller's original setting.

Snapshot loading is invoked with `require_mutations=false`. A server may advertise additional tools, but the agent context does not serialize the discovered tool list and the discovery path never invokes `save_document` or another write operation.

## Sanitized planning projection

`AgentDataContext` contains only:

- exact `DataHubSnapshot.snapshot_sha256` commitment;
- catalog version;
- logical dataset name and exact DataHub dataset URN;
- optional owner/domain labels;
- field path;
- normalized sensitivity category label;
- sorted tags and glossary terms;
- upstream lineage dataset URN, field path, and category.

Every resulting context, dataset, field, and lineage record remains `security_authoritative=false`.

These labels are hints for planning. They are not EvidenceClaims, trust resolutions, authorization facts, proof evidence, or a substitute for the downstream DataHub evidence/policy path.

## Fail-closed lineage identity

The existing DataHub normalizer can represent incomplete lineage using a deterministic unresolved synthetic ref with `datahub_urn=None`.

The agent projection does **not** silently drop such an edge and does not invent a trusted-looking URN. It rejects the discovery context with `AGENT_DATAHUB_LINEAGE_IDENTITY_UNRESOLVED`.

An upstream edge with an exact DataHub dataset URN but category `UNCLASSIFIED` may be shown to the planner because it remains explicitly non-authoritative. Downstream security evaluation still fails closed where trusted classification is required.

## Error redaction

Transport and DataHub errors are converted to stable agent-discovery codes. External exception text is not propagated through this boundary because it may contain endpoint, credential, or payload details.

## Non-goals

This slice does not:

- give the agent direct MCP access;
- let the agent choose MCP settings or mutation mode;
- create or trust EvidenceClaims;
- authorize or execute SQL;
- alter PolicyEngine, PPMC, CPCC, proof, authorization, verifier, or disclosure semantics;
- claim that the planning context is objectively correct or current forever.

The proposed SQL remains subject to independent reacquisition/revalidation of governance and evidence before any security decision or execution.

## Stack discipline

This branch is intentionally stacked on PR #87 exact reviewed head `e91fc9cbb309a79286a4bb0434bcfae431655a95`. PR #87 must merge first under the owner's explicit exact-head approval gate. This slice must then be rebased/retargeted to the resulting `main` merge before it can be considered for merge.
