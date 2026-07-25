# Read-Only DataHub Discovery for the Governed Agent — Day-12

This slice connects the planning-only Governed Agent context model to the existing trusted DataHub snapshot loader. It does not connect an LLM provider and does not add any execution, authorization, governance mutation, evidence trust, disclosure-history mutation, PPMC grammar control, or proof-validation authority to the agent.

## Architecture

The security-owned path is:

```text
dedicated RoleBoundDataHubMcpSettings(role=READ_ONLY)
  -> reject legacy/ambiguous or mutation-role credentials
  -> mutation_enabled=false
  -> TOOLS_IS_MUTATION_ENABLED=false
  -> SAVE_DOCUMENT_TOOL_ENABLED=false
  -> official MCP stdio transport
  -> RoleBoundDataHubMcpClient(role=READ_ONLY)
  -> reject any mutation-shaped tool exposure
  -> DataHubSnapshotLoader.load(require_mutations=false)
  -> validated DataHubSnapshot
  -> fail-closed canonical dataset-URN validation
  -> redacted deterministic projection
  -> AgentDataContext (security_authoritative=false)
  -> untrusted planner
```

The existing `DataHubSnapshotLoader` remains the ingestion/normalization authority. There is no second DataHub parser for the agent.

## Credential and tool boundary

The planner never receives:

- DataHub credentials;
- raw GMS endpoint;
- `RoleBoundDataHubMcpSettings`;
- MCP transport/session/client objects;
- discovered MCP tool definitions;
- callable tools;
- mutation handles.

`DataHubAgentDiscoverer` requires a dedicated `RoleBoundDataHubMcpSettings(role=READ_ONLY)` credential. Generic legacy `DataHubMcpSettings` are rejected even when their `mutation_enabled` flag is false, because disabling tool registration does not attenuate the underlying DataHub token. A MUTATION-role settings object is likewise rejected rather than repurposing a writer credential for discovery.

The discoverer creates a private copy of the dedicated read settings. The read child always emits both `TOOLS_IS_MUTATION_ENABLED=false` and `SAVE_DOCUMENT_TOOL_ENABLED=false`. Snapshot loading is invoked with `require_mutations=false` through `RoleBoundDataHubMcpClient(role=READ_ONLY)`. If the read server nevertheless exposes `save_document` or another mutation-shaped tool, discovery fails closed before any metadata call is accepted.

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

## Fail-closed DataHub identity

A mere `urn:li:dataset:` prefix is not treated as resolved identity. P0 accepts only the canonical three-part dataset-URN structure used by the governed ToxicJoin asset manifest: a non-empty `urn:li:dataPlatform:<platform>` component, a non-empty dataset-name component, and a non-empty environment component inside the dataset tuple. Ambiguous, truncated, empty-component, whitespace-containing, or otherwise malformed dataset and lineage URNs fail closed.

The existing DataHub normalizer can represent incomplete lineage using a deterministic unresolved synthetic ref with `datahub_urn=None`. The agent projection does **not** silently drop such an edge and does not invent a trusted-looking URN. It rejects the discovery context with `AGENT_DATAHUB_LINEAGE_IDENTITY_UNRESOLVED`.

An upstream edge with a canonical DataHub dataset URN but category `UNCLASSIFIED` may be shown to the planner because it remains explicitly non-authoritative. Downstream security evaluation still fails closed where trusted classification is required.

## Error redaction

The pluggable transport/factory and MCP snapshot acquisition execute inside one untrusted I/O boundary. Any exception escaping that boundary—including a forged `AgentDataHubDiscoveryError`—is replaced with the stable `AGENT_DATAHUB_DISCOVERY_FAILED` error and raised `from None`. External exception text/chaining therefore cannot be trusted to cross into the agent-facing boundary.

Projection occurs only after the transport boundary has closed. Security-owned fixed identity failures retain finite stable error codes. Any other projection failure, including Pydantic validation caused by raw MCP-derived metadata, is collapsed to `AGENT_DATAHUB_PROJECTION_FAILED` with `from None` so raw input cannot leak through exception text or traceback. Regression coverage renders full propagated tracebacks and verifies planted credential/endpoint/metadata material is absent.

## Live least-privilege coupling

The existing DataHub least-privilege security suite now includes an agent-discovery regression that feeds the real `read_only_settings_from_env()` role-bound settings into `DataHubAgentDiscoverer`, exposes mutation tools from a fake read server, and requires failure before any metadata call. That security test is part of the `Live DataHub Evidence` workflow path filter, so future changes to this read-role boundary cannot bypass the live DataHub gate silently.

## Non-goals

This slice does not:

- give the agent direct MCP access;
- let the agent choose MCP settings or mutation mode;
- create or trust EvidenceClaims;
- authorize or execute SQL;
- alter PolicyEngine, PPMC, CPCC, proof, authorization, verifier, or disclosure semantics;
- claim that the planning context is objectively correct or current forever.

The proposed SQL remains subject to independent reacquisition/revalidation of governance and evidence before any security decision or execution.

## Retarget provenance

PR #87 was merged into `main` as `d2498fce5bd44163c545286683de99fe165ed4f1` after explicit exact-head approval. PR #88 was then retargeted to that `main` merge. All earlier stacked CI/review evidence is development evidence only and is not sufficient for final merge eligibility. The final head must obtain fresh exact-head CI, security workflows, Live DataHub evidence, production-container evidence, and fresh review before a merge decision.
