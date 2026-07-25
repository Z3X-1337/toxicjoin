# Read-Only DataHub Discovery for the Governed Agent — Day-12

This slice connects the planning-only Governed Agent context model to the existing trusted DataHub snapshot loader. It does not connect an LLM provider and does not add any execution, authorization, governance mutation, evidence trust, disclosure-history mutation, PPMC grammar control, or proof-validation authority to the agent.

## Architecture

The security-owned path is:

```text
DATAHUB_GMS_READ_TOKEN
  -> ReadOnlyDataHubMcpSettings concrete credential type
  -> reject legacy/base, writer type, or authority-field relabeling
  -> mutation_enabled=false
  -> TOOLS_IS_MUTATION_ENABLED=false
  -> SAVE_DOCUMENT_TOOL_ENABLED=false
  -> official MCP stdio transport
  -> RoleBoundDataHubMcpClient(role=READ_ONLY)
  -> reject any mutation-shaped tool exposure
  -> DataHubSnapshotLoader.load(require_mutations=false)
  -> validated DataHubSnapshot
  -> redacted snapshot serialization/revalidation
  -> canonical DataHub dataset-URN exact round-trip
  -> redacted deterministic projection
  -> AgentDataContext (security_authoritative=false)
  -> untrusted planner
```

The existing `DataHubSnapshotLoader` remains the ingestion/normalization authority. There is no second DataHub parser for the agent.

## Credential provenance and tool boundary

The planner never receives:

- DataHub credentials;
- raw GMS endpoint;
- read/write MCP settings;
- MCP transport/session/client objects;
- discovered MCP tool definitions;
- callable tools;
- mutation handles.

DataHub authority now has concrete credential types:

- `ReadOnlyDataHubMcpSettings`, sourced by `read_only_settings_from_env()` from `DATAHUB_GMS_READ_TOKEN`;
- `MutationDataHubMcpSettings`, sourced by `mutation_settings_from_env()` from `DATAHUB_GMS_WRITE_TOKEN`.

`DataHubAgentDiscoverer` accepts only the exact `ReadOnlyDataHubMcpSettings` type. Generic `DataHubMcpSettings`, the abstract role-bound base, and the writer concrete type are not eligible even if their fields appear to say `READ_ONLY`. This matters because disabling MCP mutation-tool registration does not attenuate the authority of the underlying DataHub token.

Authority-bearing fields (`role`, `mutation_enabled`, and `credential_source`) are locked against Pydantic `model_copy(update=...)`. More importantly, concrete Python type identity remains part of the Agent boundary: even bypassing that override through the base Pydantic implementation cannot transform a writer instance into the read credential class.

The discoverer creates a private `ReadOnlyDataHubMcpSettings` copy. The read child always emits both `TOOLS_IS_MUTATION_ENABLED=false` and `SAVE_DOCUMENT_TOOL_ENABLED=false`. Snapshot loading is invoked with `require_mutations=false` through `RoleBoundDataHubMcpClient(role=READ_ONLY)`. If the read server nevertheless exposes `save_document` or another mutation-shaped tool, discovery fails closed before metadata calls are accepted.

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

## Fail-closed canonical DataHub identity

A mere `urn:li:dataset:` prefix is not treated as resolved identity. P0 accepts only the three-part dataset-URN structure used by the governed ToxicJoin asset manifest:

```text
urn:li:dataset:(urn:li:dataPlatform:<platform>,<dataset>,<environment>)
```

Each component is percent-decoded as strict UTF-8, checked for empty/control/whitespace/delimiter values, then re-encoded with a security-owned safe-character set. The encoded component must exactly equal its input. This rejects malformed escapes such as `%ZZ`, non-canonical encoding of safe characters such as `%2F` where `/` is canonical, truncated structures, empty components, and hidden whitespace while still permitting canonical percent-encoded Unicode.

The existing DataHub normalizer can represent incomplete lineage using a deterministic unresolved synthetic ref with `datahub_urn=None`. The agent projection does **not** silently drop such an edge and does not invent a trusted-looking URN. It rejects the discovery context with `AGENT_DATAHUB_LINEAGE_IDENTITY_UNRESOLVED`.

An upstream edge with a canonical DataHub dataset URN but category `UNCLASSIFIED` may be shown to the planner because it remains explicitly non-authoritative. Downstream security evaluation still fails closed where trusted classification is required.

## Error redaction

The pluggable transport/factory and MCP snapshot acquisition execute inside one untrusted I/O boundary. Any exception escaping that boundary—including a forged `AgentDataHubDiscoveryError`—is replaced with the stable `AGENT_DATAHUB_DISCOVERY_FAILED` error and raised `from None`.

Snapshot serialization and revalidation form a second redacted boundary. This is necessary because `DataHubSnapshot.lineage_sample` intentionally contains `dict[str, Any]`; a malicious/non-JSON value can make Pydantic serialization itself fail before ordinary validation. Every serialization/revalidation exception is collapsed to `AGENT_DATAHUB_SNAPSHOT_INVALID` with exception chaining suppressed.

After successful revalidation, security-owned fixed identity failures retain finite stable codes. Any other projection failure, including Pydantic validation caused by raw MCP-derived metadata, is collapsed to `AGENT_DATAHUB_PROJECTION_FAILED` with `from None`. Regression coverage renders complete propagated tracebacks and verifies planted credential/endpoint/metadata/type material is absent.

## Live least-privilege coupling

`tests/security/test_datahub_mcp_least_privilege.py` feeds the real `read_only_settings_from_env()` concrete read credential into `DataHubAgentDiscoverer`, exposes mutation tools from a fake read server, and requires failure before any metadata call.

In addition, `.github/workflows/datahub-live.yml` watches `src/toxicjoin/agent/**` directly and runs `DataHubAgentDiscoverer` itself against DataHub OSS quickstart. The live step verifies dedicated read provenance, mutation-disabled child settings, real snapshot acquisition, non-authoritative Agent context, expected dataset/field/lineage counts, and absence of credential/endpoint/tool-control material from serialized Agent context. A sanitized Agent discovery report is included in the Live DataHub evidence artifact.

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

PR #87 was merged into `main` as `d2498fce5bd44163c545286683de99fe165ed4f1` after explicit exact-head approval. PR #88 was then retargeted to that `main` merge. All earlier stacked or superseded-head evidence is development evidence only. The final head must obtain fresh exact-head CI, security workflows, Live DataHub evidence, production-container evidence, fresh Codex review, and a separate explicit owner merge approval.
