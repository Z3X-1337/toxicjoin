# Read-Only DataHub Discovery for the Governed Agent — Day-12

This slice connects the planning-only Governed Agent context model to the existing trusted DataHub snapshot loader. It does not connect an LLM provider and does not add any execution, authorization, governance mutation, evidence trust, disclosure-history mutation, PPMC grammar control, or proof-validation authority to the agent.

## Architecture

The security-owned path is:

```text
DATAHUB_GMS_READ_TOKEN
  -> read_only_settings_from_env()
  -> ReadOnlyDataHubMcpSettings concrete credential type
  -> authority-owned identity registry (not stored on settings)
  -> commit role/source/endpoint/launcher/timeout/token fingerprint
  -> reject direct construction, copies, relabeling, endpoint mutation, or token mutation
  -> authority-owned detached registered constructor clone
  -> revalidate + issue a fresh registered runtime clone immediately before transport launch
  -> mutation_enabled=false
  -> TOOLS_IS_MUTATION_ENABLED=false
  -> SAVE_DOCUMENT_TOOL_ENABLED=false
  -> official MCP stdio transport
  -> RoleBoundDataHubMcpClient(role=READ_ONLY)
  -> reject any mutation-shaped tool exposure
  -> DataHubSnapshotLoader.load(require_mutations=false)
  -> validated DataHubSnapshot
  -> redacted snapshot serialization/revalidation
  -> canonical DataHub dataset-URN exact round-trip + Unicode control rejection
  -> redacted deterministic projection
  -> AgentDataContext (security_authoritative=false)
  -> trusted in-process AgentPlanner adapter
  -> untrusted remote/model output
```

The existing `DataHubSnapshotLoader` remains the ingestion/normalization authority. There is no second DataHub parser for the agent.

## Credential provenance and tool boundary

The planner-adapter call surface never receives DataHub credentials, raw GMS endpoints, MCP settings, MCP transport/session/client objects, tool definitions/handles, or mutation capability.

DataHub authority has concrete credential types:

- `ReadOnlyDataHubMcpSettings`, issued by `read_only_settings_from_env()` from `DATAHUB_GMS_READ_TOKEN`;
- `MutationDataHubMcpSettings`, issued by `mutation_settings_from_env()` from `DATAHUB_GMS_WRITE_TOKEN`.

Factory provenance is **not stored on the settings object**. There is no `_factory_seal`, token-fingerprint private attribute, or settings method capable of rebinding provenance. The authority module keeps a process-local identity registry keyed by the issued object's identity and a weak reference. Each registration commits the exact authority-relevant snapshot: concrete role/source, `gms_url`, launcher command/arguments, timeout, mutation flag, and a normalized bearer-token fingerprint.

A newly constructed or `BaseModel.model_copy(...)` object has a different identity and is therefore unregistered. Mutating an issued object's bearer, endpoint, launcher configuration, timeout, role/source, or mutation flag changes the captured security snapshot and invalidates the registration. The registry entry also verifies that its weak reference still points to the same object, preventing stale identity reuse.

The Agent never rebinds provenance. It asks `clone_read_only_settings_for_child()` for a detached constructor credential. That authority-owned function captures the supplied object once, compares that exact capture against the registry, and only then creates and registers a new read credential from the same validated snapshot. Invalid but well-formed objects return no clone; malformed internals are caught by the Agent's settings-redaction boundary.

The stored constructor clone is **not trusted indefinitely**. Every call to `discover()` asks the authority registry for another detached runtime clone immediately before transport creation. If trusted in-process code has accidentally or maliciously modified `discoverer._settings` after construction—including its `SecretStr`, endpoint, role, or launcher settings—the registry comparison fails and discovery collapses to `AGENT_DATAHUB_DISCOVERY_FAILED` before the transport factory runs.

Bearer capture requires an exact `SecretStr` wrapper and normalizes its secret through the base `str.__str__` descriptor to an exact built-in `str` before hashing or cloning. This defeats `str` subclasses with overridden `encode()`/`__str__()` behavior. Each issued clone receives a distinct `SecretStr`, so later mutation of a caller-retained bearer object cannot alter a subsequently used child credential.

Ordinary `model_copy(update=...)` also blocks authority/token fields as defense in depth, but registry identity and snapshot matching—not Pydantic copy ergonomics—are the authority boundary.

The read child always emits `TOOLS_IS_MUTATION_ENABLED=false` and `SAVE_DOCUMENT_TOOL_ENABLED=false`. Snapshot loading uses `RoleBoundDataHubMcpClient(role=READ_ONLY)`. If the read server exposes `save_document` or another mutation-shaped tool, discovery fails closed before metadata calls.

## Interpreter trust boundary

The process-local credential registry is **not a sandbox against arbitrary Python running in the same interpreter**. Any code with arbitrary in-process execution can inspect module globals, environment, objects, or monkey-patch trusted functions and is therefore inside ToxicJoin's trusted computing base.

Accordingly, `AgentPlanner` means a trusted in-process adapter around an untrusted remote/model planner. The model/provider receives only serialized sanitized planning data and its returned values are treated as hostile input. A planner implementation that itself consists of untrusted executable code must run in a separate process/container/sandbox; it may not be loaded as an `AgentPlanner` object in the credential-bearing ToxicJoin process.

This is a threat-model boundary, not a naming convention. ToxicJoin does not claim that Python leading underscores, weak references, Pydantic models, or the provenance registry can isolate arbitrary hostile code sharing the process.

## Sanitized planning projection

`AgentDataContext` contains only the source snapshot commitment, catalog version, logical dataset name and exact DataHub dataset URN, optional owner/domain labels, field paths, normalized sensitivity categories, sorted tags/glossary terms, and upstream lineage identity/category. Every context/dataset/field/lineage record remains `security_authoritative=false`.

These values are planning hints, not EvidenceClaims, trust resolutions, authorization facts, proof evidence, or a substitute for downstream evidence/policy evaluation.

## Fail-closed canonical DataHub identity

P0 accepts only:

```text
urn:li:dataset:(urn:li:dataPlatform:<platform>,<dataset>,<environment>)
```

Each component is percent-decoded as strict UTF-8, checked for empty values, whitespace, tuple delimiters, and every Unicode `C*` category, then re-encoded with security-owned safe characters and required to exact-round-trip. This rejects malformed escapes, DEL/zero-width controls, private-use/unassigned characters, hidden whitespace, non-canonical encodings, truncated structures, and empty components.

Incomplete lineage represented by `datahub_urn=None` is not silently dropped or fabricated; Agent projection fails closed with `AGENT_DATAHUB_LINEAGE_IDENTITY_UNRESOLVED`. Exact-URN lineage with `UNCLASSIFIED` may remain visible to the planner only because it stays explicitly non-authoritative.

## Error redaction

Constructor credential clone/provenance acquisition is a redacted settings boundary. Malformed credential internals become `AGENT_DATAHUB_SETTINGS_INVALID` with `from None`; a well-formed but unregistered/mutated/non-read credential becomes `AGENT_DATAHUB_READ_ROLE_REQUIRED`.

Runtime revalidation occurs inside the discovery I/O boundary. Any changed internal registered credential, transport/factory error, or MCP failure becomes `AGENT_DATAHUB_DISCOVERY_FAILED` with the external chain suppressed. Snapshot serialization/revalidation failures become `AGENT_DATAHUB_SNAPSHOT_INVALID`. Other projection failures become `AGENT_DATAHUB_PROJECTION_FAILED`.

## Live least-privilege coupling

`tests/security/test_datahub_mcp_least_privilege.py` feeds the real factory-issued read credential into `DataHubAgentDiscoverer`, exposes mutation tools from a fake read server, and requires failure before metadata calls.

`.github/workflows/datahub-live.yml` also runs `DataHubAgentDiscoverer` against DataHub OSS quickstart and verifies dedicated read provenance, role-separated MCP read/write/readback, real snapshot acquisition, non-authoritative Agent context, expected dataset/field/lineage counts, live semantic policy behavior, sanitized evidence, and absence of credential/endpoint/tool-control material from serialized Agent context.

## Non-goals

This slice does not give the Agent direct MCP access, authority to choose credentials/mutation mode, EvidenceClaim trust, SQL authorization/execution, governance/disclosure mutation, PPMC/CPCC/proof control, or self-validation authority.

It also does not provide an in-process sandbox for arbitrary hostile Python. Process isolation for untrusted executable planner code is mandatory and belongs at the provider/adapter deployment boundary.

Proposed SQL remains subject to independent governance/evidence reacquisition and downstream security evaluation before execution.

## Retarget provenance

PR #87 was merged into `main` as `d2498fce5bd44163c545286683de99fe165ed4f1` after explicit exact-head approval. PR #88 was then retargeted to that `main` merge. All earlier stacked or superseded-head evidence is development evidence only. The final head must obtain fresh exact-head CI, security workflows, Live DataHub evidence, production-container evidence, fresh Codex review, and a separate explicit owner merge approval.
