# Threat-Model Delta — P3-A DataHub MCP Least Privilege

Date: 2026-07-24

## Scope

P3-A closes TJ-SEC-016 for ToxicJoin's official DataHub MCP execution paths. Before this change, the same mutation-capable MCP settings/process were used to acquire governed context, write the verification Decision, and perform fresh-process read-back. A compromise or prompt/tool-routing defect in a context-acquisition path therefore inherited unnecessary DataHub mutation capability.

P3-A separates DataHub MCP authority by process, credential variable, upstream tool exposure, transport capability, and application client role:

1. governed context acquisition runs in a server-level read-only MCP child;
2. Decision write-back runs in a distinct isolated writer MCP child behind a mandatory `save_document`-only transport allowlist;
3. persisted-content verification runs in a fresh server-level read-only MCP child.

The change affects DataHub credentials, MCP process configuration, tool discovery, live evidence, and write-back. It therefore requires negative security tests and the normal security-sensitive merge gates, including Live DataHub Evidence.

## Security objective

A process whose job is to resolve DataHub metadata for policy or to verify persisted evidence must not be able to mutate DataHub through ToxicJoin. The write path must use a distinct credential/process and ToxicJoin must not expose or invoke DataHub mutation tools other than the single `save_document` operation required for the verification Decision.

## Credential separation

Secure MCP roles use distinct environment variables:

- `DATAHUB_GMS_READ_TOKEN` for read-only context acquisition and fresh read-back;
- `DATAHUB_GMS_WRITE_TOKEN` for the isolated Decision writer.

Both roles share the configured GMS URL, MCP command, arguments, and timeout, but each child receives only its selected token as `DATAHUB_GMS_TOKEN` through the existing minimal child environment.

The legacy `DATAHUB_GMS_TOKEN` remains used by DataHub SDK seed/bootstrap tooling and low-level compatibility code. It is not accepted as an implicit fallback by the role-specific MCP factories. Missing role-specific tokens fail closed rather than silently collapsing read and write authority.

The local CI quickstart has DataHub authentication disabled, so its read/write token values are placeholders and may be identical. The evidence proves process, tool-boundary, and application-capability separation; it cannot prove production IAM scopes. A real secure deployment must provision separately scoped DataHub credentials.

## Process separation

`toxicjoin-datahub-spike` executes three independent MCP sessions:

1. **Read-only snapshot process** — `TOOLS_IS_MUTATION_ENABLED=false` and `SAVE_DOCUMENT_TOOL_ENABLED=false`; resolves entities, schema fields, and lineage.
2. **Isolated writer process** — uses the write credential and the upstream mutation-registration path required to make `save_document` exist; ToxicJoin immediately wraps this raw transport in a `save_document`-only allowlist before a writer client can discover or call tools.
3. **Fresh read-only verification process** — mutations and document writes disabled; verifies the persisted marker independently.

The governed snapshot is never acquired through the writer client. The writer response is never treated as proof of persistence.

## Verified upstream constraint

The first Live DataHub attempt under this PR deliberately tried the stronger configuration `TOOLS_IS_MUTATION_ENABLED=false` plus `SAVE_DOCUMENT_TOOL_ENABLED=true` for the writer. The run reached DataHub startup, service health, warehouse creation, metadata seed, and document bootstrap successfully, but failed at the role-separated MCP step with `missing tool save_document`.

That failure is retained as evidence rather than hidden. Source review of the pinned `mcp-server-datahub 0.6.x` implementation confirmed why: `save_document` is registered from inside `register_mutation_tools()`, and that function returns before all mutation registration when `TOOLS_IS_MUTATION_ENABLED` is false. The independent `SAVE_DOCUMENT_TOOL_ENABLED` flag is evaluated only after the general mutation-registration gate has already passed.

Therefore P3-A does **not** claim that the raw writer MCP server can expose only `save_document` under this upstream version.

## Mandatory writer transport allowlist

Because the pinned upstream server couples `save_document` registration to its broad mutation-registration path, ToxicJoin inserts `ToolAllowlistTransport` between the raw writer process and all ToxicJoin writer code.

The wrapper:

- records the complete raw upstream writer tool inventory for evidence;
- returns only `save_document` from `list_tools()`;
- rejects every non-allowlisted `call_tool()` before the underlying transport is invoked;
- uses an immutable allowlist containing exactly `save_document`.

The role-bound writer client independently verifies that its effective transport surface contains no tool other than `save_document`, validates the required Decision schema, and rejects governed read/context methods.

This gives two distinct evidence fields:

- `write_server_discovered_tools` — the honest raw upstream server inventory;
- `write_discovered_tools` — the effective ToxicJoin writer surface after the mandatory allowlist.

Broad mutation tools may exist in the **raw** writer inventory because of the upstream registration constraint. Their presence in the **effective** writer inventory is a security failure.

## Read-only boundary

Read-only context acquisition and fresh read-back do not require the upstream mutation-registration path. Their child environments force:

- `TOOLS_IS_MUTATION_ENABLED=false`;
- `DATAHUB_MCP_DOCUMENT_TOOLS_DISABLED=false` so document reads remain available;
- `SAVE_DOCUMENT_TOOL_ENABLED=false`.

`RoleBoundDataHubMcpClient` additionally rejects mutation validation, rejects `save_decision()` before transport invocation, and fails closed if mutation-shaped tools appear in read-only discovery.

## Application-level capability boundary

Upstream process configuration is not trusted as the sole control.

- `READ_ONLY` rejects mutation validation and mutation calls.
- `READ_ONLY` rejects mutation-shaped discovered tools.
- `MUTATION` must sit behind the save-only transport and validates only the `save_document` Decision contract.
- `MUTATION` rejects governed context/read APIs.
- Constructing a writer client directly on an unfiltered broad raw transport fails closed because tools outside the writer allowlist remain visible.

This prevents internal code from converting a read client into a writer by changing `require_mutations=True`, prevents the writer from becoming the source of policy context, and makes bypassing the allowlist observable and testable.

## Mutation-shaped tool policy

For read-role exposure checks ToxicJoin treats the following as mutation-shaped:

- `save_document`;
- tools prefixed by `add_`;
- `remove_`;
- `set_`;
- `update_`;
- `create_`;
- `delete_`;
- `upsert_`;
- `patch_`.

Read-only sessions reject all of them. The effective writer transport permits exactly `save_document` regardless of the broader raw inventory.

## Live evidence contract

Live DataHub Evidence must prove all of the following on the exact release-candidate SHA:

- read settings identify the read-only role and document writes are disabled;
- writer settings identify the mutation/write role and the configured ToxicJoin transport allowlist is exactly `save_document`;
- read snapshot discovery does not expose `save_document` or mutation-shaped tools;
- `write_server_discovered_tools` preserves the raw upstream writer inventory without pretending it is narrow;
- `write_discovered_tools` is exactly `save_document`;
- the effective writer inventory is a subset of the raw inventory;
- fresh read-back discovery does not expose `save_document` or mutation-shaped tools;
- the live semantic policy test acquires its snapshot through the read-only role;
- the persisted Decision marker is verified from the fresh read-only process;
- sanitized artifacts contain no credential value, local GMS endpoint, raw warehouse row, or application secret.

## Negative security tests

Coverage includes:

- read and write role factories requiring separate token variables;
- the legacy ambiguous token not satisfying either role-specific credential requirement;
- read child environment forcing mutation registration and document writes off;
- writer child environment enabling the upstream path required by `save_document` while keeping it isolated to the write credential/process;
- read client rejecting mutation-tool exposure and mutation calls;
- writer allowlist hiding raw broad mutations from client discovery;
- direct calls to a non-allowlisted writer tool being rejected before the delegate transport is invoked;
- writer client rejecting governed context reads;
- writer client constructed without the mandatory filtering layer failing closed on broad tool exposure;
- the integration spike proving process order `read-only -> allowlisted writer -> fresh read-only` and tool-call separation;
- raw and effective writer inventories being included in the report hash;
- production source scanning preventing reuse of the ambiguous legacy MCP settings factory.

## Residual risk and explicit non-goals

- **The raw writer child remains mutation-capable under `mcp-server-datahub 0.6.x`.** This is an upstream registration constraint, not hidden by P3-A. ToxicJoin limits its own reachable tool surface with process isolation, a distinct credential, a mandatory transport allowlist, and a role-bound client.
- **Server-side write-token scope is still required.** A compromise inside the raw writer process or outside ToxicJoin's allowlisted transport may exercise whatever permissions the write credential has. Production should restrict that credential to the narrowest document-write permission DataHub supports.
- **DataHub server-side token scopes are deployment-owned.** ToxicJoin cannot prove two supplied secrets have distinct privileges merely from their values.
- **CI quickstart is authentication-disabled.** The live gate proves child settings, discovered raw/effective tools, process separation, and ToxicJoin enforcement, not production IAM configuration.
- **This PR does not solve DataHub freshness/expiry.** Context fingerprint freshness metadata, freshness SLA, and drift rejection are the next P3 subphase (TJ-SEC-013).
- **This PR does not replace OS/process isolation.** Host or raw-child compromise is outside the application transport guarantee.

## Definition-of-Done impact

This change modifies a DataHub credential/tool/process trust assumption. Therefore it requires a Threat-Model Delta, negative tests, Live DataHub Evidence, normal CI, Governance Dependency Evidence, Adversarial Mutation Evidence, Compositional Ablation Evidence, and Disclosure Sequence Evidence before merge. No Devpost submission state is changed.
