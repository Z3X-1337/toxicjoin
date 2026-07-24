# Threat-Model Delta — P3-A DataHub MCP Least Privilege

Date: 2026-07-24

## Scope

P3-A closes TJ-SEC-016 for ToxicJoin's official DataHub MCP execution paths. Before this change, the same mutation-capable MCP settings/process were used to acquire governed context, write the verification Decision, and perform fresh-process read-back. A compromise or prompt/tool-routing defect in a context-acquisition path therefore inherited unnecessary DataHub mutation capability.

This change separates DataHub MCP authority by process, credential variable, upstream tool exposure, and application capability:

1. governed context acquisition runs in a read-only MCP child;
2. Decision write-back runs in a distinct document-write MCP child;
3. persisted-content verification runs in a fresh read-only MCP child.

The change affects DataHub credentials, MCP process configuration, tool discovery, live evidence, and write-back. It requires negative security tests and the normal security-sensitive merge gates, including Live DataHub Evidence.

## Security objective

A process whose job is to resolve DataHub metadata for policy or to verify persisted evidence must not be able to mutate DataHub through ToxicJoin. The short-lived writer must expose only the specific document-write mutation ToxicJoin needs; broad metadata-mutation tools are unnecessary and must remain disabled.

## Credential separation

Secure MCP roles use distinct environment variables:

- `DATAHUB_GMS_READ_TOKEN` for read-only context acquisition and fresh read-back;
- `DATAHUB_GMS_WRITE_TOKEN` for the isolated document-write process.

Both roles share the configured GMS URL, MCP command, arguments, and timeout, but each child receives only its selected token as `DATAHUB_GMS_TOKEN` through the existing minimal child environment.

The legacy `DATAHUB_GMS_TOKEN` remains used by DataHub SDK seed/bootstrap tooling and by low-level compatibility code. It is not accepted as an implicit fallback by the new role-specific MCP factories. Missing role-specific tokens therefore fail closed rather than silently collapsing read and write authority.

The local CI quickstart has DataHub authentication disabled, so its read/write token values are placeholders and may be identical. The evidence still proves process, upstream-tool, and application-capability separation. A real secure deployment must provision separately scoped DataHub credentials; CI cannot prove external identity-provider or server-side token policy.

## Process separation

`toxicjoin-datahub-spike` now executes three independent MCP sessions:

1. **Read-only snapshot process** — broad metadata mutations disabled and document writes disabled; resolves entities, schema fields, and lineage.
2. **Document-write process** — broad metadata mutations remain disabled; only `save_document` is enabled for one sanitized Decision write.
3. **Fresh read-only verification process** — broad metadata mutations and document writes disabled; verifies the persisted marker independently.

The governed snapshot is never acquired through the writer client. The writer session's response is never treated as proof of persistence.

## Upstream MCP tool minimization

The official DataHub MCP server controls broad metadata mutation tools and `save_document` independently. P3-A therefore does not enable the broad mutation family in the writer merely to obtain document write capability.

Role-bound child environments force:

| Role | `TOOLS_IS_MUTATION_ENABLED` | `SAVE_DOCUMENT_TOOL_ENABLED` |
|---|---|---|
| read-only snapshot | `false` | `false` |
| isolated document writer | `false` | `true` |
| fresh read-back | `false` | `false` |

Document tools remain globally available so read-only verification can use `grep_documents`, while the independent document-write switch remains disabled in read roles.

This is materially narrower than an application-only denylist: even if a caller escapes ToxicJoin's intended method routing, the writer child should not advertise add/remove/set/update/create/delete/upsert/patch metadata-mutation tools.

## Application-level capability boundary

Upstream process configuration is not trusted as the only control. `RoleBoundDataHubMcpClient` adds a second enforcement layer:

- `READ_ONLY` rejects requests for mutation validation and rejects `save_decision()` before a tool call;
- `READ_ONLY` fails closed if mutation-shaped tools are exposed by the upstream MCP process;
- `MUTATION` validates the `save_document` contract independently;
- `MUTATION` fails closed if unnecessary broad metadata-mutation tools are exposed;
- `MUTATION` rejects ToxicJoin context-acquisition/read APIs.

This prevents an internal caller from converting a read client into a writer merely by changing `require_mutations=True`, prevents the writer client from becoming the source of policy context, and treats unexpected upstream capability expansion as a security failure.

## Mutation-shaped tool policy

ToxicJoin treats the following as mutation-shaped for least-privilege validation:

- `save_document`;
- tools prefixed by `add_`;
- `remove_`;
- `set_`;
- `update_`;
- `create_`;
- `delete_`;
- `upsert_`;
- `patch_`.

Read-only sessions reject all of them. The document writer permits `save_document` only and rejects the broad mutation prefixes.

This name-based exposure check is defense-in-depth around the upstream server contract; ToxicJoin still exposes only the explicit methods defined by the role-bound client.

## Write authority

The writer validates only the required `save_document` contract used by ToxicJoin. It does not require read contracts and its application-level client rejects governed read/context calls. Broad metadata mutation discovery causes fail-closed startup for that writer session.

This does **not** prove that the underlying DataHub write credential is incapable of other mutations when used outside the MCP child. Server-side least privilege remains a deployment requirement. Where DataHub supports narrower token permissions, the write credential should be restricted to the minimum document write operation required by the release workflow.

## Live evidence changes

Live DataHub Evidence now fails unless all of the following hold:

- read settings report the read-only role, metadata mutations disabled, and document writes disabled;
- writer settings report the write role, metadata mutations disabled, and document writes enabled;
- read snapshot discovery does not expose `save_document` or broad mutation-shaped tools;
- writer discovery exposes `save_document` but no broad metadata-mutation tool;
- fresh read-back discovery does not expose `save_document` or broad mutation-shaped tools;
- the live semantic policy test acquires its snapshot through the read-only role;
- the persisted Decision marker is verified from the fresh read-only process;
- sanitized artifacts contain no credential value, local GMS endpoint, raw warehouse row, or application secret.

## Negative security tests

Coverage includes:

- read and write role factories requiring separate token variables;
- the legacy ambiguous token not satisfying either role-specific credential requirement;
- read child environment forcing both broad metadata mutations and `save_document` off even if the parent environment enables them;
- writer child environment keeping broad metadata mutations off while enabling only `save_document`;
- read client rejecting an upstream process that exposes mutation tools;
- read client rejecting mutation contract validation;
- read client rejecting `save_decision()` before transport invocation;
- writer client accepting the document-write contract but rejecting governed context reads;
- writer client rejecting unnecessary broad metadata mutation exposure;
- the integration spike proving process order `read-only -> document-write -> fresh read-only` and tool-call separation;
- report hashing remaining stable under the role-separated evidence schema;
- production source scanning preventing reuse of the ambiguous legacy MCP settings factory.

## Residual risk and explicit non-goals

- **DataHub server-side token scopes are deployment-owned.** ToxicJoin cannot prove that two supplied tokens have distinct privileges merely from their secret values.
- **CI quickstart is auth-disabled.** The CI gate proves MCP process flags, discovered tools, ToxicJoin client capabilities, and process separation, not production IAM configuration.
- **The document-write process still holds the write credential for its short lifetime.** Compromise outside ToxicJoin's client API may exercise whatever permissions that credential has at the DataHub server. Server-side token scoping remains necessary.
- **This PR does not yet solve DataHub freshness/expiry.** Context fingerprint freshness metadata, freshness SLA, and drift rejection are the next P3 subphase (TJ-SEC-013).
- **This PR does not replace OS/process isolation.** Child environment minimization remains defense-in-depth; host compromise is outside this application boundary.

## Definition-of-Done impact

This change modifies a DataHub credential/tool/process trust assumption. Therefore it requires a Threat-Model Delta, negative tests, Live DataHub Evidence, normal CI, Governance Dependency Evidence, Adversarial Mutation Evidence, Compositional Ablation Evidence, and Disclosure Sequence Evidence before merge. No Devpost submission state is changed.
