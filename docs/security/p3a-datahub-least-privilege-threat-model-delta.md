# Threat-Model Delta — P3-A DataHub MCP Least Privilege

Date: 2026-07-24

## Scope

P3-A closes TJ-SEC-016 for ToxicJoin's official DataHub MCP execution paths. Before this change, the same mutation-capable MCP settings/process were used to acquire governed context, write the verification Decision, and perform fresh-process read-back. A compromise or prompt/tool-routing defect in a context-acquisition path therefore inherited unnecessary DataHub mutation capability.

This change separates DataHub MCP authority by process, credential variable, and application capability:

1. governed context acquisition runs in a read-only MCP child;
2. Decision write-back runs in a distinct mutation MCP child;
3. persisted-content verification runs in a fresh read-only MCP child.

The change affects DataHub credentials, MCP process configuration, tool discovery, live evidence, and write-back. It requires negative security tests and the normal security-sensitive merge gates, including Live DataHub Evidence.

## Security objective

A process whose job is to resolve DataHub metadata for policy or to verify persisted evidence must not be able to mutate DataHub through ToxicJoin. Mutation capability must exist only in the short-lived write-back process and must not be reusable for governed context acquisition.

## Credential separation

Secure MCP roles use distinct environment variables:

- `DATAHUB_GMS_READ_TOKEN` for read-only context acquisition and fresh read-back;
- `DATAHUB_GMS_WRITE_TOKEN` for the isolated mutation process.

Both roles share the configured GMS URL, MCP command, arguments, and timeout, but each child receives only its selected token as `DATAHUB_GMS_TOKEN` through the existing minimal child environment.

The legacy `DATAHUB_GMS_TOKEN` remains used by DataHub SDK seed/bootstrap tooling and by low-level compatibility code. It is not accepted as an implicit fallback by the new role-specific MCP factories. Missing role-specific tokens therefore fail closed rather than silently collapsing read and write authority.

The local CI quickstart has DataHub authentication disabled, so its read/write token values are placeholders and may be identical. The evidence still proves process and application-capability separation. A real secure deployment must provision separately scoped DataHub credentials; CI cannot prove external identity-provider or server-side token policy.

## Process separation

`toxicjoin-datahub-spike` now executes three independent MCP sessions:

1. **Read-only snapshot process** — mutation disabled; resolves entities, schema fields, and lineage.
2. **Mutation process** — mutation enabled; validates only the `save_document` contract and writes one sanitized Decision.
3. **Fresh read-only verification process** — mutation disabled; verifies the persisted marker independently.

The governed snapshot is never acquired through the mutation client. The mutation session's write response is never treated as proof of persistence.

## Application-level capability boundary

Upstream process configuration is not trusted as the only control. `RoleBoundDataHubMcpClient` adds an application capability boundary:

- `READ_ONLY` rejects requests for mutation validation and rejects `save_decision()` before a tool call;
- `READ_ONLY` fails closed if mutation-shaped tools are exposed by the upstream MCP process;
- `MUTATION` validates the `save_document` contract independently;
- `MUTATION` rejects ToxicJoin context-acquisition/read APIs.

This prevents an internal caller from converting a read client into a writer merely by changing `require_mutations=True`, and prevents the write client from being reused as the source of policy context.

## Read-only tool exposure policy

For read-only MCP sessions, ToxicJoin rejects tool names that are clearly mutation-shaped:

- `save_document`;
- tools prefixed by `add_`;
- tools prefixed by `remove_`;
- tools prefixed by `set_`;
- tools prefixed by `update_`.

The purpose is fail-closed verification that the upstream mutation-disable setting is materially reflected in discovered MCP capability. Read-only tools outside this deny pattern may still be discovered, but ToxicJoin's role-bound client exposes only the read methods used by its integration.

## Write authority

The mutation role validates only the required `save_document` contract used by ToxicJoin. It does not require read contracts and its application-level client rejects governed read/context calls.

This does **not** prove that the underlying DataHub write credential is incapable of other mutations when used outside ToxicJoin. Server-side least privilege remains a deployment requirement. Where DataHub supports narrower token permissions, the write credential should be restricted to the minimum document write operation required by the release workflow.

## Live evidence changes

Live DataHub Evidence now fails unless all of the following hold:

- read settings report `mutation_enabled=false`;
- write settings report `mutation_enabled=true`;
- read snapshot discovery does not expose `save_document` or mutation-shaped tools;
- write discovery exposes `save_document`;
- fresh read-back discovery does not expose `save_document` or mutation-shaped tools;
- the live semantic policy test acquires its snapshot through the read-only role;
- the persisted Decision marker is verified from the fresh read-only process;
- sanitized artifacts contain no credential value, local GMS endpoint, raw warehouse row, or application secret.

## Negative security tests

Coverage includes:

- read and write role factories requiring separate token variables;
- the legacy ambiguous token not satisfying either role-specific credential requirement;
- read child environment forcing `TOOLS_IS_MUTATION_ENABLED=false` even if the parent environment says `true`;
- write child environment forcing mutation enabled;
- read client rejecting an upstream process that exposes mutation tools;
- read client rejecting mutation contract validation;
- read client rejecting `save_decision()` before transport invocation;
- mutation client accepting the write contract but rejecting governed context reads;
- the integration spike proving process order `read-only -> mutation -> fresh read-only` and tool-call separation;
- report hashing remaining stable under the new role-separated evidence schema.

## Residual risk and explicit non-goals

- **DataHub server-side token scopes are deployment-owned.** ToxicJoin cannot prove that two supplied tokens have distinct privileges merely from their secret values.
- **CI quickstart is auth-disabled.** The CI gate proves MCP process flags, discovered tools, ToxicJoin client capabilities, and process separation, not production IAM configuration.
- **The mutation process remains privileged for its short lifetime.** Compromise during the write step can exercise whatever permissions the DataHub write credential grants outside ToxicJoin's client API.
- **This PR does not yet solve DataHub freshness/expiry.** Context fingerprint freshness metadata, freshness SLA, and drift rejection are the next P3 subphase (TJ-SEC-013).
- **This PR does not replace OS/process isolation.** Child environment minimization remains defense-in-depth; host compromise is outside this application boundary.

## Definition-of-Done impact

This change modifies a DataHub credential/tool/process trust assumption. Therefore it requires a Threat-Model Delta, negative tests, Live DataHub Evidence, normal CI, Governance Dependency Evidence, Adversarial Mutation Evidence, Compositional Ablation Evidence, and Disclosure Sequence Evidence before merge. No Devpost submission state is changed.
