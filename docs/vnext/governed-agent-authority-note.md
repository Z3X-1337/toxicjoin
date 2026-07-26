# Governed Agent Authority Contract — Day-12 Core

This slice introduces the P0 Governed Agent boundary without connecting an LLM provider or DataHub MCP transport yet. It freezes what an agent may emit before any external planner/transport is allowed into the system.

## Hard authority invariant

`AGENT != SECURITY AUTHORITY`

The complete P0 agent capability enum is:

- `DISCOVER`
- `PROPOSE`
- `ADAPT`

`DISCOVER` describes the sanitized read context supplied by a separate security-owned discovery component. `GovernedAgent` itself exposes only proposal/adaptation behavior over that context.

The agent has no API or constructor dependency for:

- execution authorization;
- direct execution;
- EvidencePolicy or marking evidence trusted;
- governance mutation/commit;
- PolicyEngine mutation;
- disclosure-history mutation;
- PPMC grammar selection/shrinking;
- proof validation.

The wrapper imports no authorizer, executor, disclosure ledger, DataHub mutation client, or proof verifier.

## Trusted adapter / untrusted planner-output boundary

`AgentPlanner` is a **trusted in-process integration adapter**, not an isolation boundary for arbitrary hostile Python. The remote LLM/model/provider and every value returned by it are untrusted. A genuinely untrusted executable planner must run outside the ToxicJoin interpreter and communicate only through a narrow data/RPC boundary implemented by the trusted adapter.

This distinction is security-critical: Python code running inside the ToxicJoin process shares the interpreter, imports, environment, and memory space and is therefore part of the trusted computing base. Leading underscores or module-private objects are not treated as a sandbox.

Only the planner response is admitted into `GovernedAgent`, and it may contain only an `AgentDraft` with:

- `task_purpose`;
- `sql`.

The strict model rejects extra fields. A planner response containing fields such as `authorize`, `execute`, `mark_evidence_trusted`, or `security_authoritative=true` is rejected as `AGENT_DRAFT_INVALID` before a proposal is created.

Adapter/provider failures become `AGENT_PLANNER_FAILED`; they never create authority. No credential-bearing DataHub object is an argument to the planner adapter interface.

## Sanitized discovery context

`AgentDataContext` is immutable and hash-committed. It contains only planning views:

- exact source snapshot commitment;
- catalog version;
- logical dataset names and DataHub dataset URNs;
- optional owner/domain labels;
- field paths;
- normalized sensitivity category labels;
- tags/glossary terms;
- sanitized upstream lineage identities/categories.

Every context/dataset/field/lineage model carries `security_authoritative=false`.

This is deliberate. A category shown to the planner is information for task planning only. It is **not** an `EvidenceClaim`, `EvidenceResolution`, `EvidenceTrustState`, authorization fact, or proof. The security pipeline must reacquire/revalidate governance/evidence independently after SQL is proposed.

No credential, MCP token, settings object, transport object, callable tool, mutation handle, raw warehouse row, or execution capability belongs in this context or in the planner-adapter call signature.

## Proposal preflight

`GovernedAgent` reparses every planner SQL through the existing deterministic `analyze_sql` before returning an `AgentProposal`.

P0 proposal preflight rejects:

- parser/statement failures;
- output wildcards;
- any source dataset outside the discovered context;
- any referenced field outside the discovered context.

This preflight is a planning-surface constraint only. Passing it does **not** mean the SQL is privacy-safe or authorized. The downstream DataHub evidence resolver, PolicyEngine, Twin, PPMC, CPCC, proof builder, authorizer, verifier, and executor remain authoritative.

## Canonical proposal artifact

An `AgentProposal` commits:

- capability (`PROPOSE` or `ADAPT`);
- bounded iteration;
- exact goal hash;
- exact discovery-context hash;
- previous proposal/feedback commitments for adaptation;
- task purpose;
- exact SQL SHA-256;
- deterministic QueryPlan commitment;
- proposal SHA-256;
- `security_authoritative=false`.

The proposal never contains an authorization bit, evidence-trust bit, policy override, proof validity bit, or execution token.

## Structured adaptation feedback

`AgentFeedback` is also planning-only and hash-bound. It may communicate:

- existing ToxicJoin decision;
- canonical reason codes;
- optional PPMC status;
- counterexample-trace commitment when PPMC is `PROSPECTIVE_UNSAFE`;
- optional CPCC result commitment.

An unsafe PPMC feedback record requires a counterexample trace commitment. A trace commitment is forbidden for non-unsafe PPMC statuses.

Feedback is bound to the exact previous proposal. Adaptation also requires the same goal and the same discovery-context commitment. Rebinding feedback to another proposal, goal, or context fails closed.

The remote/model planner may use this feedback to propose a different legitimate task expression. It does not own CPCC and cannot certify that its adaptation is safe.

## Bounded adaptation

P0 allows at most eight adaptation iterations, with a security-owned configurable limit no larger than eight. This prevents untrusted planner output from driving an unbounded retry loop inside the governed wrapper.

## Process-isolation rule

The P0 security claim is about untrusted **model/provider data**, not arbitrary code execution inside the ToxicJoin interpreter. Any future local-code planner, plugin, generated Python tool, or third-party planner runtime that is not trusted must be placed in a separate process/container/sandbox before it can satisfy this contract. It must receive only the sanitized planning payload and return only draft-shaped data.

## Next slice

The following Day-12 slice adds a security-owned DataHub discovery adapter that:

- constructs DataHub MCP settings with mutations disabled;
- validates only the required read tool contracts;
- acquires a normalized DataHub snapshot through trusted integration code;
- converts that snapshot into the sanitized immutable `AgentDataContext`;
- never passes the MCP client, transport, token, settings, or mutation surface through the planner-adapter interface.

Only after that adapter passes exact-head and Live DataHub gates should a concrete LLM provider be connected through trusted adapter code.
