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

## Untrusted planner boundary

`AgentPlanner` is explicitly untrusted. It may return only an `AgentDraft` containing:

- `task_purpose`;
- `sql`.

The strict model rejects extra fields. A planner response containing fields such as `authorize`, `execute`, `mark_evidence_trusted`, or `security_authoritative=true` is rejected as `AGENT_DRAFT_INVALID` before a proposal is created.

Planner exceptions become `AGENT_PLANNER_FAILED`; they never create authority.

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

No credential, MCP token, settings object, transport object, callable tool, mutation handle, raw warehouse row, or execution capability belongs in this context.

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

The agent may use this feedback to propose a different legitimate task expression. It does not own CPCC and cannot certify that its adaptation is safe.

## Bounded adaptation

P0 allows at most eight adaptation iterations, with a security-owned configurable limit no larger than eight. This prevents an untrusted planner from creating an unbounded retry loop inside the governed wrapper.

## Next slice

The following Day-12 slice will add a security-owned DataHub discovery adapter that:

- constructs DataHub MCP settings with mutations disabled;
- validates only the required read tool contracts;
- acquires a normalized DataHub snapshot through trusted integration code;
- converts that snapshot into the sanitized immutable `AgentDataContext`;
- never gives the planner the MCP client, transport, token, settings, or mutation surface.

Only after that adapter passes exact-head and Live DataHub gates should any concrete LLM planner be considered.
