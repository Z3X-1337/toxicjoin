# ToxicJoin vNext Prior-Art Boundary

Status: **working prior-art record; not a novelty proof**

Date: 2026-07-25

Purpose: constrain claims before implementation and prevent rediscovering existing research under new names.

## 1. Conclusion

The individual ideas behind vNext have substantial prior art. ToxicJoin MUST NOT claim novelty for any one of the following in isolation:

- history-aware query auditing;
- privacy formulated as reachability;
- information-flow control around AI agents;
- proof/certificate-bearing authorization or agent actions;
- canonical action identity/attestation;
- counterexample-guided or minimum-change repair in general;
- provenance-aware trust decisions;
- temporal/bitemporal governance modeling.

The currently defensible research direction is the **specific integration** of:

1. DataHub-governed analytical SQL;
2. deterministic evidence-state resolution for governance/lineage claims;
3. actual cross-query disclosure history;
4. bounded prospective disclosure reachability over a declared finite SQL action grammar;
5. deterministic repair over a declared finite remediation/cost space;
6. proof commitments bound into ToxicJoin's existing single-use authorization and post-execution verification path.

Even this combination is a working novelty hypothesis, not a `world first` claim.

## 2. Query auditing and history-aware privacy

### Simulatable auditing / online query auditing

Kenthapadi, Mishra, and Nissim study online query auditing where prior queries and answers are part of the decision whether a new query can be answered without breaching privacy. The work also shows that denial behavior itself can leak information.

Reference:

- Krishnaram Kenthapadi, Nina Mishra, Kobbi Nissim, *Denials leak information: Simulatable auditing*, Journal of Computer and System Sciences 79(8), 2013.
- https://www.sciencedirect.com/science/article/pii/S002200001300113X

Implication for ToxicJoin:

- history-aware authorization is not novel by itself;
- denial/result surfaces should be considered part of the information channel;
- ToxicJoin's contribution must be narrower than "we consider previous queries".

## 3. Privacy as reachability

Gondron, Mödersheim, and Viganò explicitly show that privacy can be formalized as a reachability problem using a transaction-process formalism with mutable state and consciously released information.

Reference:

- Sébastien Gondron, Sebastian Mödersheim, Luca Viganò, *Privacy as Reachability*, IEEE CSF 2022.
- https://kclpure.kcl.ac.uk/portal/en/publications/privacy-as-reachability/

Implication for ToxicJoin:

- PPMC is not the first use of reachability for privacy;
- the claim must focus on ToxicJoin's concrete operational state model, finite SQL-oriented action grammar, DataHub evidence dependency, counterexample replay, and binding into a live authorization path.

## 4. Deterministic information-flow control for AI agents

FIDES models AI-agent security using information-flow control and deterministic policy enforcement around planner/tool behavior.

Reference:

- Manuel Costa et al., *Securing AI Agents with Information-Flow Control*, 2025/2026.
- https://arxiv.org/abs/2505.23643
- https://www.microsoft.com/en-us/research/publication/securing-ai-agents-with-information-flow-control/

Implication for ToxicJoin:

- `Agent != Security Authority` and deterministic enforcement are strong architectural properties but not novelty claims by themselves;
- ToxicJoin is focused on governed analytical disclosure and prospective composition, not general prompt-injection IFC.

## 5. Proof-carrying and certificate-bearing agent actions

Proof-Carrying Authorization predates modern AI agents, and current agent research applies certificate/receipt concepts to heterogeneous action runtimes.

### Proof-Carrying Agent Actions (PCAA)

PCAA defines runtime-neutral governance around an action certificate with checkpoints including pre-action admissibility, assumption capture, approval, outcome closure, receipts, and replay-ready proof.

Reference:

- Zexun Wang, *Proof-Carrying Agent Actions: Model-Agnostic Runtime Governance for Heterogeneous Agent Systems*, June 2026.
- https://arxiv.org/abs/2606.04104

Implication for ToxicJoin:

- a machine-verifiable Privacy Proof Capsule is not novel merely because it carries assumptions, approval, and execution receipts;
- ToxicJoin must distinguish its capsule through privacy-specific committed evidence/state/grammar/model-checking/repair semantics and binding to the existing execution authority.

## 6. Canonical action verification and attestation

CAVA, published in July 2026, explicitly addresses canonical runtime action identity, semantic pattern detection, approval binding, receipt reproducibility, runtime portability, and optional attestation.

Reference:

- Zexun Wang, *CAVA: Canonical Action Verification and Attestation for Runtime Governance of Agentic AI Systems*, July 2026.
- https://arxiv.org/abs/2607.13716

Implication for ToxicJoin:

- canonicalization, action identity, approval binding, or attestation are not safe standalone novelty claims;
- ToxicJoin's canonical commitments should be presented as necessary implementation mechanisms for its privacy state model, not as a new general action-attestation theory.

## 7. DataHub MCP capabilities

The official DataHub MCP server provides search, entity/schema retrieval, table/column lineage, exact lineage paths, dataset query examples, and mutation/document tools including `save_document`.

Reference:

- https://github.com/acryldata/mcp-server-datahub

Implication for ToxicJoin:

- discovery/schema/lineage access is provided by DataHub and should not be presented as ToxicJoin invention;
- the causal value lies in how ToxicJoin converts that context into evidence states and authorization dependencies;
- upstream mutation breadth reinforces the need to preserve ToxicJoin's role-separated/read-only acquisition and attenuated writer surface.

## 8. MCP authorization boundary

Current MCP authorization specifications use OAuth-based protected-resource authorization, audience/resource binding, and least-privilege scope guidance. Token passthrough is explicitly prohibited.

Reference:

- https://modelcontextprotocol.io/specification/draft/basic/authorization

Implication for ToxicJoin:

- MCP transport authorization and resource-bound tokens are protocol/security mechanisms, not ToxicJoin novelty;
- an intent-scoped ToxicJoin capability facade, if built, should be described as application-layer authority attenuation tied to a specific privacy task/proof, not as replacement for MCP authorization.

## 9. Working novelty position

The strongest current positioning is:

> ToxicJoin evaluates whether evidence-backed governance context is sufficient to authorize an analytical action, then evaluates whether admitting that action makes a declared forbidden disclosure state reachable through modeled future analytical actions, and can search a declared finite repair space before binding the accepted state into single-use execution authority.

The following wording is prohibited unless a substantially broader literature search later supports it:

- "first prospective privacy model checker";
- "first privacy reachability system";
- "first proof-carrying AI agent";
- "first deterministic security kernel for agents";
- "first query auditing system with history";
- "world first".

## 10. Research gaps still requiring search

Before final paper-like claims or Devpost originality language, perform additional focused searches on:

- database inference control and disclosure control beyond aggregate auditing;
- query-history privacy systems and tracker attacks;
- controlled query evaluation and statistical database security;
- counterexample-guided privacy repair and query synthesis;
- provenance-aware authorization and trust management;
- epistemic trust/conflicting metadata in data catalogs;
- lineage completeness / evidence-of-absence;
- temporal and bitemporal policy evaluation;
- knowledge/reasoning revocation for agents;
- hyperproperty counterexamples and explanation;
- purpose-based access control and intent drift.

This file is therefore a **claim boundary**, not a declaration that the remaining combination is proven novel.
