# ToxicJoin Judge Evidence Matrix

This page maps the project's strongest claims to retained, reproducible evidence. It is intentionally compact so a reviewer can move from a claim to the exact proof without searching the repository.

| Claim | Measured / verified result | Evidence |
|---|---|---|
| ToxicJoin uses real DataHub OSS and the official MCP Server | 5 datasets, 19 governed fields, 9 tags, 7 glossary terms, 4 lineage writes; MCP read → Decision write → fresh-process read-back | [Live DataHub evidence](datahub-live.md) |
| Governed context is on the authorization path, not decorative | Same SQL/data/policy: complete governance → `REWRITE → ALLOW`; 3 degraded-governance states → `BLOCK`; 0 unsafe effective allows | [Governance dependency evidence](governance-dependency.md) · [JSON](governance-dependency.json) |
| The agent/skill/tool relationship exists in the DataHub graph | Preview evidence independently read back 1 AI Agent, 1 Agent Skill, 5 required MCP tool APIs, and consumption lineage to all 5 governed ToxicJoin datasets | [Agent Registry preview evidence](datahub-agent-registry.md) |
| An external AI agent has a clear non-bypass integration contract | Stable FastAPI boundary exposes health, analyze, guarded execute, and receipt lookup; caller is instructed to consume data only after effective `ALLOW` and verification | [Agent integration contract](../agent-integration.md) · [architecture](../architecture.md) |
| ToxicJoin is selective rather than a blanket blocker | Balanced corpus: 10 `ALLOW`, 10 `REWRITE`, 10 `BLOCK`; 100% expected initial/effective outcomes on declared corpus | [30-case benchmark](benchmark.md) · [summary JSON](benchmark-summary.json) |
| Known-unsafe individual compositions resist superficial SQL variation | 144/144 generated mutations `BLOCK`; 144/144 hit `COMPOSITIONAL_REIDENTIFICATION_RISK`; 0 database executions; 0 unsafe allows | [Adversarial mutation evidence](adversarial-mutations.md) · [summary JSON](adversarial-mutations-summary.json) |
| Cross-column compositional reasoning materially changes the safety result | Shipped policy blocks 144/144 unsafe mutations; targeted interaction ablation allows 144/144; all 20 ALLOW/REWRITE controls preserved | [Compositional ablation evidence](compositional-ablation.md) · [summary JSON](compositional-ablation-summary.json) |
| A rewrite is not trusted merely because ToxicJoin generated it | Rewritten SQL is reparsed, regrounded, reevaluated, then independently verified before execution | [Judge testing guide](../judge-testing.md) · [benchmark](benchmark.md) |
| `BLOCK` stops before database execution | Production flow and adversarial suite both verify execution is skipped on blocked requests | [Judge testing guide](../judge-testing.md) · [adversarial evidence](adversarial-mutations.md) |
| Audit evidence does not become another privacy leak | Receipts are content-hashed and exclude returned result rows; retained evidence is sanitized | [Security model](../../SECURITY.md) · [live DataHub sanitization review](datahub-live.md#sanitization-review) |
| The public browser experience is represented honestly | Hosted interface is explicitly a deterministic Replay, not live DuckDB or live DataHub | [Hosted Replay evidence](hosted-replay.md) |

The Agent Registry row is explicitly a **preview/development-channel DataHub capability**; it is not represented as a stable production dependency. The stable enforcement path is proven separately through the released DataHub OSS/MCP evidence.

## Fast reviewer path

1. Open the [deterministic Replay](https://toxicjoin-replay.vercel.app/) to understand the product surface.
2. Read the [architecture and trust-boundary diagram](../architecture.md) to see how the AI agent, DataHub, deterministic enforcement, execution, verification, receipts, and Decision write-back fit together.
3. Read the [agent integration contract](../agent-integration.md) for the concrete control-plane API and anti-bypass semantics.
4. Follow the [90-second executable judge guide](../judge-testing.md) to run the real fixture-mode backend.
5. Read [live DataHub evidence](datahub-live.md) for the real OSS SDK/MCP integration and write-back proof.
6. Read [governance dependency](governance-dependency.md) to see why DataHub-governed context changes authorization outcomes.
7. Read [adversarial mutations](adversarial-mutations.md) and the [ablation](compositional-ablation.md) for robustness and originality evidence.

## Scope discipline

These are bounded, declared evaluations. ToxicJoin does not claim universal SQL support, universal re-identification detection, or that the hosted Replay is a live DataHub deployment. Unsupported or ambiguous cases fail closed, and each evidence document states its own limitations.
