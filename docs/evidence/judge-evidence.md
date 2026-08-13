# ToxicJoin Judge Evidence Matrix

This page maps the strongest submission claims to the **final release-candidate evidence**, not to superseded development runs.

Authoritative release index: [`release-candidate.md`](release-candidate.md).

| Claim | Final measured / verified result | Evidence |
|---|---|---|
| ToxicJoin meaningfully uses real DataHub OSS and official MCP | Final gate: 5 datasets, 19 governed fields, 10 tags, 7 glossary terms, 4 lineage writes; read-only context → isolated `save_document` writer → fresh read-only Decision read-back | [Live DataHub](datahub-live.md) · [release index](release-candidate.md) |
| DataHub governance is on the authorization path | Same SQL/data/policy: complete governance → `REWRITE → ALLOW`; three degraded-governance states → `BLOCK`; zero unsafe effective allows | [Governance dependency](governance-dependency.md) |
| DataHub upstream lineage changes effective risk | Final live spike schema 1.3 binds two fields to six normalized lineage sources, with zero unclassified sources; flagship lineage includes location, purchase, and support sources | [Live DataHub](datahub-live.md) |
| ToxicJoin is selective rather than blanket deny | Final policy 0.2 benchmark: 10 ALLOW / 10 REWRITE / 10 BLOCK; 30/30 initial and effective outcomes; zero false allows | [Benchmark](benchmark.md) · [summary JSON](benchmark-summary.json) |
| Known-unsafe compositions resist superficial SQL variation | Final exact-head mutation gate: 144/144 initial/effective BLOCK, intended compositional-risk reason 144/144, zero executions | [Adversarial mutations](adversarial-mutations.md) |
| Compositional reasoning materially changes the result | Final ablation v2: shipped policy blocks 144/144 unsafe mutations; targeted interaction ablation allows 144/144; 20/20 ALLOW/REWRITE controls preserved | [Compositional ablation](compositional-ablation.md) |
| A ToxicJoin-generated rewrite is not automatically trusted | Rewrite is reparsed, regrounded, reevaluated, authorized, executed read-only, then independently verified | [Judge testing](../judge-testing.md) · [architecture](../architecture.md) |
| BLOCK means no database execution | Production regressions, final mutation gate, frozen external replay, and black-box pentest all preserve fail-closed no-execution behavior | [Release index](release-candidate.md) |
| Cross-query differencing is considered | Authenticated stateful execution uses persistent subject-scoped disclosure state and exact-head Disclosure Sequence Evidence | [Release index](release-candidate.md) · [security docs](../security/) |
| Audit evidence does not become another privacy leak | Receipts are content-hashed, ownership-scoped, tamper-detected, and exclude raw result rows | [Security model](../../SECURITY.md) · [black-box pentest](release-candidate.md#exact-release-candidate-black-box-pentest) |
| The release was independently exercised beyond normal CI | Frozen external 24-task replay PASS; exact-image black-box pentest 24/24 PASS | [Release index](release-candidate.md) |
| Software supply-chain controls are part of the release | Frozen locks, audits, Bandit, CodeQL, SBOMs, immutable Action pins, digest-pinned Docker bases, Dependabot | [Release index](release-candidate.md#supply-chain-closure) · [P4 policy](../security/p4-supply-chain-policy.md) |
| The hosted browser experience is represented honestly | Render runs the real fixture pipeline and does not claim Live DataHub execution | [Public deployment](../deploy-public.md) |
| A reusable DataHub-native skill/agent graph exists | Preview proof independently read back 1 Agent Skill, 1 AI Agent, 5 MCP tool API entities, and 5 governed dataset dependencies | [Agent Registry preview](datahub-agent-registry.md) |

## Fast reviewer path

1. Open https://toxicjoin-public-demo.onrender.com/ to understand the product surface.
2. Read [`release-candidate.md`](release-candidate.md) for the exact release SHA and complete validation chain.
3. Follow [`../judge-testing.md`](../judge-testing.md) for the executable fixture path.
4. Read [`datahub-live.md`](datahub-live.md) for real DataHub OSS/MCP read → write → fresh-process read-back.
5. Read [`governance-dependency.md`](governance-dependency.md), [`adversarial-mutations.md`](adversarial-mutations.md), and [`compositional-ablation.md`](compositional-ablation.md) for causality, robustness, and originality evidence.
6. Inspect [`../../skills/compositional-risk-review/SKILL.md`](../../skills/compositional-risk-review/SKILL.md) for the reusable DataHub Skill.

## Scope discipline

These are bounded, declared evaluations. ToxicJoin does not claim universal SQL support, universal re-identification detection, differential privacy, or legal-compliance certification. Unsupported or ambiguous cases fail closed, and the public Render fixture is not represented as a Live DataHub deployment.
