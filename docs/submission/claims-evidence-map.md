# ToxicJoin — Claims to Evidence Map

> Review artifact only. This file does not authorize a Devpost submission.

Use this map when reviewing the Devpost text, captions, voiceover, thumbnail, and README. A claim may appear publicly only when its evidence column is complete and the wording stays within the allowed scope.

| Public claim | Required evidence | Allowed wording | Do not claim |
|---|---|---|---|
| ToxicJoin blocks unsafe SQL before execution | `tests/integration/test_pipeline.py`, `tests/integration/test_safe_execution.py`, BLOCK scenario receipt | “BLOCK outcomes never invoke DuckDB in the tested pipeline.” | Universal prevention across arbitrary SQL engines or policies |
| ToxicJoin can safely rewrite a supported query | `src/toxicjoin/rewrite/`, flagship integration tests, safe SQL example | “For the declared grouped-query profile, ToxicJoin adds or strengthens a subject-bound minimum-group threshold, then reparses and reevaluates the SQL.” | General SQL repair, automatic anonymization, or arbitrary query synthesis |
| A rewrite is not trusted automatically | Reparse, policy reevaluation, and verification tests | “Generated SQL must pass the same analyzer and deterministic policy again.” | That generated SQL is safe merely because ToxicJoin produced it |
| The policy engine—not an LLM—owns enforcement | `src/toxicjoin/policy/`, pipeline construction, threat model | “An LLM is not required and has no authority to override the deterministic decision.” | That ToxicJoin validates all possible LLM behavior |
| DuckDB execution is hardened | `src/toxicjoin/execute/duckdb_executor.py`, execution tests, container smoke test | “The demo executor is read-only, disables external access and extension auto-loading, locks configuration, and uses bounded previews and timeouts.” | Production hardening for every database or warehouse |
| Receipts do not persist raw result rows | Receipt schema/writer tests and API tests | “Persisted receipts contain hashes, governed evidence, checks, and execution summaries, but not returned result rows.” | That receipts contain no metadata or can never reveal sensitive context |
| Receipt files detect modification | Receipt content hash and tamper tests | “Receipt integrity is checked on every read, and modified JSON fails validation.” | Cryptographic non-repudiation, blockchain immutability, or protection from a privileged filesystem attacker |
| DataHub is used as governed context | `docs/evidence/datahub-live.md`, SDK seed, MCP snapshot loader | “The official SDK seeded governed metadata and lineage; the official MCP Server read entities, schemas, and lineage.” | That the public static Replay is connected to a live DataHub instance |
| ToxicJoin writes durable agent memory to DataHub | Live Decision write and fresh-process `grep_documents` read-back | “A DataHub Decision was persisted and its unique marker was found from a fresh MCP process.” | That the ephemeral Decision URL remains publicly available forever |
| Five datasets and nineteen fields were governed | `docs/evidence/datahub-live-seed.json` | “The live evidence run seeded five synthetic datasets and nineteen governed fields.” | A customer production catalog or real personal data |
| Four lineage links were written and three upstream relationships were read | Seed/spike evidence and live workflow | “The SDK wrote four lineage relationships; MCP returned three upstream relationships for the flagship column.” | That every dataset has complete lineage or that the counts are interchangeable |
| ToxicJoin publishes a reusable DataHub Agent Skill | `skills/compositional-risk-review/SKILL.md`, `docs/evidence/datahub-agent-registry.md` | “ToxicJoin publishes an Apache-2.0, git-backed Compositional Risk Review DataHub Agent Skill.” | That the Skill is merged into the upstream DataHub repository |
| DataHub cataloged the Agent → Skill → tools → datasets graph | Agent Registry live proof and independent read-back report | “An isolated development-channel proof registered one AI Agent, one Agent Skill, five MCP tool API entities, and five governed dataset dependencies, then read the relationships back independently.” | That Agent Registry preview APIs are part of ToxicJoin’s stable `acryl-datahub==1.6.0.15` dependency path |
| The benchmark achieved 30/30 decisions | `docs/evidence/benchmark.md`, JSON report, CI gates | “On the declared balanced 30-query deterministic corpus, all initial decisions and effective outcomes matched expectations.” | Universal 100% privacy-detection accuracy |
| The benchmark had zero false allows | Benchmark report and non-zero failure gates | “The declared corpus produced zero false allows and zero unsafe effective allows.” | Zero false allows for arbitrary schemas, SQL, policies, or organizations |
| Six rewrites were remediated and four failed closed | Benchmark report | “Six supported rewrites executed after verification; four unsupported rewrite paths failed closed.” | That every REWRITE can be repaired automatically |
| The hosted site is immediately testable | `docs/evidence/hosted-replay.md`, Chromium desktop/mobile report, public Vercel URL | “Judges can open a verified deterministic Replay with explicit disclosure; Docker/FastAPI remains the executable product path.” | Live DataHub writes, live DuckDB execution, or dynamic API results on the static site |
| The container is hardened | Dockerfile, Compose settings, container CI | “The tested container runs as non-root, uses a read-only root filesystem, drops Linux capabilities, enables `no-new-privileges`, and passes an external end-to-end smoke test.” | Formal container certification or protection from all host/runtime vulnerabilities |
| The project was newly created for the hackathon | Git history, clean-room declaration, project dates | “ToxicJoin was created during the submission period and does not reuse Rayluno code, assets, infrastructure, branding, or submission content.” | That no standard library, framework, AI assistance, or open-source dependency was used |

## Required limitations language

At least one public artifact—the README, Devpost description, or video—must state all of the following:

1. The current rewrite is intentionally limited to supported grouped analytical queries and a trusted distinct-subject threshold.
2. Unsupported or ambiguous transformations fail closed.
3. The benchmark measures a declared deterministic corpus and is not universal accuracy.
4. The hosted site is a Replay; Docker/FastAPI is the executable path.
5. The stable live DataHub evidence used an ephemeral DataHub OSS environment in GitHub Actions.
6. The Agent Registry proof is an isolated preview/development-channel capability, not part of the stable dependency path.
7. The public Agent Skill is an open-source DataHub ecosystem contribution maintained in ToxicJoin; it is not claimed as upstream-merged.
8. ToxicJoin is not a legal compliance certification, differential privacy system, or replacement for organization-specific governance review.

## Final review rule

Reject the release if any public text:

- removes the scope qualifier from benchmark numbers;
- presents Replay as live execution;
- says that ToxicJoin anonymizes arbitrary SQL;
- claims universal privacy guarantees;
- claims a DataHub upstream contribution that was not merged upstream;
- presents the Agent Registry preview as a stable dependency;
- presents the ephemeral DataHub environment as permanently hosted;
- references Rayluno as reused code or infrastructure.
