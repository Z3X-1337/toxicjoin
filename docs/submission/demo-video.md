# ToxicJoin Demo Video — Final Storyboard

> Target length: **2:30–2:45**. Hard limit: **under 3:00**.
>
> The Microsoft WAV is the timing source of truth. Draft timestamps below are visual targets only and must move to the actual spoken clauses after the audio is supplied.

## Recording requirements

- Resolution: 1920×1080, 30 fps.
- Language: native US English narration with reviewed English captions.
- Tone: calm technical keynote, not a trailer.
- Cursor movements: deliberate and slow.
- Zoom only to direct attention to evidence.
- Use only real ToxicJoin interface, terminal, DataHub UI, GitHub Actions, repository, and generated evidence.
- Do not display invented dashboards, fake DataHub screens, or unsupported capabilities.
- Keep the hosted Replay disclosure visible when the public site is shown.
- When showing the Docker/API path, show `mode: fixture` honestly.
- Treat the Agent Registry graph as a **preview/development-channel proof**, separate from the stable DataHub SDK/MCP integration.
- End before 2:50 to preserve upload/transcoding safety.

## Timeline and locked narration

### 0:00–0:11 — The problem

**Visual**

- Dark title card: `ToxicJoin`.
- Subtitle: `Compositional Privacy Firewall for AI Data Agents`.
- Transition immediately to the unsafe-query scenario in the real interface.

**Narration**

> AI data agents can generate useful S-Q-L in seconds. But two acceptable datasets can become sensitive when joined. Toxic Join evaluates that composed output before the query reaches the warehouse.

### 0:11–0:25 — The operating model

**Visual**

- Show the three scenario cards: `BLOCK`, `REWRITE → ALLOW`, and `ALLOW`.
- Briefly highlight `Deterministic policy`.
- Do not linger on marketing copy.

**Narration**

> Toxic Join receives the task purpose, S-Q-L, and expected subject key. A deterministic policy returns allow, safely rewrite, or block. An L-L-M does not control enforcement.

### 0:25–0:49 — Prove blocking before execution

**Visual**

- Select `Block compositional re-identification`.
- Run the scenario.
- Zoom to the evidence graph: stable pseudonym, precise location, age band, and sensitive support category.
- Show the BLOCK decision.
- Zoom to `No query was executed` and the null execution state.
- Briefly expose the sanitized receipt ID/hash.

**Narration**

> Here, the agent combines a stable customer pseudonym, two quasi-identifiers, and a sensitive support category. No single source explains the risk. The combination does. Toxic Join blocks the query and never calls Duck D-B.

### 0:49–1:26 — The flagship rewrite

**Visual**

- Select `Rewrite a sensitive churn analysis`.
- Run it.
- Show initial decision `REWRITE` and reason `SMALL_GROUP_RISK`.
- Show original SQL and safe SQL side by side.
- Highlight only the exact inserted threshold:

```sql
HAVING COUNT(DISTINCT c.customer_id) >= 20
```

- Show the re-evaluation transition into final `ALLOW`.

**Narration**

> The flagship query groups a sensitive churn score without a trusted minimum number of customers. Toxic Join adds a subject-bound threshold, reparses the generated S-Q-L, and runs the same policy again. A rewrite is never trusted merely because Toxic Join produced it.

### 1:26–1:51 — Real execution and independent verification

**Visual**

- Show the green verification checks.
- Show the three DuckDB result rows.
- Highlight `subject_count = 40` for each region.
- Show the Receipt panel.
- Highlight that persisted receipts contain hashes/evidence and not returned result rows.

**Narration**

> Only after the final decision becomes allow does the read-only executor run. Verification checks the complete result, confirms every region contains forty distinct subjects, rejects forbidden raw output fields, and stores evidence without persisting result rows.

### 1:51–2:24 — DataHub: context, memory, and reusable skill

**Visual — stable DataHub proof first**

- Show real DataHub UI from the verified live environment or retained real capture.
- Show the five seeded datasets.
- Open a dataset and show governed schema fields plus real tags or glossary terms.
- Show column lineage into `retention_scores.churn_score`.
- Show the actual ToxicJoin Decision document.
- Cut to `docs/evidence/datahub-live.md` or the green GitHub Actions proof showing fresh-process read-back.

**Visual — preview Agent Skill second**

- Show the real repository file `skills/compositional-risk-review/SKILL.md`.
- Show `docs/evidence/datahub-agent-registry.md` with these real identifiers visible:
  - `urn:li:agentSkill:toxicjoin-compositional-risk-review`
  - `urn:li:aiAgent:toxicjoin-privacy-firewall-agent`
- Briefly show the evidence that the Agent depends on one Skill, five MCP tool API entities, and five governed datasets.
- Label this shot on-screen: `Agent Registry preview — development channel`.
- Do not present the preview as a stable production dependency.

**Narration**

> Data Hub is governed context and durable memory. Toxic Join seeds five datasets, nineteen classified fields, tags, glossary terms, and column lineage through the official S-D-K. Through the official M-C-P Server, it reads governed context, writes a Data Hub Decision, closes that process, opens a fresh one, and verifies the saved marker. The review procedure is also published as a git-backed Data Hub Agent Skill; a separate preview proves the Agent, Skill, five M-C-P tools, and five dataset dependencies.

**Evidence**

- Stable SDK/MCP proof: `docs/evidence/datahub-live.md`.
- Agent Registry preview proof: `docs/evidence/datahub-agent-registry.md`.

### 2:24–2:38 — Measured evidence

**Visual**

- Show the Benchmark panel in the real ToxicJoin interface.
- Highlight only the supported-corpus values:
  - `30` cases;
  - `30/30` initial decisions;
  - `30/30` effective outcomes;
  - `0` false allows.
- Cut briefly to `docs/evidence/benchmark.md` or the generated CI artifact.

**Narration**

> A balanced thirty-query corpus runs through the real pipeline in C-I: ten allow, ten rewrite, and ten block. The declared corpus has thirty correct initial decisions, thirty correct effective outcomes, and zero false allows. Unsupported rewrites fail closed.

### 2:38–2:45 — Close

**Visual**

- Return to the ToxicJoin product header and receipt hash.
- Display:
  - `github.com/Z3X-1337/toxicjoin`
  - `toxicjoin-replay.vercel.app`
- Final line: `Context-aware. Deterministic. Fail closed.`

**Narration**

> Toxic Join gives AI data agents a privacy boundary they can explain, enforce, and leave behind in Data Hub for the next agent or reviewer.

## Capture checklist

- [ ] Hosted replay opens in a clean browser and visibly states that it is a replay.
- [ ] BLOCK scenario shows no execution.
- [ ] REWRITE scenario shows original SQL, safe SQL, final ALLOW, verification checks, and three result groups.
- [ ] Receipt panel shows hashes and no raw result rows.
- [ ] Real DataHub datasets, schema governance, lineage, and Decision document are visible.
- [ ] Stable DataHub independent read-back evidence is visible.
- [ ] Real `SKILL.md` and Agent Registry evidence are visible and labeled as preview/development-channel.
- [ ] Benchmark claim matches the committed supported-corpus report exactly.
- [ ] Public repository and Apache 2.0 license are visible.
- [ ] Final encoded duration is below 3:00.
- [ ] YouTube or Vimeo visibility matches the final hackathon submission requirement.
- [ ] Captions are reviewed for technical spelling: ToxicJoin, DataHub, MCP, SDK, SQL, DuckDB, pseudonym, lineage, Agent Skill.

## Claims that must not appear

- Universal privacy detection.
- Production readiness for arbitrary organizations.
- Differential privacy or automatic de-identification.
- General SQL repair.
- Live DataHub execution while showing the hosted Replay.
- Agent Registry preview presented as a stable released dependency.
- An upstream-merged DataHub contribution unless an actual accepted upstream PR exists.
