# ToxicJoin Demo Video — Final Storyboard

> Target length: **2:35–2:45**. Hard limit: **under 3:00**.
>
> Use only real ToxicJoin interface, terminal, DataHub UI, GitHub Actions, repository, and generated evidence. Do not display invented dashboards, fake DataHub screens, or unsupported capabilities.

## Recording requirements

- Resolution: 1920×1080, 30 fps.
- Language: native US English narration or clean English captions.
- Tone: calm technical keynote, not a trailer.
- Cursor movements: deliberate and slow.
- Zoom only to direct attention to evidence.
- Keep the hosted Replay label visible when showing the public site.
- When showing the Docker/API path, show `mode: fixture` honestly.
- Show DataHub live proof only after the verified live Artifact exists.
- End before 2:50 to preserve upload/transcoding safety.

## Timeline and narration

### 0:00–0:12 — The problem

**Visual**

- Dark title card: `ToxicJoin`.
- Subtitle: `Compositional Privacy Firewall for AI Data Agents`.
- Transition immediately to the unsafe-query scenario in the real interface.

**Narration**

> AI data agents can generate useful SQL in seconds. But two datasets that look acceptable independently can become sensitive when they are joined. ToxicJoin evaluates that composed output before the query reaches the warehouse.

### 0:12–0:27 — The operating model

**Visual**

- Show the three scenario cards: `BLOCK`, `REWRITE → ALLOW`, and `ALLOW`.
- Briefly highlight the deterministic policy label.

**Narration**

> ToxicJoin receives the task purpose, SQL, and expected subject key. A deterministic policy returns one of three outcomes: allow, safely rewrite, or block. An LLM does not control enforcement.

### 0:27–0:52 — Prove blocking before execution

**Visual**

- Select `Block compositional re-identification`.
- Run the scenario.
- Zoom to the evidence graph: stable pseudonym, precise location, age band, and sensitive support category.
- Zoom to `No query was executed` and the null execution state.

**Narration**

> Here, the agent joins a stable customer pseudonym with two quasi-identifiers and a sensitive support category. No single source is enough to explain the risk. The combination is. ToxicJoin blocks the query, creates a sanitized decision receipt, and never calls DuckDB.

### 0:52–1:32 — The flagship rewrite

**Visual**

- Select `Rewrite a sensitive churn analysis`.
- Run it.
- Show initial decision `REWRITE` and reason `SMALL_GROUP_RISK`.
- Show original SQL and safe SQL diff.
- Highlight:

```sql
HAVING COUNT(DISTINCT c.customer_id) >= 20
```

- Show final decision `ALLOW`.

**Narration**

> The flagship query is analytically useful, but it groups a sensitive churn score without a trusted minimum number of customers. ToxicJoin adds a subject-bound threshold, then reparses the generated SQL and runs the same policy again. A rewrite is never trusted merely because ToxicJoin produced it.

### 1:32–1:55 — Real execution and independent verification

**Visual**

- Show five green verification checks.
- Show the three DuckDB result rows.
- Highlight `subject_count = 40` for each region.
- Show the Receipt panel and `never raw result rows`.

**Narration**

> Only after the final decision becomes allow does the read-only executor run. Verification inspects the complete result, confirms that every region contains forty distinct subjects, checks that no forbidden raw field is projected, and stores hashes and evidence without persisting result rows.

### 1:55–2:20 — DataHub as context and durable memory

**Visual**

- Show real DataHub UI with the five seeded datasets.
- Open one dataset and show governed schema fields, tags or glossary terms.
- Show column lineage into `retention_scores`.
- Show the actual ToxicJoin Decision document.
- Cut to the verified GitHub Actions step or sanitized evidence report showing independent read-back.

**Narration**

> DataHub is the governed context layer. ToxicJoin seeds five datasets, nineteen classified fields, glossary terms, tags, and column lineage through the official SDK. Through the official MCP Server it reads entities, schema fields, and lineage, writes a DataHub Decision, closes that MCP process, opens a fresh process, and independently verifies the saved marker.

**Gate**

Do not record this section until `[PENDING_VERIFIED_EVIDENCE_LINK]` is replaced by a real green live run.

### 2:20–2:36 — Measured evidence

**Visual**

- Show Benchmark panel in the interface.
- Cut to `docs/evidence/benchmark.md` or GitHub Actions Artifact.

**Narration**

> A balanced thirty-query regression corpus runs through the real pipeline in CI: ten allow, ten rewrite, and ten block cases. The current declared corpus has thirty correct initial decisions, thirty correct effective outcomes, and zero false allows. Unsupported rewrites fail closed.

### 2:36–2:45 — Close

**Visual**

- Return to the product header and receipt hash.
- Display repository and hosted replay URLs.
- Final title: `Context-aware. Deterministic. Fail closed.`

**Narration**

> ToxicJoin gives AI data agents a privacy boundary they can explain, enforce, and leave behind in DataHub for the next agent or reviewer.

## Capture checklist

- [ ] Hosted replay opens in a clean browser and visibly states that it is a replay.
- [ ] BLOCK scenario shows no execution.
- [ ] REWRITE scenario shows original SQL, safe SQL, final ALLOW, five checks, and three result groups.
- [ ] Receipt panel shows hashes and no raw result rows.
- [ ] Real DataHub datasets, schema governance, lineage, and Decision document are visible.
- [ ] Independent read-back evidence is visible.
- [ ] Benchmark claim matches the committed report exactly.
- [ ] Public repository and Apache 2.0 license are visible.
- [ ] Final encoded duration is below 3:00.
- [ ] YouTube or Vimeo visibility is Public, not Unlisted or Private if the rules require public visibility.
- [ ] Captions are reviewed for technical spelling: DataHub, MCP, SQLGlot, DuckDB, pseudonym, lineage.

## Claims that must not appear

- Universal privacy detection.
- Production readiness for arbitrary organizations.
- Differential privacy or automatic de-identification.
- General SQL repair.
- Live DataHub execution while showing the hosted Replay.
- Any upstream DataHub contribution unless an actual accepted or public PR exists.
