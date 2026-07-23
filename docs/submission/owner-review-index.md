# ToxicJoin — Owner Review Index

> **Submission lock:** This index is for review only. No Devpost create, update, terms acceptance, or submission action is authorized by this document.

Use this page as the entry point for the final owner review. A gate marked **Pending** must not be treated as evidence or copied into Devpost until its placeholder is replaced with a verified public link or committed report.

## Current review gates

| Gate | Status | Review target |
|---|---|---|
| Product repository | Ready for review | https://github.com/Z3X-1337/toxicjoin |
| Core CI | Ready; recheck exact final commit | GitHub Actions on `main` |
| 30-query benchmark | Ready | `docs/evidence/benchmark.md` and `docs/evidence/benchmark.json` |
| Judge interface | Ready locally and in Docker | `apps/web/` and production container |
| Hosted replay | Ready and externally browser-verified | https://toxicjoin-replay.vercel.app/ — evidence: `docs/evidence/hosted-replay.md` |
| Stable live DataHub proof | Ready | `docs/evidence/datahub-live.md` |
| Open-source DataHub Agent Skill | Ready | `skills/compositional-risk-review/SKILL.md` |
| Agent Registry preview proof | Ready | `docs/evidence/datahub-agent-registry.md` |
| Devpost cover | Ready for visual approval | Real ToxicJoin interface-derived 1200×630 image |
| Microsoft narration | Specification ready; WAV pending | `microsoft-voice-production.md` |
| Final demo video | Pending Microsoft WAV and final capture/edit | `demo-video.md` |
| Devpost text | Draft ready; only video URL remains pending | `devpost-draft.md` |
| Final submission | Locked | Requires explicit owner approval |

## Review order

### 1. Product behavior

Open the repository and inspect:

- `README.md`
- `docs/judge-testing.md`
- `examples/README.md`
- `examples/unsafe-individual-export.sql`
- `examples/regional-churn-original.sql`
- `examples/regional-churn-safe.sql`
- `examples/public-order-counts.sql`

Confirm that the product story is understandable without reading implementation code:

1. a sensitive individual composition is blocked before execution;
2. a supported grouped query is rewritten with a subject-bound threshold;
3. the rewritten query is reparsed, reevaluated, executed, and verified;
4. a low-risk aggregate is allowed;
5. receipts do not persist raw result rows.

### 2. Measured evidence

Review:

- `docs/evidence/benchmark.md`
- `docs/evidence/benchmark.json`

The accepted benchmark language is limited to the declared deterministic corpus:

- 10 ALLOW cases;
- 10 REWRITE cases;
- 10 BLOCK cases;
- 30/30 initial decisions correct;
- 30/30 effective outcomes correct;
- zero false allows;
- unsupported rewrites fail closed.

Do not reinterpret these values as universal privacy-detection accuracy.

### 3. Stable live DataHub proof

Review the committed sanitized evidence:

- `docs/evidence/datahub-live.md`
- `docs/evidence/datahub-live-seed.json`
- `docs/evidence/datahub-live-spike.json`

Verified stable-path values:

- five datasets;
- nineteen governed fields;
- nine controlled tags;
- seven glossary terms;
- four lineage writes from the SDK seed;
- three upstream relationships read through MCP for the flagship column;
- official MCP tool discovery and contract validation;
- DataHub Decision document persisted;
- first MCP process closed;
- fresh MCP process found the unique marker inside persisted document content through `grep_documents`;
- no token value, password, local endpoint, raw row, local path, or unrelated secret in retained evidence;
- persisted JSON reports have reproducible `report_sha256` values.

The proof used a real ephemeral DataHub OSS deployment inside GitHub Actions. It does not claim that the hosted static Replay is a live DataHub session or that the temporary DataHub environment remains publicly available.

### 4. Open-source DataHub Skill and Agent Registry preview

Review:

- `skills/compositional-risk-review/SKILL.md`
- `docs/evidence/datahub-agent-registry.md`
- `docs/evidence/datahub-agent-registry.json`
- `docs/evidence/datahub-agent-registry-verified.json`
- GitHub Actions run: https://github.com/Z3X-1337/toxicjoin/actions/runs/30010740896

Verified preview graph:

```text
ToxicJoin Privacy Firewall Agent
  -> adopts Compositional Risk Review Agent Skill
  -> invokes five DataHub MCP tool API entities
  -> consumes five governed ToxicJoin datasets
```

Confirm that:

- the Skill points to the exact public git source path;
- the Skill requires exactly the five registered MCP tool API URNs;
- the Agent adopts exactly one ToxicJoin Skill and the five tool APIs;
- the Agent has upstream lineage to all five governed datasets;
- a fresh graph client independently read every relationship back;
- the evidence reports are sanitized and content-hashed;
- the preview/development channel is not described as part of the stable `acryl-datahub==1.6.0.15` dependency path.

This is an Apache-2.0 open-source DataHub Agent Skill maintained in the ToxicJoin repository. Do not describe it as merged into the upstream DataHub repository.

### 5. Public experience

Open the hosted replay in a clean browser:

https://toxicjoin-replay.vercel.app/

Review `docs/evidence/hosted-replay.md` and confirm:

- HTTP 200;
- immutable, provenance-pinned interface assets;
- visible Replay disclosure before interaction;
- no claim of live DataHub or DuckDB execution on the hosted static site;
- desktop 1440×1000 verification;
- mobile 390×844 verification;
- REWRITE→ALLOW flagship evidence;
- safe SQL and three forty-subject groups;
- benchmark values match the committed report;
- no unexpected console error, page error, failed static asset, or horizontal overflow.

The Docker/FastAPI path remains the executable product path.

### 6. Visual assets

Review the real-interface-derived Devpost cover and final screenshots. Reject any asset that:

- substitutes a generated dashboard for the product;
- exposes credentials, private account data, or local paths;
- implies unsupported functionality;
- presents Replay as live execution;
- presents the Agent Registry preview as a stable dependency.

### 7. Microsoft narration

Review `microsoft-voice-production.md`.

Audition the first two paragraphs with identical settings using:

1. `en-US-AndrewMultilingualNeural`;
2. `en-US-BrianMultilingualNeural`.

Deliver one continuous 48 kHz PCM WAV, 2:30–2:45, without music or embedded effects. The final video will be synchronized to the actual waveform after the file is supplied.

### 8. Final video

Review `demo-video.md`, then watch the final encoded video from start to finish. Confirm:

- duration below 3:00;
- real ToxicJoin, DataHub, repository, and retained evidence footage only;
- BLOCK proves no execution;
- REWRITE shows the exact SQL change and final ALLOW;
- three result groups each contain forty subjects;
- stable DataHub proof includes lineage, Decision write, and fresh-process read-back;
- the Agent Skill and Agent Registry preview are shown briefly and labeled correctly;
- benchmark claims match the committed supported-corpus report;
- captions spell ToxicJoin, DataHub, MCP, SDK, SQLGlot, DuckDB, pseudonym, lineage, and Agent Skill correctly.

### 9. Devpost packet

Review `devpost-draft.md` line by line. At the current stage the only intended `[PENDING_*]` marker is the final public YouTube or Vimeo video URL.

Required final links:

- public GitHub repository;
- hosted judge replay;
- public YouTube or Vimeo video under three minutes;
- examples directory;
- stable live DataHub evidence;
- open-source DataHub Agent Skill;
- Agent Registry preview evidence.

### 10. Exact-version approval

Complete `review-checklist.md` and record:

- exact `main` commit;
- exact video URL;
- exact hosted replay URL;
- approval date;
- explicit statement approving submission of that exact packet.

Only after that explicit approval may a Devpost submission action be performed.

## Files in this review packet

- `owner-review-index.md` — this page.
- `review-checklist.md` — binary acceptance checklist and signature block.
- `devpost-draft.md` — all proposed Devpost field answers and project description.
- `demo-video.md` — visual storyboard and narration mapping.
- `microsoft-voice-production.md` — Microsoft neural TTS script and audio acceptance requirements.
- `claims-evidence-map.md` — public-claim boundaries and required evidence.
