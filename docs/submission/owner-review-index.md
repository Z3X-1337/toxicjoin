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
| Hosted replay | Ready | https://toxicjoin-replay.vercel.app/ — evidence: https://github.com/Z3X-1337/toxicjoin/blob/main/docs/evidence/hosted-replay.md |
| Live DataHub proof | Ready | https://github.com/Z3X-1337/toxicjoin/blob/main/docs/evidence/datahub-live.md |
| Devpost cover | Ready for visual approval | Real ToxicJoin interface-derived 1200×630 image |
| Microsoft narration | Specification ready; WAV pending | `microsoft-voice-production.md` |
| Final demo video | Pending Microsoft WAV and final live captures | `demo-video.md` |
| Devpost text | Draft ready; replay/video placeholders remain | `devpost-draft.md` |
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

### 3. Live DataHub proof

Review the committed sanitized evidence:

- `docs/evidence/datahub-live.md`
- `docs/evidence/datahub-live-seed.json`
- `docs/evidence/datahub-live-spike.json`
- GitHub Actions run: https://github.com/Z3X-1337/toxicjoin/actions/runs/29975433969

Verified values:

- five datasets;
- nineteen governed fields;
- nine controlled tags;
- seven glossary terms;
- four lineage writes from the SDK seed;
- three upstream relationships read through MCP for the flagship column;
- official MCP tool discovery and contract validation;
- DataHub Decision document URN;
- first MCP process closed;
- fresh MCP process found the unique marker inside persisted document content through `grep_documents`;
- no token value, password, local endpoint, raw row, local path, or unrelated secret in retained evidence;
- both persisted JSON reports have reproducible `report_sha256` values.

The proof used a real ephemeral DataHub OSS deployment inside GitHub Actions. It does not claim that the hosted static Replay is a live DataHub session or that the temporary DataHub environment remains publicly available.

### 4. Public experience

Open the final hosted replay in a clean browser and verify:

- HTTP 200;
- visible Replay disclosure before interaction;
- no claim of live DataHub or DuckDB execution on the hosted static site;
- correct `/toxicjoin/` asset paths;
- desktop and mobile layouts;
- BLOCK, REWRITE→ALLOW, and ALLOW scenarios;
- benchmark values match the committed report.

The Docker/FastAPI path remains the executable product path.

### 5. Visual assets

Review the real-interface-derived Devpost cover and final screenshots. Reject any asset that:

- substitutes a generated dashboard for the product;
- exposes credentials, private account data, or local paths;
- implies unsupported functionality;
- presents Replay as live execution.

### 6. Microsoft narration

Review `microsoft-voice-production.md`.

Audition the first two paragraphs with identical settings using:

1. `en-US-AndrewMultilingualNeural`;
2. `en-US-BrianMultilingualNeural`.

Deliver one continuous 48 kHz PCM WAV, 2:30–2:45, without music or embedded effects. The final video will be synchronized to the actual waveform after the file is supplied.

### 7. Final video

Review `demo-video.md`, then watch the final encoded video from start to finish. Confirm:

- duration below 3:00;
- real ToxicJoin and DataHub footage only;
- BLOCK proves no execution;
- REWRITE shows the exact SQL change and final ALLOW;
- three result groups each contain forty subjects;
- live DataHub proof includes lineage, Decision write, and fresh-process read-back;
- benchmark claims match the committed report;
- captions spell DataHub, MCP, SQLGlot, DuckDB, pseudonym, and lineage correctly.

### 8. Devpost packet

Review `devpost-draft.md` line by line. Every `[PENDING_*]` marker must be removed and every URL tested before approval.

Required final links:

- public GitHub repository;
- hosted judge replay;
- public YouTube or Vimeo video under three minutes;
- examples directory;
- live DataHub evidence.

### 9. Exact-version approval

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
