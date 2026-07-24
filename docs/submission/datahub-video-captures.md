# ToxicJoin — Real DataHub Video Capture Package

> This package is for the final demo edit. Every screenshot must come from a real DataHub OSS instance after ToxicJoin metadata and Agent Registry preview entities are registered. It is not generated UI and it is not the public Replay.

## Capture source

The workflow `.github/workflows/capture-datahub-video.yml` starts the coordinated DataHub development quickstart, seeds the governed ToxicJoin datasets, registers and independently verifies the Compositional Risk Review Agent Skill graph, opens the real DataHub frontend on port 9002, and captures only mature OSS UI states with Chromium.

Current DataHub quickstart documentation exposes the local UI at `http://localhost:9002` with the default quickstart credentials. The capture workflow uses those credentials only inside the ephemeral GitHub Actions runner.

The public DataHub documentation states that the configurable **Agents** UI is currently DataHub Cloud Private Beta rather than a Self-Hosted OSS feature. For that reason this package does **not** fabricate Agent/Skill UI screenshots from OSS search. The Agent Registry preview contribution is represented by its independently verified machine evidence instead.

The interactive self-hosted Lineage canvas also remained in a skeletal loading state under headless Chromium even though DataHub's loaded entity Summary exposed authoritative lineage counts and the SDK/MCP evidence independently verified the upstream entities. The package therefore captures the loaded real DataHub Summary panel rather than presenting a loading canvas as lineage evidence.

## Required real DataHub OSS frames

| File | Required visible evidence | Video use |
|---|---|---|
| `01-retention-scores-search.png` | Actual Dataset search result, `ToxicJoin retention_scores`, `churn_score` | Establish real DataHub discovery and show that the synthetic governed asset is indexed. |
| `02-retention-scores-overview.png` | `ToxicJoin retention_scores`, `churn_score`, `customer_id`, `model_timestamp` | Show the governed sensitive model-output dataset and field-level classifications. |
| `03-retention-scores-lineage-summary.png` | `ToxicJoin retention_scores`, `UPSTREAM`, `Depends on 4 datasets`, `DOWNSTREAM`, `Used by 1` | Show the loaded lineage dependency summary without exposing a skeletal canvas. |

The capture workflow fails if a required Dataset link is absent, if the page says `No results found`, if visible loading skeletons remain in a captured region, if a screenshot is unexpectedly small, or if the DataHub page produces JavaScript/page errors.

## Lineage evidence boundary

The third frame proves the lineage counts exactly as displayed by the real DataHub OSS UI:

- upstream dependency count: `4 datasets`;
- downstream usage count: `1`.

The exact upstream names are not inferred from the screenshot. They are taken from independently verified seed/MCP evidence:

- `customers`;
- `orders`;
- `support_cases`;
- `location_activity`.

For the final video, the DataHub Summary panel may remain visible while a restrained ToxicJoin evidence overlay lists those four names. The overlay must be labeled as verified evidence and must not imitate a DataHub graph node or claim that the skeletal canvas rendered those names.

## Agent Registry preview evidence

The Artifact also contains:

- `.toxicjoin/datahub-agent-registry.json`
- `.toxicjoin/datahub-agent-registry-verified.json`

Those reports must prove:

- one registered `agentSkill`;
- one registered `aiAgent`;
- five MCP tool API entities;
- Agent → Skill dependency;
- Agent → five tool dependencies;
- Agent → five governed dataset dependencies;
- independent GraphQL read-back verification.

For the final video, present this contribution as a clean ToxicJoin evidence overlay next to the real DataHub OSS footage. The overlay may quote exact counts and URNs from the verified reports, but it must not imitate a DataHub UI screen or imply that the Cloud Agents UI is available in OSS.

## Narration mapping

The exact timings will be locked only after the final Microsoft WAV is supplied. Use semantic anchors rather than hard-coded timestamps.

### DataHub context sentence

Narration concept:

> ToxicJoin grounds the request in DataHub: governed schema fields, sensitivity labels, and upstream lineage.

Visual sequence:

1. `01-retention-scores-search.png` — establish real DataHub discovery.
2. `02-retention-scores-overview.png` — slow controlled push into `churn_score` and its governed metadata.
3. `03-retention-scores-lineage-summary.png` — push into the real lineage summary while the verified four upstream names appear as a restrained evidence overlay.

### Reusable Agent Skill sentence

Narration concept:

> The same review workflow is packaged as a reusable DataHub Agent Skill, linked to the MCP tools and governed assets it depends on.

Visual sequence:

1. Keep the real DataHub lineage-summary frame visible at reduced scale or blurred depth.
2. Animate a restrained evidence overlay sourced from `datahub-agent-registry-verified.json`:
   - `1 Agent Skill`
   - `1 AI Agent`
   - `5 MCP tools`
   - `5 governed datasets`
   - `Independent read-back: verified`
3. Add a small `Development-channel preview` label so the stability boundary is explicit.

### DataHub memory sentence

The live Decision write/read-back is proven by committed JSON evidence and the live integration workflow. For the final video, combine a real DataHub frame with a clean on-screen callout containing the exact verified Decision fact. Do not fabricate a permanent public DataHub URL; the evidence environment was ephemeral.

## Editing rules

- Use the full-resolution DataHub captures as primary media.
- Gentle zoom/pan only; no fake dashboard reconstruction.
- Never alter DataHub entity names, field names, counts, or lineage relationships inside screenshots.
- Do not cover the DataHub logo or Dataset title with captions.
- Never present machine evidence as a screenshot of a DataHub feature that is not exposed by Self-Hosted OSS.
- Never present the skeletal Lineage canvas as loaded evidence; use the captured Summary panel and separately verified upstream names.
- Do not present Agent Registry preview capability as a stable DataHub dependency; label it as coordinated development-channel preview.
- Do not present the public Vercel Replay as a live DataHub session.
- Keep all values synthetic.

## Verified capture review — July 23, 2026

The exact PR head `6393028ce7b78d11c031b6b46a51773fc42b57f9` passed both normal CI and `Capture DataHub Video Evidence` before this review was recorded.

Capture workflow:

- run: `30030444776`;
- conclusion: `success`;
- Artifact: `toxicjoin-real-datahub-video-captures`;
- Artifact ID: `8573156142`;
- Artifact digest: `sha256:1b2ff7d4081e8a04b08738ce5663e15fe18fa4353e64ea2b3cb6ab0168bf58cf`;
- Artifact expiry: August 22, 2026.

Independent visual review of the downloaded Artifact confirmed:

- `01-retention-scores-search.png` is a real loaded DataHub search page, not query text alone; the `ToxicJoin retention_scores` dataset result is selected and `churn_score` is visibly matched;
- `02-retention-scores-overview.png` is a loaded DataHub Columns view showing exactly `churn_score`, `customer_id`, and `model_timestamp`, with no login page, empty state, loading skeleton, tour, or modal obstruction;
- `03-retention-scores-lineage-summary.png` is a clean real DataHub Summary-panel crop showing `UPSTREAM — Depends on 4 datasets` and `DOWNSTREAM — Used by 1`, with no skeletal lineage canvas inside the captured region;
- all three frames preserve the DataHub identity and ToxicJoin dataset title without a fabricated dashboard overlay;
- no visible real-person data or non-synthetic warehouse content appears in the frames.

File dimensions and SHA-256:

| File | Dimensions | SHA-256 |
|---|---:|---|
| `01-retention-scores-search.png` | 1600×1000 | `d3c95efc6b56414ef26f8173e16cd5374872dc60da4a2d665fdaa87c5a784bb9` |
| `02-retention-scores-overview.png` | 1600×1000 | `994c7ff526d69f023409ee2906de94dcf3ae47daabc8e9194f8e170fae98352f` |
| `03-retention-scores-lineage-summary.png` | 495×380 | `b898c3ca043abcd4850bc9b73abfbc9ac8d2985dbd83e627a312855d8071f347` |
| `manifest.json` | — | `03f59ea11fdf181d69a0237c518aec922c7e9b4c0aab05a359b17b0d6b4d9656` |

The accompanying machine evidence was also present in the same Artifact:

- `datahub-agent-registry.json` — `fe7e8fa842dd6e0de08ada1b59d173312b8693c2f2ea563fc19ef50e3cf2bc62`;
- `datahub-agent-registry-verified.json` — `788311a56367e36f8b8cd9dc06f1699eeb14a68a4c8e9da4c69f4e262d56e566`;
- `datahub-seed.json` — `03d296796d2069e80a0c056f8b6ddba93aef812c231477b75f5b7395a12f8d9f`.

**Review decision:** frames 1–3 are approved as source media for the final edit. The Agent Registry remains machine-evidence-only, and the lineage canvas limitation remains explicitly disclosed.

## Acceptance gate

Before the final edit may use this package:

1. [x] The capture workflow is green.
2. [x] The Artifact contains all three PNGs plus `manifest.json` and both Agent Registry reports.
3. [x] `manifest.json` reports `source: real-datahub-oss-ui`, exactly three captures, zero console errors, zero page errors, and `visual_ui_claimed: false` for Agent Registry preview evidence.
4. [x] `manifest.json` reports `lineage_evidence.visual_mode: loaded-summary-panel`, `upstream_dataset_count: 4`, and `downstream_usage_count: 1`.
5. [x] The Dataset search frame contains a real `/dataset/` result rather than query text alone.
6. [x] The lineage-summary frame visibly contains `Depends on 4 datasets` and `Used by 1` and contains no loading skeletons inside the captured region.
7. [x] The Agent Registry reports passed the count/dependency assertions in CI.
8. [x] All three frames were visually reviewed for clipping, loading states, login pages, tours, or stale search results.
9. [ ] The final Microsoft narration must be synchronized to the actual waveform; screenshot durations are not fixed in advance.
