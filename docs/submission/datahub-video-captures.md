# ToxicJoin — Real DataHub Video Capture Package

> This package is for the final demo edit. Every screenshot must come from a real DataHub OSS instance after ToxicJoin metadata and Agent Registry preview entities are registered. It is not generated UI and it is not the public Replay.

## Capture source

The workflow `.github/workflows/capture-datahub-video.yml` starts the coordinated DataHub development quickstart, seeds the governed ToxicJoin datasets, registers and independently verifies the Compositional Risk Review Agent Skill graph, opens the real DataHub frontend on port 9002, and captures only mature OSS UI views with Chromium.

Current DataHub quickstart documentation exposes the local UI at `http://localhost:9002` with the default quickstart credentials. The capture workflow uses those credentials only inside the ephemeral GitHub Actions runner.

The public DataHub documentation states that the configurable **Agents** UI is currently DataHub Cloud Private Beta rather than a Self-Hosted OSS feature. For that reason this package does **not** fabricate Agent/Skill UI screenshots from OSS search. The Agent Registry preview contribution is represented by its independently verified machine evidence instead.

## Required real DataHub OSS frames

| File | Required visible evidence | Video use |
|---|---|---|
| `01-retention-scores-search.png` | Actual Dataset search result, `ToxicJoin retention_scores`, `churn_score` | Establish real DataHub discovery and show that the synthetic governed asset is indexed. |
| `02-retention-scores-overview.png` | `ToxicJoin retention_scores`, `churn_score`, `customer_id`, `model_timestamp` | Show the governed sensitive model-output dataset and field-level classifications. |
| `03-retention-scores-lineage.png` | `retention_scores`, Lineage, `customers`, `orders`, `support_cases`, `location_activity` | Show the four real upstream paths consumed by ToxicJoin's context model. |

The capture workflow fails if a required Dataset link is absent, if the page says `No results found`, if visible loading skeletons remain, if any expected upstream node is missing, if a screenshot is unexpectedly small, or if the DataHub page produces JavaScript/page errors.

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
3. `03-retention-scores-lineage.png` — reveal the four upstream datasets converging on the flagship asset.

### Reusable Agent Skill sentence

Narration concept:

> The same review workflow is packaged as a reusable DataHub Agent Skill, linked to the MCP tools and governed assets it depends on.

Visual sequence:

1. Keep the real DataHub lineage frame visible at reduced scale or blurred depth.
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
- Do not present Agent Registry preview capability as a stable DataHub dependency; label it as coordinated development-channel preview.
- Do not present the public Vercel Replay as a live DataHub session.
- Keep all values synthetic.

## Acceptance gate

Before the final edit may use this package:

1. The capture workflow must be green.
2. The Artifact must contain all three PNGs plus `manifest.json` and both Agent Registry reports.
3. `manifest.json` must report `source: real-datahub-oss-ui`, exactly three captures, zero console errors, zero page errors, and `visual_ui_claimed: false` for Agent Registry preview evidence.
4. The Dataset search frame must contain a real `/dataset/` result rather than query text alone.
5. The Lineage frame must visibly contain all four expected upstream Dataset names and no loading skeletons.
6. The Agent Registry reports must pass the count/dependency assertions in CI.
7. All three frames must be visually reviewed for clipping, loading states, login pages, tours, or stale search results.
8. The final Microsoft narration must be synchronized to the actual waveform; screenshot durations are not fixed in advance.
