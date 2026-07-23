# ToxicJoin — Real DataHub Video Capture Package

> This package is for the final demo edit. It must contain only screenshots captured from a real DataHub OSS instance after ToxicJoin metadata and Agent Registry entities are registered. It is not generated UI and it is not the public Replay.

## Capture source

The workflow `.github/workflows/capture-datahub-video.yml` starts the coordinated DataHub development quickstart, seeds the governed ToxicJoin datasets, registers the Compositional Risk Review Agent Skill and AI Agent, opens the real DataHub frontend on port 9002, and captures the required views with Chromium.

Current DataHub quickstart documentation exposes the local UI at `http://localhost:9002` with the default quickstart credentials. The capture workflow uses those credentials only inside the ephemeral GitHub Actions runner.

## Required frames

| File | Required visible evidence | Video use |
|---|---|---|
| `01-datahub-home.png` | DataHub UI | Establish that the demo is grounded in a real DataHub instance. |
| `02-retention-scores-overview.png` | `retention_scores`, `churn_score` | Show the governed sensitive model-output dataset before ToxicJoin evaluates the join. |
| `03-retention-scores-lineage.png` | `retention_scores`, Lineage | Show that ToxicJoin consumes DataHub lineage rather than treating tables as isolated assets. |
| `04-compositional-risk-agent-skill.png` | `Compositional Risk Review` | Show the reusable git-backed DataHub Agent Skill. |
| `05-toxicjoin-ai-agent.png` | `ToxicJoin Privacy Firewall Agent` | Show the registered Agent → Skill → tools/datasets concept in DataHub. |

The workflow fails if any required frame cannot be reached, if the visible evidence is absent, if the screenshot is unexpectedly small, or if the DataHub page produces JavaScript/page errors.

## Narration mapping

The exact timings will be locked only after the final Microsoft WAV is supplied. Use these semantic anchors rather than hard-coded timestamps:

### DataHub context sentence

Narration concept:

> ToxicJoin grounds the request in DataHub: governed schema fields, sensitivity labels, and upstream lineage.

Visual sequence:

1. `02-retention-scores-overview.png` — 55% of the sentence.
2. Slow controlled push into the `churn_score` field — 20%.
3. Cross-dissolve to `03-retention-scores-lineage.png` — final 25%.

### Reusable Agent Skill sentence

Narration concept:

> The same review workflow is packaged as a reusable DataHub Agent Skill, linked to the MCP tools and governed assets it depends on.

Visual sequence:

1. `04-compositional-risk-agent-skill.png` — first half.
2. `05-toxicjoin-ai-agent.png` — second half.

### DataHub memory sentence

The live Decision write/read-back is proven by committed JSON evidence and the live integration workflow. For the final video, combine the real DataHub UI frame with a clean on-screen callout containing the exact verified Decision fact. Do not fabricate a permanent public DataHub URL; the evidence environment was ephemeral.

## Editing rules

- Use the full-resolution captures as primary media.
- Gentle zoom/pan only; no fake dashboard reconstruction.
- Never alter DataHub entity names, field names, counts, or lineage relationships inside the screenshots.
- Do not cover the DataHub logo or entity title with captions.
- Do not present Agent Registry preview capability as a stable DataHub dependency; the repository explicitly labels it as a coordinated development-channel preview.
- Do not present the public Vercel Replay as a live DataHub session.
- Keep all sensitive values synthetic.

## Acceptance gate

Before the final edit may use these frames:

1. The capture workflow must be green.
2. The Artifact must contain all five PNGs plus `manifest.json`.
3. `manifest.json` must report `source: real-datahub-oss-ui`, exactly five captures, zero console errors, and zero page errors.
4. The visual frames must be reviewed for clipping, empty loading states, login pages, or stale search results.
5. The final Microsoft narration must be synchronized to the actual waveform; screenshot durations are not fixed in advance.
