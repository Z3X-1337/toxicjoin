# ToxicJoin — Microsoft Voice Production Specification

This document defines the voice asset that will drive the final demo edit. The final video must be cut to the delivered narration, not the other way around.

## Voice audition

Two production-ready SSML files are committed beside this document:

- `microsoft-tts-andrew.ssml` — `en-US-AndrewMultilingualNeural`.
- `microsoft-tts-brian.ssml` — `en-US-BrianMultilingualNeural`.

They use the same narration, pause map, rate, pitch, and pronunciation controls; the voice name is the intentional A/B variable.

Generate the first two paragraphs with both voices before rendering the full script:

1. **Primary:** `en-US-AndrewMultilingualNeural` — calm, clear, neutral technology-presenter delivery.
2. **Backup:** `en-US-BrianMultilingualNeural` — slightly deeper delivery if Andrew sounds too light for the product.

Use the same rate, pitch, and pause settings for both samples. Select the voice based on intelligibility, natural paragraph transitions, and correct pronunciation of the product terms—not merely on depth. Do not use a personal or cloned voice.

After selecting the voice, render the **full matching SSML file** rather than recreating its settings manually. Do not mix paragraphs from Andrew and Brian in the final narration.

## Required output

- Provider: Microsoft Azure Speech neural text-to-speech through Speech Studio Audio Content Creation or the Azure Speech API.
- Language: native US English.
- Voice character: calm, intelligent, technically credible, neutral, and easy to understand.
- Delivery style: modern technology keynote; not a trailer, advertisement, radio announcer, or aggressive sales voice.
- Target narration duration: **2:30–2:45**.
- Hard video limit: **under 3:00**.
- Audio format: **WAV, PCM, 48 kHz, 16-bit or 24-bit**.
- Channels: mono preferred; stereo is acceptable if the voice is centered and contains no effects.
- No music, reverb, compression pumping, room simulation, or sound effects in the supplied voice file.
- Leave approximately 250–450 ms of clean silence before the first word and after the final word.
- Export one continuous narration file. Keep a second unprocessed copy if the Microsoft interface offers processing options.

## Performance direction

- Pronounce `ToxicJoin` as **Toxic Join**.
- Pronounce `DataHub` as **Data Hub**.
- Pronounce `SQL` as **S-Q-L**, not “sequel.”
- Pronounce `MCP` as **M-C-P**.
- Pronounce `SDK` as **S-D-K**.
- Pronounce `CI` as **C-I**.
- Pronounce `DuckDB` as **Duck D-B**.
- Give slight emphasis to: `before the query reaches the warehouse`, `deterministic`, `never calls Duck D-B`, `fresh one`, `Agent Skill`, and `zero false allows`.
- Do not over-emphasize BLOCK, REWRITE, or ALLOW like advertising slogans.
- Use short intentional pauses between sections. Avoid audible breaths inserted by the generator.
- Prefer a slightly slower rate over post-production time stretching. Do not speed up or slow down the final WAV unless a minor correction below 2% is unavoidable.

## Final narration script

AI data agents can generate useful S-Q-L in seconds. But two acceptable datasets can become sensitive when joined. Toxic Join evaluates that composed output before the query reaches the warehouse.

Toxic Join receives the task purpose, S-Q-L, and expected subject key. A deterministic policy returns allow, safely rewrite, or block. An L-L-M does not control enforcement.

Here, the agent combines a stable customer pseudonym, two quasi-identifiers, and a sensitive support category. No single source explains the risk. The combination does. Toxic Join blocks the query and never calls Duck D-B.

The flagship query groups a sensitive churn score without a trusted minimum number of customers. Toxic Join adds a subject-bound threshold, reparses the generated S-Q-L, and runs the same policy again. A rewrite is never trusted merely because Toxic Join produced it.

Only after the final decision becomes allow does the read-only executor run. Verification checks the complete result, confirms every region contains forty distinct subjects, rejects forbidden raw output fields, and stores evidence without persisting result rows.

Data Hub is governed context and durable memory. Toxic Join seeds five datasets, nineteen classified fields, tags, glossary terms, and column lineage through the official S-D-K. Through the official M-C-P Server, it reads governed context, writes a Data Hub Decision, closes that process, opens a fresh one, and verifies the saved marker. The review procedure is also published as a git-backed Data Hub Agent Skill; a separate preview proves the Agent, Skill, five M-C-P tools, and five dataset dependencies.

A balanced thirty-query corpus runs through the real pipeline in C-I: ten allow, ten rewrite, and ten block. The declared corpus has thirty correct initial decisions, thirty correct effective outcomes, and zero false allows. Unsupported rewrites fail closed.

Toxic Join gives AI data agents a privacy boundary they can explain, enforce, and leave behind in Data Hub for the next agent or reviewer.

## Suggested pause map

The checked-in SSML files already encode the intended pause ranges. When using a UI that ignores SSML breaks, approximate:

- After paragraph 1: 300–350 ms
- After paragraph 2: 250–300 ms
- After paragraph 3: 350–400 ms
- After paragraph 4: 300–350 ms
- After paragraph 5: 300–350 ms
- After paragraph 6: 400–450 ms
- After paragraph 7: 300–350 ms
