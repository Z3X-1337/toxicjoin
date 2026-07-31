# Phase 6 Production Browser E2E

This phase closes the gap between unit/component testing and the actual judge-facing production topology.

## Architecture under test

The workflow builds the committed multi-stage `Dockerfile`, runs the resulting image with the same hardening used by canonical CI, and drives the integrated React frontend and FastAPI API through the published container port. `vite dev`, generated dashboards, and synthetic replacement interfaces are outside the success path.

The browser driver is the already locked root dependency:

- Node.js `22.16.0`
- npm `10.9.2`
- `playwright-core==1.54.1`

Browser binaries and their system dependencies are installed by that exact package. No floating JavaScript dependency is introduced.

## Matrix

The evidence tool executes six production cells:

| Engine | Desktop | Mobile |
|---|---:|---:|
| Chromium | yes | yes |
| Firefox | yes | yes |
| WebKit | yes | yes |

Each cell runs the three authoritative scenarios through `/api/execute-safe`, compares the API payload with the rendered lifecycle and receipt, performs receipt lookup, checks accessibility and responsive layout, and captures real full-page screenshots.

## Negative paths

Two negative paths are isolated from the production-success cells:

1. `execute-safe` is intentionally returned as `503` to prove the UI discloses failure and offers retry without silently switching to Replay.
2. Bootstrap API calls are intentionally made unavailable to prove the interface uses the exact Replay wording and never calls live execution while in Replay mode.

Route interception is used only to create these negative conditions. It is never used to fabricate successful ALLOW, REWRITE, BLOCK, receipt, or security-header evidence.

## Evidence

The successful Artifact contains:

- `browser-e2e-report.json`
- `source-identity.json`
- `container-inspect.json`
- `production-container.log`
- `security-headers.json`
- 20 PNG screenshots from the real production build
- `SHA256SUMS`

`browser-e2e-report.json` is self-hashed and binds every result to the exact source SHA, Git tree, image ID, browser version, viewport, and screenshot hash.
