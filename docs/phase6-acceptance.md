# Phase 6 Acceptance — Production Browser E2E and Cross-Browser Validation

Phase 6 passes only when one exact candidate SHA satisfies every requirement below.

## Production path

- The committed `Dockerfile` builds the frontend and API into the production image.
- Browser tests use the hardened production container, not `vite`, a mock server, generated UI, or static Replay as a substitute.
- The container remains non-root, read-only, capability-dropped, and protected by `no-new-privileges`.

## Browser and viewport matrix

- Chromium, Firefox, and WebKit complete the full production path where supported by Playwright on Ubuntu 24.04.
- Every engine is exercised at a desktop viewport and a mobile viewport.
- Responsive checks reject horizontal overflow and interactive controls outside the viewport.

## Required product behavior

- Real API execution covers ALLOW, REWRITE, and BLOCK.
- REWRITE must become verified ALLOW through the production frontend/API path.
- Every decision displays a receipt whose exact receipt lookup succeeds and whose integrity hash matches.
- A valid missing receipt lookup returns the stable `RECEIPT_NOT_FOUND` disclosure.
- An induced `execute-safe` 503 produces the real failure disclosure and retry control without relabeling the session as Replay.
- An unavailable bootstrap API produces a clearly labeled deterministic Replay, states that no live execution or DataHub write is claimed, and performs no live `execute-safe` request.
- Required security headers and API no-store behavior are checked from real browser/network responses.
- Required accessibility and responsive layout checks require one H1, semantic landmarks, unique IDs, named interactive controls, a usable keyboard tab stop, and no horizontal overflow.
- Screenshots are captured from the real production build. Fake or generated UI evidence is prohibited.

## Evidence integrity

- The workflow explicitly checks out the exact pull-request head SHA.
- The final report records the exact candidate SHA, Git tree, image ID, browser versions, viewports, assertions, screenshots, container hardening, and boundaries.
- Every report and screenshot is SHA-256 indexed in `SHA256SUMS`.
- Missing, skipped, stale, or partially successful browser cells fail closed.

## Preserved boundaries

- Phase 7 is not started.
- PR #118 and PostgreSQL remain isolated and unmodified.
- Vercel and Devpost are not mutated.
- No tag or release is created.
- `main` is not modified directly.
- Merging requires a later explicit authorization tied to the exact final head SHA.
