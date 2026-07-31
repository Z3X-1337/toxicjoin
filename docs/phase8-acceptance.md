# Phase 8 Acceptance — Durable Evidence Retention

Phase 8 is accepted only when the exact candidate head proves all of the following.

1. Essential machine-readable evidence is stored in Git under a SHA-256 content-addressed object path and does not depend on GitHub Actions artifact retention.
2. The catalog self-hash, every object digest, every object size, and every object path are verified fail-closed.
3. Every retained entry records exact source SHAs, provenance commands, environment, timestamps, and tool versions.
4. The catalog distinguishes `current` from `historical` lifecycle and distinguishes `preview`, `replay-only`, `submission`, and operational purpose.
5. A fresh retrieval directory receives an object selected only by SHA-256, and the copied bytes reproduce the same digest.
6. Large binary evidence is not committed as repository bloat. It remains digest-indexed and must become a Phase 9 release asset before immutable release closure.
7. The Phase 8 proof is bound to the exact pull-request head and is required by the generated candidate manifest.
8. Missing objects, path traversal, duplicate IDs or digests, malformed provenance, tampering, stale source identity, or failed retrieval stop the gate.

Phase 8 does not create a tag, GitHub Release, Vercel deployment, Devpost submission, PostgreSQL integration, ruleset, or repository cleanup.
