# Durable evidence store

ToxicJoin retains essential textual evidence in a Git-backed SHA-256 object store:

```text
evidence/retained/catalog.json
evidence/retained/objects/sha256/<first-two-hex>/<full-sha256>.json
```

The catalog is self-hashed and records each object's exact byte digest, size, media type, source SHA, lifecycle, purpose, status, commands, environment, timestamps, and tool versions. Paths are derived from the digest rather than from mutable labels.

## Classification

Lifecycle and purpose are separate dimensions.

- `current` and `historical` describe whether an evidence record represents the current product boundary or a prior exact revision.
- `preview` is candidate or pull-request evidence and is not an immutable release identity.
- `replay-only` is deterministic hosted replay evidence and must not be represented as live execution.
- `submission` records submission readiness without claiming that Devpost was submitted.
- `operational` records current repository and retention state.

## Retrieval

The verifier reads the catalog, validates its self-hash, derives the object path from the requested SHA-256, verifies the source bytes, copies the object into a fresh destination, and verifies the copied bytes again.

```bash
python scripts/phase8_durable_evidence.py \
  --root . \
  --catalog evidence/retained/catalog.json \
  --source-sha "$SOURCE_SHA" \
  --checked-out-sha "$(git rev-parse HEAD)" \
  --retrieve-dir artifacts/phase8/retrieved \
  --output artifacts/phase8/phase8-retention-proof.json
```

The GitHub Actions proof may expire; the source objects and catalog do not, because they are versioned in Git. The proof artifact exists to demonstrate retrieval and exact-head verification.

## Large binary evidence

Browser screenshots, full Live DataHub bundles, SBOMs, and other large binary artifacts are indexed by digest but are not committed into normal Git history. Phase 9 must attach those bytes to the immutable GitHub Release and verify that their checksums the release manifest.
