# Retained ToxicJoin evidence

This directory is the durable, Git-backed textual evidence store established in Phase 8.

- `catalog.json` is the self-hashed index and provenance authority.
- `objects/sha256/` contains immutable objects addressed by the SHA-256 of their exact bytes.
- Object filenames and catalog digests must agree.
- Large binary evidence is not stored here; it remains digest-indexed for attachment to the Phase 9 immutable release.

Run `python scripts/phase8_durable_evidence.py --help` for the retrieval verifier.
