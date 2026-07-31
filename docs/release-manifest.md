# ToxicJoin Release Manifest

`Generated Release Manifest` emits schema `2.0` in two explicit modes.

- `candidate`: verifies an exact pull-request head while requiring its recorded `main` base to remain
  current. The output states that it is not a release identity.
- `release`: verifies only the exact current `main` SHA.

The generator polls GitHub Actions for eleven exact-SHA workflows, verifies required job conclusions,
downloads required artifacts without forwarding the bearer token to signed storage, validates the
GitHub ZIP digest, rejects unsafe archives, and validates each evidence schema.

The manifest fails closed when a workflow or artifact is missing, stale, skipped, expired, empty,
duplicated, malformed, digest-mismatched, or inconsistent with the exact source SHA.
