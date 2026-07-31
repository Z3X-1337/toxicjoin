# Phase 7 Risk Register

- A workflow success without required artifact contents is rejected.
- A matching artifact name with a stale source SHA is rejected.
- Expired, empty, duplicate, unsafe, malformed, or digest-mismatched artifacts are rejected.
- Candidate manifests cannot be represented as immutable release identities.
- Multi-replica and PostgreSQL claims remain false until the Phase 12 authority changes them.
