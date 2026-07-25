# Final Security-Head Black-Box Validation

This is the final external production-image validation for the security-remediated ToxicJoin release.

## Exact target

- production PR: `#68`
- exact validated security head: `536c37c34de7b36495d33f63095585f72e5f4b46`
- landed `main` merge commit: `ee4991a93070c148e41dd158c952d5f1e9a6ed2c`
- `main` contains the exact validated head and the merge commit introduces no file-tree difference relative to that head.

The validation harness lived in draft PR #69 and was **never merged**. It resolved `refs/pull/68/head` at runtime, failed closed if the SHA moved, created a detached worktree at the exact production SHA, built the Docker image from that worktree, and interacted with the resulting container through HTTP and Docker inspection.

## Result

GitHub Actions run `30145592349`: **24/24 PASS**.

- artifact: `8615893443`
- artifact digest: `sha256:347c1cb66116367183a15e70a1ea892881cdfcf98321db581fbf10db5ae75d0a`
- report SHA-256: `c857cf8856e1850124f5d0c6bff2a2cdcbf1baa01ea21372db5bcb9fbb8d6dd3`
- failed probes: `0`

The sanitized machine-readable report is retained at [`final-security-blackbox.json`](final-security-blackbox.json).

## Covered boundaries

The external probes verified:

- runtime UID `10001`;
- read-only root filesystem;
- all Linux capabilities dropped;
- `no-new-privileges` enabled;
- bounded PID/CPU/memory configuration in the validation container;
- host publication restricted to loopback;
- minimal unauthenticated liveness response and security headers;
- restricted production API surface;
- hostile `Host` rejection;
- missing/invalid bearer rejection;
- malformed session rejection;
- scope separation for system, analyze, execute, and receipt access;
- request-body budget enforcement;
- DML mutation fail-closed with no execution summary;
- compositional sensitive export blocked before execution;
- legitimate low-risk aggregate allowed through the real execution boundary;
- receipt ownership isolation between principals;
- persisted receipt file mode `0600`;
- persisted-receipt modification detected through the public API;
- unknown and malformed receipt handling;
- per-principal rate limiting;
- no synthetic credentials, traceback, or internal source path in observed HTTP responses or container logs.

## Relationship to PR #68 regression coverage

The black-box suite validates externally observable production boundaries. PR #68 separately added direct regression coverage for the hardening findings that are better asserted at the semantic/integrity layer, including:

- `COUNT(CASE...)` and filtered conditional-aggregate privacy oracles;
- threshold and target-subject cohort-identity mutation;
- repeated protected-release / temporal-differencing closure;
- concurrent disclosure reservations;
- `PENDING -> RELEASED | ABORTED` finalization;
- receipt ID/timestamp/semantic/governance tampering;
- attacker recomputation of the public SHA-256 without the receipt HMAC key;
- HMAC key persistence, wrong-key rejection, and missing-key fail-closed behavior;
- protected execution-error sanitization;
- loopback-only default Compose publication.

The exact PR #68 head passed the complete release-gate set and Python 3.12 pytest reported **309 passed**.

## Scope

This is bounded engineering evidence, not a claim of formal verification, universal SQL/privacy coverage, differential privacy, or compliance certification.
