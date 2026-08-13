# ToxicJoin Production-Readiness Plan

Status: active execution plan for the post-submission improvement window.

This plan applies the repository-owned
[`production-execution-prompt.md`](production-execution-prompt.md). It is evidence-driven and
supersedes unchecked milestone boxes as a statement of current readiness. It does not override
the claim hierarchy in [`../architecture.md`](../architecture.md).

## Measured baseline — 2026-08-13

| Gate | Result | Interpretation |
| --- | --- | --- |
| Python lint | pass | `ruff check src tests` |
| Python tests | 968 passed, 1 skipped, 5 warnings | functional baseline is green; warnings remain visible |
| Frontend | 24 tests pass; typecheck and production build pass | current frontend builds |
| HTTP deployment verifier | pass | ALLOW, verified REWRITE, BLOCK, and both closed bypasses behave correctly |
| Benchmark | 30/30; zero false allows; zero unsafe effective allows | bounded declared corpus is green |
| Adversarial mutations | 144 cases; no gate failures | declared mutation corpus is green |
| Governance dependency | 4 cases; no gate failures | policy depends on governed context as expected |
| Compositional ablation | no gate failures | targeted compositional contribution remains measured |
| Static supply-chain policy | pass | locks, pinned Actions, and workflow surfaces meet current static policy |
| Bandit release profile | pass | no medium/high issue at configured confidence |
| Root npm audit | pass | no current finding |
| Web npm audit | fail on baseline | High `nanoid` advisory; remediation in this branch |
| Python audit | fail on baseline | `cryptography 49.0.0` advisory; remediation in this branch |
| Python lock consistency | fail on baseline | `pyproject.toml` disagrees with the committed DataHub lock profiles |
| Exact-SHA Live DataHub | pass | Previous verified PR candidate `45afaaebcfe47dbf306b70a5dfa8137b8d3bc1e1` passed [Phase 5 run 31657292789](https://github.com/Z3X-1337/toxicjoin/actions/runs/31657292789); the PR description and checks identify the newest current-head evidence |
| Current public live deployment | pending | the retained Vercel URL is historical replay, not current live execution |

## Prioritized execution

### P0 — Restore trustworthy release gates

- [x] Reproduce the web dependency advisory.
- [x] Reproduce Python manifest/lock drift with exact `uv 0.8.4`.
- [x] Reuse the independently documented `cryptography 50.0.0` lock fix from PR #142.
- [x] Upgrade the affected transitive `nanoid` lock entry to a fixed version.
- [x] Reconcile DataHub dependency declarations with the evidence-bound lock/toolchain profiles.
- [x] Add `uv lock --check` to CI and static workflow invariants.
- [x] Re-run both npm audit validators with zero findings.
- [x] Install both exact Python profiles and verify their required DataHub imports.
- [x] Re-run both locked Python vulnerability-service audits; each reports only the
  documented, unexpired `setuptools` exception and no unapproved finding.

### P1 — Revalidate the canonical product

- [x] Re-sync from exact locks after dependency changes.
- [x] Run Python lint and all tests: 968 passed, 1 skipped, 5 warnings. The skipped test is
  `tests/security/test_disclosure_ledger_security.py::test_ledger_file_is_owner_only_and_symlink_target_is_rejected`:
  it deliberately skips only when the current platform cannot create a symbolic link. This
  Windows environment could not create the test symlink, so the symlink-rejection assertion was
  not altered merely to remove the platform-dependent skip.
- [x] Run frontend typecheck, 24 tests, production build, and audit.
- [x] Re-run benchmark, adversarial, governance, ablation, PPMC, and HTTP black-box
  verification.
- [x] Review the final diff for security-boundary changes and stale measured claims.

### P2 — Produce current real DataHub evidence

- [x] Publish the branch and open [Draft PR #153](https://github.com/Z3X-1337/toxicjoin/pull/153).
- [x] Run [Phase 5 Exact-SHA Live DataHub](https://github.com/Z3X-1337/toxicjoin/actions/runs/31657292789)
  successfully on the previous verified PR candidate SHA
  `45afaaebcfe47dbf306b70a5dfa8137b8d3bc1e1`.
- [x] Run [Live DataHub](https://github.com/Z3X-1337/toxicjoin/actions/runs/31657292807) and
  [Live DataHub Agent Registry](https://github.com/Z3X-1337/toxicjoin/actions/runs/31657292831)
  successfully for that previous candidate.
- [x] Inspect the uploaded `phase5-exact-sha-live-datahub-evidence` artifact for that previous
  candidate: it records an exact source checkout, real DataHub OSS services, read-only discovery,
  a writer limited to `save_document`, and a successful fresh-process read-back. Its sanitization
  report records no credential values, no raw warehouse rows, and zero GMS URL reflections.
- [x] Keep the newest Exact-SHA evidence for the current PR head in the PR description and checks;
  this plan does not claim a `main` evidence run before merge.
- [x] Update current-evidence documentation only after the live gate passes.

### P3 — Replace the historical public-only experience

- [ ] Deploy the current hardened Docker image to a public container host with persistent runtime
  storage.
- [ ] Run `scripts/verify_deployment.py` against the deployed URL.
- [ ] Record the exact candidate SHA, data mode, policy version, and verification output.
- [ ] Keep the historical Vercel replay labeled and separate until the live URL is proven.

### P4 — Judge and submission finish

- [ ] Reconcile stale test counts and release status across judge-facing documentation.
- [ ] Verify desktop/mobile browser behavior on the live URL.
- [ ] Produce and publish the final video under three minutes.
- [ ] Synchronize the Devpost project with the exact verified release.
- [ ] Request explicit owner review before merge or submission mutation.

## Current owner-controlled delivery tasks

No active blocker remains for PR merge readiness. Public live deployment, final video publication, and Devpost synchronization remain owner-controlled delivery tasks.

1. A current public URL requires an authenticated Fly.io, Render, or equivalent deployment
   account and persistent storage configuration.
2. Video upload and Devpost mutation require the owner's accounts and final approval.

These tasks do not justify substituting mock evidence or relabeling the historical replay.
