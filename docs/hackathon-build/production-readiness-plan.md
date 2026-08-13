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
| Python tests | 978 passed, 5 warnings | exact Linux candidate baseline is green; warnings remain visible |
| Frontend | 26 tests pass; typecheck and production build pass | Render-only redesigned frontend builds |
| HTTP deployment verifier | pass | ALLOW, verified REWRITE, BLOCK, and both closed bypasses behave correctly |
| Benchmark | 30/30; zero false allows; zero unsafe effective allows | bounded declared corpus is green |
| Adversarial mutations | 144 cases; no gate failures | declared mutation corpus is green |
| Governance dependency | 4 cases; no gate failures | policy depends on governed context as expected |
| Compositional ablation | no gate failures | targeted compositional contribution remains measured |
| Static supply-chain policy | pass | locks, pinned Actions, and workflow surfaces meet current static policy |
| Bandit release profile | pass | no medium/high issue at configured confidence |
| Root npm audit | pass | no current finding |
| Web npm audit | pass | remediated `nanoid` advisory; locked web audit is green |
| Python audit | pass with one governed exception | `cryptography` is fixed at 50.0.0; the only accepted finding is the narrowly scoped, time-bound `setuptools` upstream exception |
| Python lock consistency | pass | `uv lock --check` and the evidence-bound DataHub profiles agree |
| Release identity | pass | [v0.1.0](https://github.com/Z3X-1337/toxicjoin/releases/tag/v0.1.0) resolves to `4bf3a46dcbf6cf6a184067263102475e140abb04`, the exact `main` commit used for publication; Phase 9 verified the release assets |
| Exact-SHA Live DataHub | pass | See the [Phase 5 workflow history](https://github.com/Z3X-1337/toxicjoin/actions/workflows/phase5-live-datahub.yml?query=branch%3Amain); each successful run is the exact-revision authority only for the SHA recorded in that run |
| Current public demo | pass | [Render Free public demo](https://toxicjoin-public-demo.onrender.com/) last externally verified 2026-08-13; it is a synthetic fixture over the real execution path, not Live DataHub |

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
- [x] Run Python lint and all tests: 978 passed, 5 warnings on the exact Linux candidate.
- [x] Run frontend typecheck, 26 tests, production build, and audit.
- [x] Re-run benchmark, adversarial, governance, ablation, PPMC, and HTTP black-box
  verification.
- [x] Review the final diff for security-boundary changes and stale measured claims.

### P2 — Produce current real DataHub evidence

- [x] Publish and merge [PR #153](https://github.com/Z3X-1337/toxicjoin/pull/153) after its required
  checks passed.
- [x] Retain the historical [Phase 5 Exact-SHA Live DataHub run](https://github.com/Z3X-1337/toxicjoin/actions/runs/31659258883)
  from the then-current post-PR #153 `main` revision; it proves only the SHA recorded in that
  workflow.
- [x] Use the [Phase 5 workflow history](https://github.com/Z3X-1337/toxicjoin/actions/workflows/phase5-live-datahub.yml?query=branch%3Amain)
  for current `main` evidence; every run in that history proves only its recorded SHA.
- [x] Verify the [release exact-SHA run](https://github.com/Z3X-1337/toxicjoin/actions/runs/31699350889)
  on `4bf3a46dcbf6cf6a184067263102475e140abb04`, the same SHA used by `v0.1.0`.
- [x] Run [Live DataHub](https://github.com/Z3X-1337/toxicjoin/actions/runs/31657292807) and
  [Live DataHub Agent Registry](https://github.com/Z3X-1337/toxicjoin/actions/runs/31657292831)
  successfully for that previous candidate.
- [x] Inspect the uploaded `phase5-exact-sha-live-datahub-evidence` artifact for that previous
  candidate: it records an exact source checkout, real DataHub OSS services, read-only discovery,
  a writer limited to `save_document`, and a successful fresh-process read-back. Its sanitization
  report records no credential values, no raw warehouse rows, and zero GMS URL reflections.
- [x] Keep the Exact-SHA evidence in its workflow run and release manifest; this plan does not
  elevate historical or branch-only evidence beyond its recorded revision.
- [x] Update current-evidence documentation only after the live gate passes.

### P3 — Publish a current zero-cost public demo

- [x] Deploy the current hardened Docker image to a public Render Free web service in explicit
  fixture mode, with no Postgres, persistent disk, add-on, paid instance, organization data, or
  credentials.
- [x] Run `scripts/verify_deployment.py` against the
  [public URL](https://toxicjoin-public-demo.onrender.com/).
- [x] Record the public URL, fixture data mode, policy version, health/readiness result, browser
  ALLOW/BLOCK evidence, and idle cold-start result in the deployment PR. The external verification
  date is 2026-08-13; exact source revisions remain in the PR and deployment record.
- [x] Remove the secondary static host from source, workflows, supply-chain artifacts, release
  contracts, retained current evidence, and documentation. Repository scans return no provider
  name, retired URL, or old static-host workflow reference.
- [ ] Delete the retired project from the owner's external hosting account. This is an account-level
  destructive action, separate from the repository cleanup, and requires owner-side dashboard access.

### P3.1 — Render-only interface redesign candidate

- [x] Replace the prior visual system and page hierarchy with a new responsive design.
- [x] Make Render/same-origin API results the only interactive runtime source.
- [x] Fail explicitly with reconnect/retry controls when bootstrap or execution is unavailable.
- [x] Verify desktop 1440×1000 and mobile 390×844: no horizontal overflow, console error, page
  error, or unexpected alert; the real fixture path produced REWRITE → ALLOW.
- [x] Publish immutable historical release `v0.2.0`; its tag remains bound to its original commit.
- [x] Prepare the `v0.2.1` runtime-version-provenance patch candidate and no-side-effect Phase 9
  preview contracts.
- [ ] Merge, publish `v0.2.1`, and manually deploy the resulting exact `main` commit to Render only
  after owner review and explicit approval.

### P4 — Judge and submission finish

- [x] Reconcile stale test counts and release status across judge-facing documentation.
- [ ] Verify desktop/mobile browser behavior on the live URL.
- [ ] Produce and publish the final video under three minutes.
- [ ] Synchronize the Devpost project with the exact verified release.
- [ ] Request explicit owner approval before Devpost mutation or final submission.

## Current owner-controlled delivery tasks

No active technical blocker remains in the `v0.2.1` runtime-version-provenance candidate. Merge/release, manual Render
deployment, deletion of the retired external hosting project, final video publication, and Devpost
synchronization remain owner-controlled delivery tasks.

1. A future public **Live DataHub** deployment requires its own authenticated account, governed
   credentials, and persistent audit/privacy state. It is separate from the zero-cost fixture demo.
2. Video upload and Devpost mutation require the owner's accounts and final approval.

These tasks do not justify substituting mock evidence or relabeling historical artifacts.
