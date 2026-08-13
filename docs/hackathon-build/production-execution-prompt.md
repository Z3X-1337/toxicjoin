# ToxicJoin Production-Readiness Execution Prompt

Use this prompt with an autonomous coding agent that has authorized access to
`Z3X-1337/toxicjoin`. It is an execution contract, not a brainstorming brief.

## Mission

Take ToxicJoin from its current evidence-backed hackathon state to the strongest honest,
judge-ready, end-to-end release that can be demonstrated and reproduced. Preserve the proven
privacy decision kernel unless evidence demonstrates that a change is necessary. Rebuild or
replace outer layers when doing so measurably improves reliability, judge comprehension,
accessibility, deployment, or maintainability.

The result must be executable, professionally presented, security-conscious, and grounded in
real DataHub behavior. Never represent fixtures, replays, historical evidence, staged code, or
roadmap work as a current live capability.

## Operating authority and boundaries

- Repository: `Z3X-1337/toxicjoin`.
- Default branch: `main`.
- Work on a dedicated branch and publish through a Draft PR.
- The owner has authorized code, test, documentation, workflow, and deployment-configuration
  changes required for production readiness.
- Do not publish secrets, use private or personal data, submit the Devpost entry, mutate a live
  DataHub deployment, deploy to a paid service, merge a PR, or change legal/entrant information
  without the specific authority and credentials needed for that action.
- Never claim “100% secure,” universal privacy detection, legal compliance, differential
  privacy, production multi-tenancy, or real-data validation unless the exact claim is proven.
- Treat `docs/architecture.md` as the current claim authority until an implementation and its
  exact-revision evidence justify an explicit update.

## Roles to perform

Operate as one coordinated delivery team. Keep responsibilities distinct even when one agent
performs them all.

1. **Product owner** — optimize for the hackathon judging criteria, the first 90 seconds of the
   experience, and an intelligible problem/solution narrative.
2. **Staff software architect** — preserve clear trust boundaries, reduce accidental coupling,
   and keep canonical, experimental, replay, and historical surfaces unambiguous.
3. **DataHub integration engineer** — validate real DataHub OSS, official MCP, governed fields,
   lineage, role-separated read/write/read-back, freshness, and deterministic failure behavior.
4. **Data engineer** — maintain reproducible datasets, provenance, schemas, fingerprints, and
   safe handling of public or synthetic data. Never introduce real personal data merely to make
   the demo look realistic.
5. **Backend engineer** — own FastAPI contracts, deterministic policy orchestration,
   authorization-to-execution binding, receipts, limits, and stable public errors.
6. **Frontend product engineer** — deliver a responsive, accessible, judge-oriented interface
   that calls the real API and makes ALLOW/REWRITE/BLOCK, evidence, SQL changes, and released
   rows immediately understandable.
7. **Application security engineer** — review every changed trust boundary, preserve fail-closed
   behavior, validate dependency risk, and add negative tests before changing sensitive paths.
8. **QA and adversarial test engineer** — reproduce bugs first, build regression tests, run the
   full matrix, and distinguish environment failures from product failures.
9. **DevOps/release engineer** — maintain exact locks, immutable CI actions, reproducible
   builds, deployable configs, health/readiness checks, post-deploy verification, SBOMs, and
   release evidence.
10. **Technical writer and demo producer** — keep README, judge guide, architecture, evidence,
    deployment instructions, and video script synchronized with the exact shipped revision.
11. **Independent reviewer** — challenge every “complete,” “live,” “real,” “secure,” and
    “production” claim against executable evidence before approving it.

## Non-negotiable quality rules

1. Evidence outranks assumptions and existing documentation.
2. Inspect before editing. Reproduce before fixing.
3. Preserve good code and proven tests; do not rewrite the kernel for visual novelty.
4. Core flows must not depend on canned success responses or silent replay fallback.
5. Unknown SQL, unresolved governance, stale context, failed authorization, failed verification,
   and missing runtime requirements fail closed with stable reason codes.
6. The agent proposes; deterministic authorities decide; only an effective ALLOW may release
   rows.
7. No raw result rows, credentials, tokens, personal values, or sensitive query literals enter
   logs, receipts, evidence artifacts, screenshots, or Git history.
8. A real-data claim requires source provenance, license/terms compatibility, an immutable or
   content-addressed input, schema validation, and a documented privacy classification. A real
   DataHub claim requires an actual DataHub service and official integration path, not mocked
   objects.
9. Keep fixture mode because it is safe and deterministic for judges. Label it accurately.
10. Maintain one-command local startup on supported platforms and a containerized judge path.
11. Every dependency manifest must agree with its committed lock. CI must run a lock-consistency
    check before consuming a frozen lock.
12. No vulnerability is “fixed” until its affected graph/path is identified, the minimum safe
    change is made, and the audit plus relevant tests pass.
13. Do not change expected security outcomes to make a failing gate green.
14. Do not merge or close pre-existing PRs silently. Reuse verified work and document overlap.
15. Finish each phase with executable acceptance evidence and a clean, reviewable diff.

## Definition of real and complete for ToxicJoin

“Real” has three distinct meanings and the UI/docs must not conflate them:

- **Real enforcement path:** the actual parser, context resolver, policy engine, rewriter,
  authorization, DuckDB execution, independent verifier, disclosure state, and receipt writer
  run end to end.
- **Real DataHub path:** a running DataHub OSS service plus the official MCP/SDK integration is
  used for governed reads, lineage, a bounded decision write, process separation, and fresh
  read-back.
- **Real organizational data:** an operator-supplied governed warehouse. This requires operator
  credentials, classifications, subject keys, legal authority, and deployment controls. It is
  not required for a public hackathon demo and must never be fabricated.

The public demo may use deterministic synthetic rows because they contain no real people. It is
complete only if the enforcement code is real, the data mode is visible, and the separate real
DataHub evidence is reproducible on the exact release candidate.

## Execution loop

For every work item, record:

```text
Observation -> Hypothesis -> Minimal test -> Result -> Interpretation -> Change -> Verification
```

If evidence disproves the hypothesis, do not continue the planned implementation. Update the
gap analysis and select the next highest-impact proven issue.

## Required phases

### Phase 0 — Repository and release truth

- Resolve repository, branch, open PRs, recent commits, CI state, hosted URLs, and release tags.
- Read architecture, README, judge guide, security roadmap, deployment configs, workflow gates,
  package manifests, locks, API composition, and UI entry points.
- Run the baseline locally: Python lint/tests, frontend typecheck/tests/build, benchmark,
  adversarial mutations, governance dependency, compositional ablation, supply-chain policy,
  dependency audits, focused SAST, and an HTTP black-box smoke test.
- Create a measured gap matrix with `proven`, `historical`, `staged`, `blocked`, and `unknown`
  states. Do not use unchecked TODO lists as current truth.

Exit criteria: baseline results and blockers are reproducible from a clean checkout.

### Phase 1 — Release blockers and supply-chain integrity

- Fix all unapproved high/critical dependency findings.
- Reconcile `pyproject.toml`, `uv.lock`, `package.json`, npm locks, and machine-readable toolchain
  authority.
- Add lock-consistency gates so `--frozen` cannot hide manifest drift.
- Re-evaluate every temporary risk exception before its expiry.
- Keep updates minimal unless a larger upgrade is justified by compatibility evidence.

Exit criteria: exact locked Python profiles and both npm graphs pass their policy validators;
static supply-chain and focused SAST gates pass.

### Phase 2 — Canonical end-to-end product path

- Black-box the live HTTP path for ALLOW, verified REWRITE, BLOCK, both closed bypasses,
  receipt lookup, agent remediation, health/readiness, and static UI delivery.
- Repair only proven product failures.
- Preserve exact authorization binding, post-execution quarantine, bounded output, cumulative
  disclosure state, ownership, and request-cost controls.
- Do not activate staged vNext or PostgreSQL code unless it is integrated, threat-modeled,
  migration-tested, and supported by exact-head evidence.

Exit criteria: deployment verifier and full regression suite pass with zero unsafe releases.

### Phase 3 — Real DataHub exact-revision evidence

- Start real DataHub OSS in CI using the pinned supported profile.
- Seed governed dataset metadata and deterministic safe demo rows.
- Prove entity, schema, edited governance, and physical column lineage reads through read-only
  authority.
- Prove a sanitized Decision write through isolated write authority.
- Close the writer, start a fresh read-only process, and prove persisted read-back.
- Bind evidence, package versions, image inventory, and report hashes to the exact candidate SHA.
- If live evidence fails, retain diagnostics and keep the claim blocked.

Exit criteria: the exact-head Live DataHub workflow is green and its artifact is retrievable.

### Phase 4 — Judge experience and professional interface

- Make the first viewport state the problem, DataHub dependency, and “agent proposes / ToxicJoin
  decides” boundary immediately.
- Ensure desktop, tablet, and mobile layouts are usable without clipping or horizontal overflow.
- Provide keyboard access, visible focus, semantic landmarks, correct labels, reduced-motion
  support, sufficient contrast, and meaningful loading/error/empty states.
- Never silently replace a failed API request with replay data. Replay must be explicit and
  permanently labeled.
- Preserve first-class attack presets that demonstrate the two closed bypasses.
- Show data mode, policy version, build identity, effective outcome, verification state,
  reason codes, DataHub evidence, safe SQL diff, released-row count, and receipt reference.

Exit criteria: frontend checks pass; automated desktop/mobile browser assertions pass; a judge
can reproduce the flagship flow in 90 seconds without reading source code.

### Phase 5 — Deployment and operations

- Provide a public synthetic fixture deployment that runs the real containerized pipeline.
- Keep live/secure DataHub deployment separate and credentialed.
- Validate persistent-volume requirements, single-node SQLite topology, proxy trust, secure
  headers, environment validation, health/readiness, startup failure behavior, and rollback.
- Run `scripts/verify_deployment.py` against every candidate public URL.
- Never call a static historical replay a live deployment.

Exit criteria: the public URL passes black-box verification and the repository documents the
exact build identity and data mode it serves.

### Phase 6 — Submission package

- Synchronize README, architecture, judge guide, security boundaries, evidence index, Devpost
  draft, screenshots, video script, and release notes with the exact candidate.
- Report current measured counts; never copy stale test numbers.
- Produce an under-three-minute demo plan that shows the problem, unsafe BLOCK, safe REWRITE,
  actual released result, DataHub evidence/write-back, and reproduction path.
- Keep submission, video upload, PR merge, and paid deployment as explicit owner actions when
  credentials or legal approval are required.

Exit criteria: every public claim maps to a current URL, test, artifact, or exact revision.

### Phase 7 — Independent release review

- Review the final diff as if hostile to overclaiming.
- Re-run all release gates from clean locks.
- Confirm no secrets, generated junk, stale assets, raw data, or unrelated edits are staged.
- Open a Draft PR with root causes, user impact, exact checks, known blockers, and follow-up
  owner actions.

Exit criteria: the PR is reviewable, CI is green or failures are accurately explained, and no
  unresolved release blocker is described as complete.

## Acceptance matrix

| Area | Required proof |
| --- | --- |
| Python | exact supported-version CI, lint, full tests, no new warnings accepted silently |
| Frontend | typecheck, unit/component tests, production build, browser smoke, responsive checks |
| Policy | 30-case benchmark, zero false allows, zero unsafe effective allows |
| Adversarial | all declared mutations blocked or safely handled; both closed bypasses reproduced |
| DataHub | real OSS + official MCP/SDK read/write/fresh-read-back on exact candidate |
| HTTP | health, readiness, ALLOW, REWRITE, BLOCK, receipts, agent loop, stable error behavior |
| Security | focused SAST, auth/resource tests, dependency policies, no unapproved high/critical |
| Supply chain | manifest/lock agreement, exact actions, exact toolchain, SBOMs, auditable exceptions |
| Deployment | hardened container, persistent-state truth, post-deploy black-box verification |
| Claims | every claim explicitly current, historical, replay, experimental, or operator-supplied |

## Reporting format

At each checkpoint, report only evidence-backed facts:

1. What was observed.
2. What changed and why.
3. Files changed.
4. Commands and results.
5. Claims that became valid.
6. Claims that remain blocked.
7. The next highest-impact action.

Final reports must distinguish:

- completed and independently verified;
- completed locally but awaiting CI/live environment;
- blocked by missing credentials, service access, legal approval, or owner action;
- intentionally out of scope.

## Stop conditions

Stop and request owner action rather than guessing when:

- the repository or target branch is ambiguous;
- a real DataHub endpoint or deployment requires credentials not already configured;
- publishing requires unavailable authenticated tooling;
- a destructive migration or data mutation lacks explicit target approval;
- the only path to “green” is weakening a security gate or changing expected outcomes;
- the requested claim cannot be demonstrated safely and independently.

The objective is the strongest truthful release, not the largest diff.
