# ToxicJoin — Owner Review Before Devpost Submission

> **Submission lock:** Do not submit, publish a Devpost project, or accept final terms until the project owner has reviewed every checked item below and explicitly approved submission.

## 1. Product identity

- [ ] Project name is exactly `ToxicJoin`.
- [ ] Tagline accurately describes a compositional privacy firewall.
- [ ] All public material is in English where Devpost requires English.
- [ ] No Rayluno name, code, screenshots, infrastructure, branding, or submission text appears anywhere.
- [ ] Public repository is `https://github.com/Z3X-1337/toxicjoin`.
- [ ] Apache 2.0 license is visible in the repository.

## 2. Technical claims

- [ ] BLOCK is shown without database execution.
- [ ] REWRITE is shown as initial `REWRITE` followed by reparse, reevaluation, final `ALLOW`, execution, and verification.
- [ ] ALLOW is shown for a low-risk aggregate.
- [ ] The LLM is never described as the enforcement authority.
- [ ] Unsupported or ambiguous SQL is described as failing closed.
- [ ] No claim of universal privacy detection appears.
- [ ] No claim of differential privacy, general SQL repair, or production readiness appears.
- [ ] Benchmark language says “declared corpus” or equivalent scope limitation.

## 3. Stable DataHub evidence

- [ ] Stable live DataHub workflow is green on the exact merged commit.
- [ ] Seed report proves five datasets.
- [ ] Seed report proves 19 governed fields.
- [ ] Seed report proves four lineage writes.
- [ ] MCP tool discovery and contract validation succeeded.
- [ ] Entity, schema-field, and lineage reads succeeded.
- [ ] `save_document` wrote a DataHub `Decision`.
- [ ] The first MCP process was closed.
- [ ] A fresh MCP process exposed `grep_documents`.
- [ ] The fresh process found the unique marker inside persisted document content.
- [ ] Retained evidence contains no token, password, endpoint, raw warehouse row, or secret.
- [ ] README links to the committed sanitized evidence.

## 4. DataHub Skill and Agent Registry preview

- [ ] `skills/compositional-risk-review/SKILL.md` is public and Apache-2.0 covered.
- [ ] The Skill source points to the exact git repository and path.
- [ ] Five MCP tools are registered as DataHub API entities.
- [ ] The Agent Skill requires exactly those five tool URNs.
- [ ] The ToxicJoin AI Agent adopts the Skill and the five tools.
- [ ] The Agent consumes all five governed ToxicJoin datasets through DataHub lineage.
- [ ] A fresh graph client independently read the Agent, Skill, tools, and dataset dependencies back.
- [ ] Agent Registry evidence is sanitized and content-hashed.
- [ ] The preview is explicitly separated from the stable `acryl-datahub==1.6.0.15` integration.
- [ ] No public text claims that the Skill was merged into the upstream DataHub repository.

## 5. Public experience

- [ ] Hosted replay returns HTTP 200 in a clean browser.
- [ ] The retained provenance matches the verified CI-built interface artifact.
- [ ] Desktop layout has no unexpected console error, page error, failed static asset, or horizontal overflow.
- [ ] Mobile layout has no unexpected console error, page error, failed static asset, or horizontal overflow.
- [ ] Replay disclosure is visible before interaction.
- [ ] Hosted replay never claims live DataHub or DuckDB execution.
- [ ] Docker/FastAPI remains documented as the executable product path.

## 6. Screenshots and thumbnail

- [ ] Thumbnail uses the real ToxicJoin interface.
- [ ] Thumbnail is legible at Devpost card size.
- [ ] At least one screenshot shows REWRITE → ALLOW.
- [ ] At least one screenshot shows the Evidence graph.
- [ ] At least one screenshot shows DataHub lineage or the Decision document.
- [ ] At least one review asset shows the Agent Skill / Agent Registry evidence with its preview label.
- [ ] No screenshot exposes a credential, local filesystem path, or private account data.

## 7. Demo video

- [ ] Final encoded duration is under 3:00.
- [ ] Video resolution is 1920×1080 or another clear 16:9 resolution.
- [ ] Narration and captions are understandable without background music.
- [ ] The video shows only real ToxicJoin UI, terminal, DataHub, CI, repository, and evidence.
- [ ] BLOCK demonstrates that execution did not occur.
- [ ] REWRITE shows the added distinct-subject threshold.
- [ ] Verification shows all three groups contain 40 subjects.
- [ ] Receipt section states that raw result rows are not persisted.
- [ ] Stable DataHub section shows the real live proof, not fixture or replay content presented as live.
- [ ] Agent Skill / Agent Registry section is explicitly labeled preview/development channel.
- [ ] Benchmark values exactly match committed evidence.
- [ ] Video is publicly accessible at the final submitted URL.

## 8. Devpost fields

- [ ] Category: `Agents That Do Real Work`.
- [ ] Technologies include `DataHub OSS / Core Platform`, `DataHub MCP Server`, and `DataHub Skills`.
- [ ] Agent Registry is mentioned only in the description as a preview/development-channel proof.
- [ ] Country: `Jordan`.
- [ ] Newly created during submission period: `Yes`.
- [ ] Public repository URL is correct.
- [ ] Project/demo URL is `https://toxicjoin-replay.vercel.app/` and publicly accessible.
- [ ] Examples URL is correct.
- [ ] Video URL is correct, public, and under three minutes.
- [ ] Feedback Prize answer has been reviewed.
- [ ] Contribution field links the public `Compositional Risk Review` DataHub Agent Skill.
- [ ] Contribution field explicitly says the Skill is not claimed as upstream-merged.
- [ ] Pre-existing-code disclosure explicitly states that no Rayluno material was reused.
- [ ] Every `[PENDING_*]` marker has been removed from the final text.

## 9. Final repository state

- [ ] `main` CI is green on Python 3.11 and 3.12.
- [ ] Web typecheck, Vitest, and Vite build are green.
- [ ] Production Docker smoke test is green.
- [ ] Stable live DataHub workflow is green.
- [ ] Agent Registry preview workflow is green.
- [ ] Hosted Replay verification workflow is green.
- [ ] No temporary patch Workflow remains.
- [ ] No generated secret or `.toxicjoin/` runtime file is committed accidentally.
- [ ] README setup commands work from a fresh checkout.
- [ ] All links in README and submission text were tested.
- [ ] Open PRs are intentional and explained.

## 10. Owner approval

- [ ] I reviewed the public repository.
- [ ] I reviewed the hosted replay.
- [ ] I reviewed the DataHub Skill / Agent Registry evidence.
- [ ] I reviewed the screenshots and thumbnail.
- [ ] I watched the final video from start to finish.
- [ ] I reviewed the complete Devpost text and every custom field.
- [ ] I approve submitting this exact version.

**Owner approval:** ____________________

**Date:** ____________________

**Exact main commit reviewed:** ____________________

**Exact video URL reviewed:** ____________________

**Exact hosted replay URL reviewed:** ____________________
