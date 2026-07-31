# ToxicJoin Submission Freeze

## Status

**Hard feature freeze.**

The engineering roadmap is complete through **Phase 16 — Shared Disclosure State Topology Verification**. From this point until the DataHub hackathon submission, repository changes are limited to documentation, evidence synchronization, demo/video packaging, submission metadata, or a narrowly proven release-blocking bug.

No new feature is allowed merely because it would be interesting.

## Last engineering baseline

Phase 16 landed on `main` as:

```text
5d297778a9a9caaae0732e7dfb7401a5f380f089
```

Exact pre-merge candidate head:

```text
826881acdb1256a8dd1b1f97fba6dae00369dd0c
```

PR #117: `security: enforce truthful disclosure state topology`.

The exact candidate head completed successfully:

- CI;
- Python 3.11;
- Python 3.12;
- balanced benchmark evidence;
- PPMC hard-gate evidence;
- hardened production container and flagship flow;
- Ground Truth Baseline;
- CodeQL;
- Supply Chain Security;
- Governance Dependency Evidence;
- Adversarial Mutation Evidence;
- Compositional Ablation Evidence;
- Disclosure Sequence Evidence, including the Phase 16 topology regression.

The generated release workflow remains the revision-level release authority. This document records the last engineering baseline; later documentation-only commits do not imply new runtime behavior.

Final submission-documentation `main` audited before Phase 2:

```text
1aead67c339c218f5858a9eb9de05868cdc3a0e5
```

That later SHA does not retroactively change the environment or revision identity of retained runtime or Live DataHub evidence.

## Product claim

ToxicJoin is a DataHub-grounded compositional privacy firewall for AI data agents.

It analyzes proposed analytical SQL before execution, resolves governed context and physical lineage, and returns one deterministic decision:

```text
ALLOW | REWRITE | BLOCK
```

The model proposes work; deterministic security authorities decide whether the effective query may execute.

The normative product architecture and claim hierarchy are defined in [`../architecture.md`](../architecture.md).

## DataHub claim

DataHub is part of the governed decision path, not decorative metadata.

The retained real integration evidence demonstrates:

```text
read-only DataHub MCP
  -> governed entity / schema / lineage context
  -> deterministic policy/action
  -> isolated writer
  -> sanitized DataHub Decision write-back
  -> writer closed
  -> fresh read-only MCP
  -> independent Decision read-back
```

The current source also contains the reusable Compositional Risk Review Agent Skill under `skills/compositional-risk-review/`.

The Live DataHub evidence is retained as exact evidence for the revision on which it was produced. It was **not** rerun on final `main` `1aead67c339c218f5858a9eb9de05868cdc3a0e5`. Later unrelated hardening and unchanged-source applicability arguments are not described as an exact-final-SHA live rerun.

## Stable runtime vs staged vNext

The canonical HTTP product path remains the supported judge-executable runtime documented in `docs/judge-testing.md`.

`docs/vnext/**` records staged security architecture developed during the hardening roadmap. It includes proposal-only Governed Agent boundaries, authenticated authority handoffs, PPMC, proof provenance, proof-bound authorization, warehouse-snapshot revalidation, cryptographic domain separation, and explicit disclosure-state topology verification.

These components are real code with exact-revision tests. They do **not** imply that the canonical HTTP runtime has fully migrated to the complete vNext proof chain.

This separation is intentional and is part of the release claim boundary.

## Measured regression contract

The supported deterministic benchmark remains:

- 30 cases total;
- 10 ALLOW;
- 10 REWRITE;
- 10 BLOCK;
- 30/30 expected initial decisions;
- 30/30 expected effective outcomes;
- 30/30 expected reason codes;
- zero false allows;
- zero unsafe effective allows;
- six rewrites remediated to verified ALLOW;
- four rewrite paths fail closed;
- 16 verified executions.

This is a bounded regression corpus for the declared SQL/policy profile, not a universal privacy-detection accuracy claim.

The retained adversarial mutation gate covers 144 valid mutations across known-unsafe composition families with zero unsafe executions on its recorded exact revision.

## Phase 16 deployment truth

The public SQLite cumulative-disclosure authority is `SINGLE_NODE` only.

Phase 16 proved that two replicas using separate local SQLite files can partition cumulative privacy history. ToxicJoin rejects declared multi-replica use of that local state rather than pretending it is globally authoritative.

Not claimed on current `main`:

- PostgreSQL/shared-authoritative disclosure state;
- automatic replica discovery;
- distributed transactions;
- Redis-backed global rate limiting;
- cross-node replay state;
- horizontally shared receipt storage;
- shared key custody.

Draft PR #118 contains an off-main PostgreSQL shared-authoritative implementation and evidence workflow. It is not present on current `main`, not wired into the canonical HTTP runtime, and not a production-supported capability.

## Historical replay boundary

The repository preserves the earlier release evidence, production-image black-box report, and hosted deterministic replay provenance.

Those artifacts remain valuable evidence, but their historical SHAs must not be presented as current repository identity.

The hosted Vercel experience is explicitly a **Historical Deterministic Replay** and is not represented as a build of current `main` or as a live DataHub mutation environment. Its retained policy identity is `0.1.0`; current product policy is `0.2.0`.

The current repository replay source stores valid SQL clause order and no longer applies an in-memory corrective transform. This source correction does not redeploy or alter the historical public assets.

## Submission requirements audit

For **Build with DataHub: The Agent Hackathon**:

### Satisfied in repository

- public GitHub repository;
- Apache License 2.0 file;
- executable setup instructions;
- judge testing guide;
- sample outputs under `examples/`;
- public deterministic replay URL;
- real DataHub OSS + official MCP evidence;
- DataHub Skill;
- open-source DataHub contribution recorded honestly as open/pending review.

### Submission selections

Primary challenge category:

```text
Agents That Do Real Work
```

DataHub technologies actually used:

```text
DataHub OSS / Core Platform
DataHub MCP Server
DataHub Skills
```

Do not select technologies merely because they are adjacent to the project.

### Remaining blocking deliverable

A public YouTube or Vimeo demonstration video **under 3 minutes** is required by the hackathon and is not yet attached to the ToxicJoin Devpost project.

The project must not be submitted until the final video URL is present and the Devpost text has been synchronized with this freeze boundary.

## Devpost synchronization rules

Before submission, the Devpost write-up must ensure that:

- the first screen explains the problem and DataHub dependency immediately;
- the judge quick path is near the top;
- historical SHAs are not presented as current release identity;
- Phase 16 single-node topology truth is explicit;
- vNext components are described as staged security architecture where appropriate;
- benchmark claims retain their bounded-regression qualifier;
- DataHub write-back plus fresh read-back is prominent;
- the open DataHub Skills contribution is described as open/pending review, not merged;
- the public replay is labeled historical and policy `0.1.0`;
- PR #118 is described only as off-main draft work when mentioned;
- the video URL is public and under three minutes.

## Freeze rule

After this point:

```text
Code feature change -> NO
Unproven hardening idea -> NO
Architecture expansion -> NO
Release-blocking proven bug -> minimal TDD fix only
Docs/evidence truth correction -> YES
Video/demo packaging -> YES
Devpost synchronization -> YES
Final submission checks -> YES
```

The optimization target is **judge comprehension + reproducibility + evidence integrity**, not additional feature count.
