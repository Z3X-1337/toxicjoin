# Phase 9 — Immutable Release Identity acceptance

Phase 9 is accepted only when all of the following are proven against one exact `main` commit:

1. the generated Release Manifest is in `release` mode and all required gates are verified;
2. project version `0.2.0`, tag `v0.2.0`, release name, notes, and assets agree;
3. the annotated tag resolves to the exact release commit;
4. the GitHub Release is published, not a draft, and not a prerelease;
5. final evidence index, four CycloneDX SBOMs, reproducibility instructions, Release Manifest, deterministic evidence bundle, and `SHA256SUMS` are attached;
6. every downloaded release asset passes SHA-256 verification;
7. release notes preserve `SINGLE_NODE`, PostgreSQL-not-canonical, synthetic public fixture, Render temporary-state, and no-Devpost-submission boundaries;
8. the release workflow is idempotent and refuses a mismatched pre-existing tag or Release;
9. PR #118 remains isolated;
10. no Phase 10 ruleset work, Phase 11 cleanup, Phase 12 PostgreSQL disposition, hosting-provider, or Devpost mutation occurs.
