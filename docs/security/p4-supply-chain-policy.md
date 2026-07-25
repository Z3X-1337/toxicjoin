# P4 Software Supply Chain Policy

## Reproducible inputs

- Python dependency resolution is committed in `uv.lock` and CI uses `uv sync --frozen`.
- Web dependency resolution is committed in `apps/web/package-lock.json` and CI/Docker use `npm ci`.
- Hosted Replay browser tooling is committed in the root `package-lock.json` and verification uses `npm ci`.
- Production Docker base images are pinned by immutable SHA-256 digest.
- Third-party GitHub Actions are pinned to full 40-character commit SHAs.

## Security gates

Every production candidate must pass:

- `pip-audit` on the locked DataHub and Agent Registry profiles;
- `npm audit` on both committed npm locks;
- Bandit focused Python SAST;
- CodeQL `security-extended` for Python and JavaScript/TypeScript;
- Dependency Review protection for introduced dependency risk;
- CycloneDX SBOM generation for both Python profiles, the web application, and Hosted Replay tooling.

### Dependency Review availability

The preferred path is GitHub's official Dependency Review API and `actions/dependency-review-action`, with High/Critical introduced vulnerabilities rejected.

The repository currently receives HTTP `403 Forbidden` from the Dependency Review REST endpoint before any dependency analysis. The gate therefore probes the API on every pull request:

- HTTP `200`: run the official pinned Dependency Review action.
- HTTP `403`: run the exact-lock local fallback against the pull-request head. The fallback records the dependency-manifest diff and re-runs `pip-audit` for both Python profiles plus `npm audit` for both npm locks. Any unapproved finding fails the gate.
- Any other HTTP status: fail closed.

The `403` path is a platform-availability fallback, not a vulnerability exception. If GitHub Dependency Graph becomes available, the workflow automatically returns to the official action without a code change.

## Vulnerability SLA

- Critical: remediate or explicitly block release within 24 hours.
- High: remediate or explicitly block release within 72 hours.
- Moderate: remediate within 14 days.
- Low: review during the monthly dependency cycle.

Risk exceptions are narrow, machine-validated, and expire automatically. An expired exception fails the supply-chain gate. The current DataHub `setuptools` exception is upstream-blocked and may not be generalized to another package, advisory, or runtime profile.

## Update procedure

1. Dependabot opens dependency, Actions, npm, and Docker updates.
2. Regenerate `uv.lock` / npm lockfiles as applicable.
3. Run dependency audits, SAST, CodeQL, existing ToxicJoin security evidence gates, Live DataHub evidence, and the frozen external replay.
4. Accept a new digest or Action SHA only with exact-head evidence.
5. Never merge a lock update that introduces an unapproved advisory.
