# P4 Software Supply Chain Policy

## Reproducible inputs

- Python dependency resolution is committed in `uv.lock` and CI uses `uv sync --frozen`.
- Web dependency resolution is committed in `apps/web/package-lock.json` and CI/Docker use `npm ci`.
- Production Docker base images are pinned by immutable SHA-256 digest.
- Third-party GitHub Actions are pinned to full 40-character commit SHAs.

## Security gates

Every production candidate must pass:

- `pip-audit` on the locked DataHub and Agent Registry profiles;
- `npm audit` on the committed package lock;
- Bandit focused Python SAST;
- CodeQL `security-extended` for Python and JavaScript/TypeScript;
- GitHub Dependency Review for High/Critical introduced vulnerabilities;
- CycloneDX SBOM generation for both Python profiles and the web application.

## Vulnerability SLA

- Critical: remediate or explicitly block release within 24 hours.
- High: remediate or explicitly block release within 72 hours.
- Moderate: remediate within 14 days.
- Low: review during the monthly dependency cycle.

Risk exceptions are narrow, machine-validated, and expire automatically. An expired exception fails the supply-chain gate. The current DataHub `setuptools` exception is upstream-blocked and may not be generalized to another package, advisory, or runtime profile.

## Update procedure

1. Dependabot opens dependency, Actions, npm, and Docker updates.
2. Regenerate `uv.lock` / `package-lock.json` as applicable.
3. Run dependency audits, SAST, CodeQL, existing ToxicJoin security evidence gates, Live DataHub evidence, and the frozen external replay.
4. Accept a new digest or Action SHA only with exact-head evidence.
5. Never merge a lock update that introduces an unapproved advisory.
