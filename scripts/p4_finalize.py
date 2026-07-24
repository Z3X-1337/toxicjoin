from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
TEMP_WORKFLOWS = {
    WORKFLOWS / "p4-supply-chain-bootstrap.yml",
    WORKFLOWS / "p4-materialize-locks.yml",
    WORKFLOWS / "p4-finalize-hardening.yml",
}
PROTECTED_INPUTS = (
    "pyproject.toml",
    "apps/web/package.json",
    "Dockerfile",
    "docs/security/p4-dependency-risk-exceptions.json",
)
UV_VERSION = "0.8.4"


def run(*args: str, cwd: Path = ROOT, capture: bool = False) -> str:
    result = subprocess.run(
        list(args),
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
    )
    return result.stdout.strip() if capture else ""


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def validate_materialized_evidence(start_sha: str) -> tuple[dict, dict]:
    summary = load_json(ROOT / "p4-bootstrap" / "summary.json")
    exceptions = load_json(ROOT / "docs/security/p4-dependency-risk-exceptions.json")
    source_sha = summary["source_head_sha"]

    run("git", "merge-base", "--is-ancestor", source_sha, start_sha)
    diff = run("git", "diff", "--name-only", f"{source_sha}..{start_sha}", "--", *PROTECTED_INPUTS, capture=True)
    if diff:
        raise SystemExit(f"Materialized supply-chain inputs changed after audit: {diff}")

    npm = summary["npm"]
    if npm["exit_code"] != 0 or npm["finding_count"] != 0:
        raise SystemExit(f"npm audit is not clean: {json.dumps(npm, sort_keys=True)}")

    allowed = exceptions.get("exceptions", [])
    if len(allowed) != 1:
        raise SystemExit("P4 requires exactly one explicit temporary dependency exception")
    exception = allowed[0]
    if exception.get("status") != "temporary_upstream_blocked":
        raise SystemExit("Dependency exception is not in temporary_upstream_blocked state")
    if date.today() > date.fromisoformat(exception["expires_on"]):
        raise SystemExit("Dependency exception has expired")

    valid_ids = {exception["id"], *exception.get("aliases", [])}
    for profile_key, profile_name in (
        ("python_datahub", "datahub"),
        ("python_agent_registry", "agent-registry"),
    ):
        item = summary[profile_key]
        findings = item.get("findings", [])
        if item.get("exit_code") != 1 or len(findings) != 1:
            raise SystemExit(f"Unexpected Python audit result for {profile_name}: {item}")
        finding = findings[0]
        if (
            finding.get("package") != exception["package"]
            or finding.get("id") not in valid_ids
            or profile_name not in exception["scope"]
            or exception["fixed_version"] not in finding.get("fix_versions", [])
        ):
            raise SystemExit(f"Unapproved Python finding for {profile_name}: {finding}")

    docker = dict(line.split("=", 1) for line in summary["docker_base_images"])
    expected = {"node:22.16.0-alpine", "python:3.12-slim"}
    if set(docker) != expected:
        raise SystemExit(f"Unexpected Docker base set: {sorted(docker)}")
    for logical, resolved in docker.items():
        if not re.fullmatch(r"(?:node|python)@sha256:[0-9a-f]{64}", resolved):
            raise SystemExit(f"Invalid Docker digest for {logical}: {resolved}")

    return summary, exceptions


def validator_script() -> str:
    return r'''from __future__ import annotations

import argparse
import json
import re
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXCEPTIONS = ROOT / "docs/security/p4-dependency-risk-exceptions.json"


def load(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def active_exceptions(profile: str) -> list[dict]:
    payload = load(EXCEPTIONS)
    active = []
    today = date.today()
    for item in payload.get("exceptions", []):
        if item.get("status") != "temporary_upstream_blocked":
            continue
        if profile not in item.get("scope", []):
            continue
        expires = date.fromisoformat(item["expires_on"])
        if today > expires:
            raise SystemExit(f"Dependency risk exception expired: {item['id']} on {expires}")
        active.append(item)
    return active


def validate_python(profile: str, audit_json: str) -> None:
    payload = load(audit_json)
    findings = []
    for dependency in payload.get("dependencies", []):
        for vuln in dependency.get("vulns", []):
            findings.append(
                {
                    "package": dependency.get("name"),
                    "version": dependency.get("version"),
                    "id": vuln.get("id"),
                    "fix_versions": vuln.get("fix_versions", []),
                }
            )

    allowed = active_exceptions(profile)
    rejected = []
    accepted = []
    for finding in findings:
        match = None
        for exception in allowed:
            ids = {exception["id"], *exception.get("aliases", [])}
            if (
                finding["package"] == exception["package"]
                and finding["id"] in ids
                and exception["fixed_version"] in finding["fix_versions"]
            ):
                match = exception
                break
        if match is None:
            rejected.append(finding)
        else:
            accepted.append({"finding": finding, "exception": match["id"]})

    if rejected:
        raise SystemExit("Unapproved Python dependency findings: " + json.dumps(rejected, sort_keys=True))
    print(json.dumps({"profile": profile, "accepted_exceptions": accepted}, sort_keys=True))


def validate_npm(audit_json: str) -> None:
    payload = load(audit_json)
    vulnerabilities = payload.get("vulnerabilities", {})
    total = payload.get("metadata", {}).get("vulnerabilities", {}).get("total", len(vulnerabilities))
    if vulnerabilities or total:
        raise SystemExit("npm audit findings are not allowed: " + json.dumps(vulnerabilities, sort_keys=True))
    print("npm audit clean")


def validate_static() -> None:
    lock = ROOT / "uv.lock"
    npm_lock = ROOT / "apps/web/package-lock.json"
    if not lock.is_file() or not npm_lock.is_file():
        raise SystemExit("Required lockfile missing")

    docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    from_lines = [line for line in docker.splitlines() if line.startswith("FROM ")]
    if len(from_lines) < 3 or any("@sha256:" not in line for line in from_lines):
        raise SystemExit(f"Docker bases must be digest pinned: {from_lines}")
    if "npm ci --no-audit --no-fund" not in docker or "uv sync --frozen" not in docker:
        raise SystemExit("Dockerfile does not consume committed locks")

    floating = []
    uses_re = re.compile(r"uses:\s*([^\s#]+)@([^\s#]+)")
    for path in sorted((ROOT / ".github/workflows").glob("*.y*ml")):
        text = path.read_text(encoding="utf-8")
        for match in uses_re.finditer(text):
            target, ref = match.groups()
            if target.startswith("./"):
                continue
            if not re.fullmatch(r"[0-9a-f]{40}", ref):
                floating.append(f"{path.relative_to(ROOT)}:{target}@{ref}")
        if "npm install" in text:
            raise SystemExit(f"Floating npm install remains in workflow: {path.relative_to(ROOT)}")
        if re.search(r"pip\s+install\s+-e\s+['\"]?\.\[", text):
            raise SystemExit(f"Editable range install remains in workflow: {path.relative_to(ROOT)}")
    if floating:
        raise SystemExit("Floating GitHub Actions refs: " + json.dumps(floating))

    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    if "uv sync --frozen --extra dev" not in ci or "npm ci --no-audit --no-fund" not in ci:
        raise SystemExit("CI does not consume committed dependency locks")
    print("Static supply-chain invariants verified")


def main() -> None:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    py = sub.add_parser("python")
    py.add_argument("--profile", required=True)
    py.add_argument("--audit-json", required=True)
    npm = sub.add_parser("npm")
    npm.add_argument("--audit-json", required=True)
    sub.add_parser("static")
    args = parser.parse_args()
    if args.command == "python":
        validate_python(args.profile, args.audit_json)
    elif args.command == "npm":
        validate_npm(args.audit_json)
    else:
        validate_static()


if __name__ == "__main__":
    main()
'''


def supply_chain_workflow() -> str:
    return '''name: Supply Chain Security

on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  static-policy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Verify static supply-chain invariants
        run: python3 scripts/validate_dependency_audit.py static

  python-audit:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        profile: [datahub, agent-registry]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip
      - name: Sync exact locked profile
        shell: bash
        run: |
          set -euo pipefail
          python -m pip install --disable-pip-version-check 'uv==0.8.4'
          uv sync --frozen --no-install-project --extra dev --extra security --extra "${{ matrix.profile }}"
      - name: Audit exact locked profile
        shell: bash
        run: |
          set -euo pipefail
          PROFILE="${{ matrix.profile }}"
          uv export --frozen --no-emit-project --no-hashes \
            --extra dev --extra security --extra "$PROFILE" \
            --output-file "requirements-$PROFILE.txt"
          set +e
          .venv/bin/pip-audit -r "requirements-$PROFILE.txt" --format json --output "pip-audit-$PROFILE.json"
          AUDIT_RC=$?
          set -e
          echo "pip-audit exit code: $AUDIT_RC"
          .venv/bin/python scripts/validate_dependency_audit.py python \
            --profile "$PROFILE" --audit-json "pip-audit-$PROFILE.json"
      - name: Generate reproducible Python CycloneDX SBOM
        shell: bash
        run: |
          set -euo pipefail
          PROFILE="${{ matrix.profile }}"
          .venv/bin/cyclonedx-py requirements "requirements-$PROFILE.txt" \
            --output-reproducible --output-format JSON \
            --output-file "sbom-python-$PROFILE.cdx.json"
      - uses: actions/upload-artifact@v4
        with:
          name: python-supply-chain-${{ matrix.profile }}
          path: |
            pip-audit-${{ matrix.profile }}.json
            sbom-python-${{ matrix.profile }}.cdx.json
          if-no-files-found: error
          retention-days: 30

  web-audit:
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: apps/web
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: "22.16.0"
          cache: npm
          cache-dependency-path: apps/web/package-lock.json
      - name: Install exact lock
        run: npm ci --no-audit --no-fund
      - name: Audit npm dependency graph
        shell: bash
        run: |
          set -euo pipefail
          set +e
          npm audit --package-lock-only --json > npm-audit.json
          AUDIT_RC=$?
          set -e
          echo "npm audit exit code: $AUDIT_RC"
          python3 ../../scripts/validate_dependency_audit.py npm --audit-json npm-audit.json
      - name: Verify web build and tests
        run: npm run check
      - name: Generate Node CycloneDX SBOM
        run: npm run sbom
      - uses: actions/upload-artifact@v4
        with:
          name: web-supply-chain
          path: |
            apps/web/npm-audit.json
            apps/web/sbom.cdx.json
          if-no-files-found: error
          retention-days: 30

  bandit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip
      - name: Focused Python SAST
        shell: bash
        run: |
          set -euo pipefail
          python -m pip install --disable-pip-version-check 'uv==0.8.4'
          uv sync --frozen --no-install-project --extra security
          .venv/bin/bandit -r src/toxicjoin -ll -ii -q

  dependency-review:
    if: github.event_name == 'pull_request'
    runs-on: ubuntu-latest
    permissions:
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: actions/dependency-review-action@v4
        with:
          fail-on-severity: high
          allow-ghsas: GHSA-h35f-9h28-mq5c
'''


def codeql_workflow() -> str:
    return '''name: CodeQL

on:
  pull_request:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  analyze:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        language: [python, javascript-typescript]
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v4
        with:
          languages: ${{ matrix.language }}
          queries: security-extended
      - uses: github/codeql-action/analyze@v4
'''


def dependabot_config() -> str:
    return '''version: 2
updates:
  - package-ecosystem: pip
    directory: "/"
    schedule:
      interval: weekly
    open-pull-requests-limit: 5
  - package-ecosystem: npm
    directory: "/apps/web"
    schedule:
      interval: weekly
    open-pull-requests-limit: 5
  - package-ecosystem: github-actions
    directory: "/"
    schedule:
      interval: weekly
    open-pull-requests-limit: 5
  - package-ecosystem: docker
    directory: "/"
    schedule:
      interval: weekly
    open-pull-requests-limit: 5
'''


def policy_document() -> str:
    return '''# P4 Software Supply Chain Policy

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
'''


def dockerfile(summary: dict) -> str:
    digests = dict(line.split("=", 1) for line in summary["docker_base_images"])
    node = digests["node:22.16.0-alpine"]
    python = digests["python:3.12-slim"]
    return f'''# syntax=docker/dockerfile:1.7

FROM {node} AS web-builder
WORKDIR /build/apps/web
COPY apps/web/package.json apps/web/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY apps/web/ ./
RUN npm run build

FROM {python} AS python-deps
WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN python -m pip install --no-cache-dir 'uv=={UV_VERSION}' \\
    && uv sync --frozen --no-dev --no-install-project

FROM {python} AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \\
    PYTHONUNBUFFERED=1 \\
    PIP_DISABLE_PIP_VERSION_CHECK=1 \\
    PATH=/app/.venv/bin:$PATH \\
    PYTHONPATH=/app/src \\
    TOXICJOIN_HOST=0.0.0.0 \\
    TOXICJOIN_PORT=8000 \\
    TOXICJOIN_RUNTIME_DIR=/var/lib/toxicjoin \\
    TOXICJOIN_WEB_DIST=/app/apps/web/dist
WORKDIR /app
RUN useradd \\
      --uid 10001 \\
      --create-home \\
      --home-dir /home/toxicjoin \\
      --shell /usr/sbin/nologin \\
      toxicjoin \\
    && mkdir -p /var/lib/toxicjoin /app/apps/web/dist \\
    && chown -R toxicjoin:toxicjoin /var/lib/toxicjoin /app
COPY --from=python-deps /app/.venv /app/.venv
COPY src/ ./src/
COPY config/ ./config/
COPY demo/ ./demo/
COPY --from=web-builder /build/apps/web/dist/ /app/apps/web/dist/
RUN chown -R toxicjoin:toxicjoin /app/apps/web/dist
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=20s --timeout=4s --start-period=25s --retries=3 \\
  CMD ["python", "-c", "import json, urllib.request; data=json.load(urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)); assert data['status'] == 'ok'"]
CMD ["python", "-c", "from toxicjoin.cli import run_api; run_api()"]
'''


def rewrite_ci() -> None:
    path = WORKFLOWS / "ci.yml"
    text = path.read_text(encoding="utf-8")
    old = "run: python -m pip install --upgrade pip && python -m pip install -e '.[dev]'"
    new = """run: |\n          python -m pip install --disable-pip-version-check 'uv==0.8.4'\n          uv sync --frozen --extra dev"""
    if old not in text:
        raise SystemExit("CI Python install pattern changed; refusing blind rewrite")
    text = text.replace(old, new)
    text = text.replace("run: ruff check src tests", "run: uv run --frozen ruff check src tests")
    text = text.replace("pytest -q 2>&1 | tee pytest-${{ matrix.python-version }}.log", "uv run --frozen pytest -q 2>&1 | tee pytest-${{ matrix.python-version }}.log")
    text = text.replace("run: toxicjoin-benchmark --output-dir artifacts/benchmark", "run: uv run --frozen toxicjoin-benchmark --output-dir artifacts/benchmark")
    text = text.replace("run: npm install --no-audit --no-fund", "run: npm ci --no-audit --no-fund")
    path.write_text(text, encoding="utf-8")


def rewrite_other_locked_installs() -> None:
    editable = re.compile(r"^(?P<i>\s*)(?:python(?:3)?\s+-m\s+pip|pip)\s+install\s+-e\s+['\"]?\.\[(?P<e>[^\]]+)\]['\"]?\s*$")
    plain = re.compile(r"^(?P<i>\s*)(?:python(?:3)?\s+-m\s+pip|pip)\s+install\s+-e\s+\.?\s*$")
    for path in sorted(WORKFLOWS.glob("*.y*ml")):
        if path in TEMP_WORKFLOWS or path.name in {"supply-chain.yml", "codeql.yml", "ci.yml"}:
            continue
        output = []
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            match = editable.match(line)
            if match:
                extras = " ".join(f"--extra {item.strip()}" for item in match.group("e").split(",") if item.strip())
                indent = match.group("i")
                output.extend([
                    f"{indent}python -m pip install --disable-pip-version-check 'uv=={UV_VERSION}'",
                    f"{indent}uv sync --frozen {extras}".rstrip(),
                    f"{indent}echo \"$PWD/.venv/bin\" >> \"$GITHUB_PATH\"",
                ])
                continue
            if plain.match(line):
                indent = plain.match(line).group("i")
                output.extend([
                    f"{indent}python -m pip install --disable-pip-version-check 'uv=={UV_VERSION}'",
                    f"{indent}uv sync --frozen",
                    f"{indent}echo \"$PWD/.venv/bin\" >> \"$GITHUB_PATH\"",
                ])
                continue
            if stripped in {
                "python -m pip install --upgrade pip wheel setuptools uv",
                "python -m pip install --upgrade pip wheel setuptools",
            }:
                output.append(line[: len(line) - len(line.lstrip())] + f"python -m pip install --disable-pip-version-check 'uv=={UV_VERSION}'")
                continue
            output.append(line.replace("npm install --no-audit --no-fund", "npm ci --no-audit --no-fund"))
        path.write_text("\n".join(output) + "\n", encoding="utf-8")


def resolve_action(repo: str, ref: str) -> str:
    url = f"https://github.com/{repo}.git"
    patterns = [f"refs/tags/{ref}^{{}}", f"refs/tags/{ref}", f"refs/heads/{ref}"]
    output = run("git", "ls-remote", url, *patterns, capture=True)
    refs = {}
    for line in output.splitlines():
        sha, name = line.split("\t", 1)
        refs[name] = sha
    for name in patterns:
        sha = refs.get(name)
        if sha and re.fullmatch(r"[0-9a-f]{40}", sha):
            return sha
    raise SystemExit(f"Cannot resolve immutable Action ref {repo}@{ref}")


def pin_all_actions() -> dict:
    uses = re.compile(r"(?P<prefix>uses:\s*)(?P<repo>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)(?P<sub>/[^\s@#]+)?@(?P<ref>[^\s#]+)")
    evidence = {}
    for path in sorted(WORKFLOWS.glob("*.y*ml")):
        text = path.read_text(encoding="utf-8")
        def replace(match: re.Match[str]) -> str:
            ref = match.group("ref")
            repo = match.group("repo")
            sub = match.group("sub") or ""
            if re.fullmatch(r"[0-9a-f]{40}", ref):
                sha = ref
            else:
                sha = resolve_action(repo, ref)
            evidence[f"{repo}{sub}@{ref}"] = sha
            return f"{match.group('prefix')}{repo}{sub}@{sha}"
        path.write_text(uses.sub(replace, text), encoding="utf-8")
    return dict(sorted(evidence.items()))


def apply(start_sha: str) -> None:
    summary, exceptions = validate_materialized_evidence(start_sha)

    scripts = ROOT / "scripts"
    scripts.mkdir(exist_ok=True)
    (scripts / "validate_dependency_audit.py").write_text(validator_script(), encoding="utf-8")
    (WORKFLOWS / "supply-chain.yml").write_text(supply_chain_workflow(), encoding="utf-8")
    (WORKFLOWS / "codeql.yml").write_text(codeql_workflow(), encoding="utf-8")
    (ROOT / ".github/dependabot.yml").write_text(dependabot_config(), encoding="utf-8")
    (ROOT / "docs/security/p4-supply-chain-policy.md").write_text(policy_document(), encoding="utf-8")
    (ROOT / "Dockerfile").write_text(dockerfile(summary), encoding="utf-8")

    rewrite_ci()
    rewrite_other_locked_installs()

    for path in TEMP_WORKFLOWS:
        path.unlink(missing_ok=True)
    shutil.rmtree(ROOT / "p4-bootstrap", ignore_errors=True)

    pins = pin_all_actions()
    evidence = {
        "schema_version": "1.0",
        "finalizer_start_sha": start_sha,
        "materialized_source_sha": summary["source_head_sha"],
        "dependency_audits": {
            "python_datahub": summary["python_datahub"],
            "python_agent_registry": summary["python_agent_registry"],
            "npm": summary["npm"],
        },
        "docker_base_images": summary["docker_base_images"],
        "risk_exceptions": exceptions["exceptions"],
        "action_pins": pins,
    }
    (ROOT / "docs/security/p4-supply-chain-evidence.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    Path(__file__).unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--start-sha", required=True)
    args = parser.parse_args()
    apply(args.start_sha)


if __name__ == "__main__":
    main()
