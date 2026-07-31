from __future__ import annotations

import argparse
import json
import re
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXCEPTIONS = ROOT / "docs/security/p4-dependency-risk-exceptions.json"
TOOLCHAIN = ROOT / "config/toolchain.json"
_ALLOWED_UV_BOOTSTRAP_RE = re.compile(
    r"^(?:run:\s*)?python -m pip install(?: --no-cache-dir)? "
    r"--disable-pip-version-check [\"']uv==0\.8\.4[\"']$"
)


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
        raise SystemExit(
            "Unapproved Python dependency findings: " + json.dumps(rejected, sort_keys=True)
        )
    print(json.dumps({"profile": profile, "accepted_exceptions": accepted}, sort_keys=True))


def validate_npm(audit_json: str) -> None:
    payload = load(audit_json)
    vulnerabilities = payload.get("vulnerabilities", {})
    total = payload.get("metadata", {}).get("vulnerabilities", {}).get(
        "total", len(vulnerabilities)
    )
    if vulnerabilities or total:
        raise SystemExit(
            "npm audit findings are not allowed: " + json.dumps(vulnerabilities, sort_keys=True)
        )
    print("npm audit clean")


def _validate_workflow_installs(path: Path, text: str) -> None:
    for line in text.splitlines():
        stripped = line.strip()
        if re.search(r"\bpip\s+install\b", stripped):
            if not _ALLOWED_UV_BOOTSTRAP_RE.fullmatch(stripped):
                raise SystemExit(
                    f"Unapproved pip bootstrap/install remains in {path.relative_to(ROOT)}: {stripped}"
                )
        if "npm install" in stripped:
            raise SystemExit(
                f"Floating npm install remains in workflow: {path.relative_to(ROOT)}: {stripped}"
            )


def _consumes_frozen_python_lock(text: str) -> bool:
    return "uv sync --frozen" in text or "scripts/bootstrap.py sync" in text


def _validate_phase3_matrix(ci: str) -> None:
    toolchain = load(TOOLCHAIN)
    runners = toolchain["github_runners"]
    supported = toolchain["python"]["supported_by_platform"]
    for platform_name in ("linux", "windows", "macos"):
        runner = runners[platform_name]
        for version in supported[platform_name]:
            pair = re.compile(
                rf"-\s+os:\s*{re.escape(runner)}\s*\n"
                rf"\s+python:\s*[\"']{re.escape(version)}[\"']",
                re.MULTILINE,
            )
            if not pair.search(ci):
                raise SystemExit(
                    f"CI Phase 3 matrix missing exact pair: {runner}/{version}"
                )


def validate_static() -> None:
    required_locks = (
        ROOT / "uv.lock",
        ROOT / "package-lock.json",
        ROOT / "apps/web/package-lock.json",
    )
    missing_locks = [str(path.relative_to(ROOT)) for path in required_locks if not path.is_file()]
    if missing_locks:
        raise SystemExit("Required lockfile missing: " + json.dumps(missing_locks))

    bootstrap = (ROOT / "scripts/bootstrap.py").read_text(encoding="utf-8")
    if "command = [UV_BIN, \"sync\", \"--frozen\"]" not in bootstrap:
        raise SystemExit("Bootstrap sync authority no longer enforces uv --frozen")
    if "supported_by_platform" not in bootstrap or "platform_key()" not in bootstrap:
        raise SystemExit("Bootstrap no longer enforces platform-specific Python patches")

    docker = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    from_lines = [line for line in docker.splitlines() if line.startswith("FROM ")]
    if len(from_lines) < 3 or any("@sha256:" not in line for line in from_lines):
        raise SystemExit(f"Docker bases must be digest pinned: {from_lines}")
    if "npm ci --no-audit --no-fund" not in docker or not _consumes_frozen_python_lock(docker):
        raise SystemExit("Dockerfile does not consume committed locks")
    if "scripts/bootstrap.py sync --no-install-project" not in docker:
        raise SystemExit("Dockerfile must consume uv.lock without installing the project early")

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
        _validate_workflow_installs(path, text)
    if floating:
        raise SystemExit("Floating GitHub Actions refs: " + json.dumps(floating))

    ci = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    if not _consumes_frozen_python_lock(ci) or "npm ci --no-audit --no-fund" not in ci:
        raise SystemExit("CI does not consume committed dependency locks")
    required_phase3_tokens = (
        "bootstrap-contract:",
        "bootstrap-native:",
        "matrix:\n        include:",
        "scripts/bootstrap.py audit",
        "scripts/bootstrap.py evidence",
        "phase3-bootstrap-${{ matrix.os }}-python-${{ matrix.python }}",
    )
    if any(token not in ci for token in required_phase3_tokens):
        raise SystemExit("CI does not contain the complete Phase 3 gate")
    _validate_phase3_matrix(ci)

    hosted = (ROOT / ".github/workflows/verify-hosted-replay.yml").read_text(encoding="utf-8")
    if "npm ci --no-audit --no-fund" not in hosted:
        raise SystemExit("Hosted Replay does not consume the root npm lock")

    supply = (ROOT / ".github/workflows/supply-chain.yml").read_text(encoding="utf-8")
    required_supply_tokens = (
        "python-audit:",
        "web-audit:",
        "hosted-replay-audit:",
        "bandit:",
        "dependency-review-probe:",
        "dependency-review:",
        "dependency-review-fallback:",
        "exact-lock-local-fallback",
        "dependency-review-platform-error:",
    )
    if any(token not in supply for token in required_supply_tokens):
        raise SystemExit("Permanent supply-chain workflow is incomplete")

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
