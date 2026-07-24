from __future__ import annotations

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
