#!/usr/bin/env python3
"""ToxicJoin Phase 3 fail-closed, lock-bound bootstrap authority."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "config" / "toolchain.json"
UV_BIN = os.environ.get("TOXICJOIN_UV_BIN", "uv")


class BootstrapError(RuntimeError):
    pass


def now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(command: Sequence[str], *, timeout: int = 900, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            list(command), cwd=ROOT, text=True, encoding="utf-8", errors="replace",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise BootstrapError(f"command unavailable or timed out: {' '.join(command)}") from exc
    if check and result.returncode:
        detail = (result.stderr or result.stdout or "no output")[-4000:]
        raise BootstrapError(f"command failed ({result.returncode}): {' '.join(command)}\n{detail}")
    return result


def contract() -> dict[str, Any]:
    try:
        value = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError) as exc:
        raise BootstrapError(f"invalid or missing toolchain contract: {exc}") from exc
    required = {"schema_version", "baseline_main_sha", "python", "uv", "node", "docker", "datahub", "containers", "github_runners", "locks"}
    missing = sorted(required - value.keys())
    if value.get("schema_version") != "1.0" or missing:
        raise BootstrapError(f"unsupported or incomplete toolchain contract; missing={missing}")
    return value


def git_identity() -> dict[str, str | None]:
    if not (ROOT / ".git").exists() or not shutil.which("git"):
        return {"commit_sha": None, "tree_sha": None}
    return {
        "commit_sha": run(["git", "rev-parse", "HEAD"]).stdout.strip(),
        "tree_sha": run(["git", "rev-parse", "HEAD^{tree}"]).stdout.strip(),
    }


def lock_hashes(value: dict[str, Any] | None = None) -> dict[str, str]:
    value = value or contract()
    result: dict[str, str] = {}
    for item in value["locks"]:
        path = ROOT / item["path"]
        if not path.is_file():
            raise BootstrapError(f"required lock missing: {item['path']}")
        result[item["path"]] = sha(path)
    return result


def parse_version(text: str, pattern: str, label: str) -> str:
    match = re.search(pattern, text)
    if not match:
        raise BootstrapError(f"cannot parse {label} version from {text!r}")
    return match.group(1)


def manifest_errors(value: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    if pyproject["project"].get("requires-python") != value["python"]["requires_python"]:
        errors.append("pyproject.toml requires-python differs from toolchain contract")
    for relative in ("package.json", "apps/web/package.json"):
        package = json.loads((ROOT / relative).read_text(encoding="utf-8"))
        if package.get("packageManager") != value["node"]["package_manager"]:
            errors.append(f"{relative} packageManager mismatch")
        engines = package.get("engines", {})
        if engines.get("node") != value["node"]["version"]:
            errors.append(f"{relative} engines.node mismatch")
        if engines.get("npm") != value["node"]["npm_version"]:
            errors.append(f"{relative} engines.npm mismatch")
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    for key in ("node_builder", "python_runtime"):
        if value["containers"][key] not in dockerfile:
            errors.append(f"Dockerfile missing exact {key} identity")
    vercel = json.loads((ROOT / "vercel.json").read_text(encoding="utf-8"))
    command = vercel.get("buildCommand", "")
    if "npm ci" not in command or re.search(r"\bnpm\s+install\b", command):
        errors.append("vercel.json must use npm ci")
    return errors


def verify(components: list[str]) -> dict[str, Any]:
    value = contract()
    result: dict[str, Any] = {
        "schema_version": "1.0", "generated_at": now(), "git": git_identity(),
        "contract_sha256": sha(CONTRACT_PATH),
        "platform": {"system": platform.system(), "release": platform.release(), "machine": platform.machine()},
    }
    if "contract" in components:
        errors = manifest_errors(value)
        if errors:
            raise BootstrapError("contract authority mismatch:\n- " + "\n- ".join(errors))
        result["contract"] = "verified"
    if "python" in components:
        actual = platform.python_version()
        if actual not in value["python"]["supported_exact"]:
            raise BootstrapError(f"unsupported Python {actual}; expected {value['python']['supported_exact']}")
        result["python"] = {"version": actual, "executable": str(Path(sys.executable).resolve())}
    if "uv" in components:
        output = run([UV_BIN, "--version"]).stdout.strip()
        actual = parse_version(output, r"\buv\s+(\d+\.\d+\.\d+)\b", "uv")
        if actual != value["uv"]["version"]:
            raise BootstrapError(f"uv mismatch: expected {value['uv']['version']}, got {actual}")
        result["uv"] = {"version": actual, "executable": shutil.which(UV_BIN) or UV_BIN}
    if "node" in components:
        actual = parse_version(run(["node", "--version"]).stdout, r"v?(\d+\.\d+\.\d+)", "Node")
        if actual != value["node"]["version"]:
            raise BootstrapError(f"Node mismatch: expected {value['node']['version']}, got {actual}")
        result["node"] = actual
    if "npm" in components:
        actual = parse_version(run(["npm", "--version"]).stdout, r"(\d+\.\d+\.\d+)", "npm")
        if actual != value["node"]["npm_version"]:
            raise BootstrapError(f"npm mismatch: expected {value['node']['npm_version']}, got {actual}")
        result["npm"] = actual
    if "docker" in components:
        versions = value["docker"]
        pair = run(["docker", "version", "--format", "{{.Client.Version}}|{{.Server.Version}}"]).stdout.strip().split("|", 1)
        if pair != [versions["client_version"], versions["server_version"]]:
            raise BootstrapError(f"Docker client/server mismatch: {pair}")
        buildx = parse_version(run(["docker", "buildx", "version"]).stdout, r"v?(\d+\.\d+\.\d+)", "Buildx")
        compose = parse_version(run(["docker", "compose", "version", "--short"]).stdout, r"v?(\d+\.\d+\.\d+)", "Compose")
        if buildx != versions["buildx_version"] or compose != versions["compose_version"]:
            raise BootstrapError(f"Docker plugin mismatch: buildx={buildx}, compose={compose}")
        result["docker"] = {"client": pair[0], "server": pair[1], "buildx": buildx, "compose": compose}
    if "locks" in components:
        result["locks"] = lock_hashes(value)
    return result


def bootstrap_files() -> list[Path]:
    files = [ROOT / name for name in ("run.sh", "run.ps1", "Dockerfile", "vercel.json")]
    files += sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
    return [path for path in files if path.is_file()]


def audit() -> dict[str, Any]:
    value = contract()
    violations: list[dict[str, Any]] = []
    runners = set(value["github_runners"].values())
    for path in bootstrap_files():
        relative = path.relative_to(ROOT).as_posix()
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            checks = [
                ("P3-PIP-EDITABLE", bool(re.search(r"\bpip\s+install\b.*\s-e(?:\s|=)", text)), "editable pip install bypasses uv.lock"),
                ("P3-PIP-UPGRADE", bool(re.search(r"\bpip\s+install\b.*--upgrade\s+pip\b", text)), "unbounded pip upgrade"),
                ("P3-NPM-INSTALL", bool(re.search(r"\bnpm\s+install\b", text)), "npm install bypasses package lock"),
                ("P3-UV-SYNC", "uv sync" in text and "--frozen" not in text, "uv sync lacks --frozen"),
                ("P3-UV-RUN", "uv run" in text and "--frozen" not in text, "uv run lacks --frozen"),
                ("P3-RUNNER-LATEST", any(x in text for x in ("ubuntu-latest", "windows-latest", "macos-latest")), "moving runner label"),
            ]
            for rule, matched, message in checks:
                if matched:
                    violations.append({"rule_id": rule, "path": relative, "line": number, "message": message, "text": text[:300]})
            uv_match = re.search(r"uv==(\d+\.\d+\.\d+)", text)
            if uv_match and uv_match.group(1) != value["uv"]["version"]:
                violations.append({"rule_id": "P3-UV-VERSION", "path": relative, "line": number, "message": "wrong uv version", "text": text[:300]})
            py_match = re.search(r"python-version:\s*[\"']?([^\"'\s]+)", text)
            if py_match and "${{" not in py_match.group(1) and py_match.group(1) not in value["python"]["supported_exact"]:
                violations.append({"rule_id": "P3-PYTHON-VERSION", "path": relative, "line": number, "message": "setup-python is not exact", "text": text[:300]})
            node_match = re.search(r"node-version:\s*[\"']?([^\"'\s]+)", text)
            if node_match and "${{" not in node_match.group(1) and node_match.group(1) != value["node"]["version"]:
                violations.append({"rule_id": "P3-NODE-VERSION", "path": relative, "line": number, "message": "setup-node is not exact", "text": text[:300]})
            runner_match = re.search(r"runs-on:\s*([^#\s]+)", text)
            if runner_match and "${{" not in runner_match.group(1):
                runner = runner_match.group(1).strip("\"'")
                if runner.startswith(("ubuntu-", "windows-", "macos-")) and runner not in runners:
                    violations.append({"rule_id": "P3-RUNNER-VERSION", "path": relative, "line": number, "message": "runner outside contract", "text": text[:300]})
    for message in manifest_errors(value):
        violations.append({"rule_id": "P3-AUTHORITY", "path": "config/toolchain.json", "line": 1, "message": message, "text": ""})
    return {"schema_version": "1.0", "generated_at": now(), "scanned_files": len(bootstrap_files()), "violation_count": len(violations), "violations": violations}


def package_identity() -> dict[str, Any]:
    code = "import importlib.metadata as m,json;print(json.dumps(sorted((d.metadata['Name'].lower(),d.version) for d in m.distributions()),separators=(',',':')))"
    packages = json.loads(run([UV_BIN, "run", "--frozen", "python", "-c", code]).stdout)
    canonical = json.dumps(packages, sort_keys=True, separators=(",", ":")).encode()
    return {"count": len(packages), "sha256": hashlib.sha256(canonical).hexdigest(), "packages": packages}


def sync(extras: list[str]) -> dict[str, Any]:
    verify(["python", "uv", "locks", "contract"])
    before = lock_hashes()
    command = [UV_BIN, "sync", "--frozen"]
    for extra in extras:
        command += ["--extra", extra]
    started = time.monotonic()
    run(command)
    after = lock_hashes()
    if before != after:
        raise BootstrapError("frozen sync changed a committed lock")
    return {"schema_version": "1.0", "generated_at": now(), "command": command, "duration_seconds": round(time.monotonic() - started, 3), "lock_hashes_before": before, "lock_hashes_after": after, "installed_package_identity": package_identity()}


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def get_json(url: str) -> dict[str, Any]:
    with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=3) as response:
        return json.load(response)


def smoke(timeout: int) -> dict[str, Any]:
    verify(["python", "uv", "locks", "contract"])
    port = free_port()
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="toxicjoin-phase3-") as tmp:
        tmp_path = Path(tmp)
        env = os.environ.copy()
        env.update({"TOXICJOIN_HOST": "127.0.0.1", "TOXICJOIN_PORT": str(port), "TOXICJOIN_RUNTIME_DIR": str(tmp_path / "runtime"), "PYTHONUNBUFFERED": "1"})
        (tmp_path / "runtime").mkdir()
        log_path = tmp_path / "fixture.log"
        with log_path.open("w", encoding="utf-8") as log:
            process = subprocess.Popen([UV_BIN, "run", "--frozen", "toxicjoin-api"], cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT, text=True, encoding="utf-8", errors="replace")
            health = ready = None
            error: str | None = None
            deadline = time.monotonic() + timeout
            try:
                while time.monotonic() < deadline:
                    if process.poll() is not None:
                        raise BootstrapError(f"fixture exited early: {process.returncode}")
                    try:
                        health = get_json(f"http://127.0.0.1:{port}/api/health")
                        ready = get_json(f"http://127.0.0.1:{port}/api/ready")
                        break
                    except (OSError, urllib.error.URLError, json.JSONDecodeError):
                        time.sleep(0.5)
                else:
                    raise BootstrapError("fixture readiness timeout")
                if health != {"status": "ok"}:
                    raise BootstrapError(f"unexpected health: {health}")
                expected = {"status": "ok", "mode": "fixture", "database_ready": True, "receipt_store_ready": True}
                if ready is None or any(ready.get(k) != v for k, v in expected.items()):
                    raise BootstrapError(f"unexpected readiness: {ready}")
            except BootstrapError as exc:
                error = str(exc)
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(timeout=10)
        result = {"schema_version": "1.0", "generated_at": now(), "git": git_identity(), "duration_seconds": round(time.monotonic() - started, 3), "health": health, "ready": ready, "log_tail": log_path.read_text(encoding="utf-8", errors="replace")[-4000:], "passed": error is None}
        if error:
            result["error"] = error
            raise BootstrapError(json.dumps(result, indent=2, sort_keys=True))
        return result


def tracked_files() -> list[Path]:
    if (ROOT / ".git").exists() and shutil.which("git"):
        names = run(["git", "ls-files"]).stdout.splitlines()
        return [ROOT / name for name in names]
    return [p for p in ROOT.rglob("*") if p.is_file() and not any(x in p.parts for x in (".git", ".venv", "node_modules", "dist"))]


def census(path: Path) -> int:
    patterns = [("pip", r"\bpip\s+install\b"), ("uv-sync", r"\buv\s+sync\b"), ("uv-run", r"\buv\s+run\b"), ("uvx", r"\buvx\b"), ("npm-ci", r"\bnpm\s+ci\b"), ("npm-install", r"\bnpm\s+install\b"), ("docker", r"\bdocker\b"), ("setup-python", r"python-version:"), ("setup-node", r"node-version:"), ("runner", r"runs-on:")]
    rows: list[dict[str, Any]] = []
    for file in tracked_files():
        if file.suffix.lower() not in {"", ".json", ".md", ".mjs", ".ps1", ".py", ".sh", ".toml", ".yaml", ".yml"}:
            continue
        try:
            lines = file.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError:
            continue
        for number, line in enumerate(lines, 1):
            text = line.strip()
            if not text or text.startswith("#"):
                continue
            for tool, pattern in patterns:
                if re.search(pattern, text):
                    rows.append({"path": file.relative_to(ROOT).as_posix(), "line": number, "tool": tool, "command": text[:500]})
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["path", "line", "tool", "command"])
        writer.writeheader(); writer.writerows(rows)
    return len(rows)


def cleanliness(allowed: set[str]) -> dict[str, Any]:
    if not (ROOT / ".git").exists():
        raise BootstrapError("git worktree required")
    entries = [line for line in run(["git", "status", "--porcelain=v1", "--untracked-files=all"]).stdout.splitlines() if line]
    unexpected = [entry for entry in entries if entry[3:].replace("\\", "/") not in allowed]
    result = {"schema_version": "1.0", "generated_at": now(), "observed_entries": entries, "unexpected_entries": unexpected, "clean": not unexpected}
    if unexpected:
        raise BootstrapError("unexpected worktree changes:\n" + "\n".join(unexpected))
    return result


def evidence(output: Path) -> dict[str, Any]:
    output.mkdir(parents=True, exist_ok=True)
    identity = verify(["python", "uv", "node", "npm", "locks", "contract"])
    audit_result = audit()
    if audit_result["violation_count"]:
        raise BootstrapError(f"static audit found {audit_result['violation_count']} violation(s)")
    write_json(output / "toolchain-identity.json", identity)
    write_json(output / "bootstrap-static-audit.json", audit_result)
    write_json(output / "installed-package-identity.json", package_identity())
    census(output / "bootstrap-install-path-census.csv")
    items = [{"path": p.name, "size_bytes": p.stat().st_size, "sha256": sha(p)} for p in sorted(output.iterdir()) if p.is_file() and p.name != "SHA256SUMS"]
    index = {"schema_version": "1.0", "generated_at": now(), "phase": "3-reproducible-locked-bootstrap", "git": git_identity(), "contract_sha256": sha(CONTRACT_PATH), "lock_hashes": lock_hashes(), "artifacts": items, "live_datahub_executed": False, "phase4_full_portability_suite_executed": False}
    write_json(output / "bootstrap-evidence-index.json", index)
    checksums = [f"{sha(p)}  {p.name}" for p in sorted(output.iterdir()) if p.is_file() and p.name != "SHA256SUMS"]
    (output / "SHA256SUMS").write_text("\n".join(checksums) + "\n", encoding="utf-8")
    return index


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("verify"); p.add_argument("--components", default="python,uv,locks,contract"); p.add_argument("--output", type=Path)
    p = commands.add_parser("sync"); p.add_argument("--extra", action="append", default=[]); p.add_argument("--output", type=Path)
    p = commands.add_parser("audit"); p.add_argument("--output", type=Path)
    p = commands.add_parser("census"); p.add_argument("--output", type=Path, required=True)
    p = commands.add_parser("smoke"); p.add_argument("--output", type=Path); p.add_argument("--timeout-seconds", type=int, default=75)
    p = commands.add_parser("cleanliness"); p.add_argument("--allow", action="append", default=[]); p.add_argument("--output", type=Path)
    p = commands.add_parser("evidence"); p.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "verify": result = verify([x.strip() for x in args.components.split(",") if x.strip()])
        elif args.command == "sync": result = sync(args.extra)
        elif args.command == "audit":
            result = audit()
            if result["violation_count"]: raise BootstrapError(f"bootstrap audit found {result['violation_count']} violation(s)")
        elif args.command == "census": result = {"rows": census(args.output), "output": str(args.output)}
        elif args.command == "smoke": result = smoke(args.timeout_seconds)
        elif args.command == "cleanliness": result = cleanliness(set(args.allow))
        elif args.command == "evidence": result = evidence(args.output_dir)
        else: raise BootstrapError("unsupported command")
        output_path = getattr(args, "output", None)
        if output_path and args.command not in {"census"}: write_json(output_path, result)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except BootstrapError as exc:
        print(f"bootstrap error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
