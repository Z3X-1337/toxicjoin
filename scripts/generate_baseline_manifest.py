from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import tempfile
import tomllib
from pathlib import Path
from typing import Any

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_PYTEST_PASSED_RE = re.compile(r"(?P<count>\d+) passed(?:,| in)")

_REQUIRED_INPUTS = (
    "uv.lock",
    "package-lock.json",
    "apps/web/package-lock.json",
    "Dockerfile",
    "src/toxicjoin/policy/default_policy.yaml",
)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Expected JSON object in {path}")
    return payload


def _parse_pytest_count(path: Path) -> int:
    text = path.read_text(encoding="utf-8", errors="replace")
    matches = list(_PYTEST_PASSED_RE.finditer(text))
    if not matches:
        raise ValueError(f"Could not find pytest passed-count in {path}")
    return int(matches[-1].group("count"))


def _project_version(root: Path) -> str:
    payload = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    version = payload.get("project", {}).get("version")
    if not isinstance(version, str) or not version:
        raise ValueError("pyproject.toml does not contain project.version")
    return version


def _validate_sha(value: str, *, name: str) -> str:
    normalized = value.strip().lower()
    if not _GIT_SHA_RE.fullmatch(normalized):
        raise ValueError(f"{name} must be a full 40-character Git SHA")
    return normalized


def _benchmark_summary(payload: dict[str, Any]) -> dict[str, Any]:
    metrics = payload.get("metrics")
    if not isinstance(metrics, dict):
        raise ValueError("benchmark report is missing metrics")
    gate_failures = payload.get("gate_failures")
    if not isinstance(gate_failures, list):
        raise ValueError("benchmark report gate_failures must be a list")
    if gate_failures:
        raise ValueError(f"benchmark gate failed: {gate_failures}")

    report_sha256 = payload.get("report_sha256")
    if not isinstance(report_sha256, str) or not _SHA256_RE.fullmatch(report_sha256):
        raise ValueError("benchmark report_sha256 is invalid")

    required_metrics = (
        "total_cases",
        "initial_accuracy",
        "effective_accuracy",
        "reason_accuracy",
        "full_case_accuracy",
        "false_allow_count",
        "unsafe_effective_allow_count",
        "rewrite_remediated_count",
        "rewrite_fail_closed_count",
        "verified_execution_count",
    )
    missing = [key for key in required_metrics if key not in metrics]
    if missing:
        raise ValueError(f"benchmark metrics missing required keys: {missing}")

    return {
        "schema_version": payload.get("schema_version"),
        "benchmark_version": payload.get("benchmark_version"),
        "policy_version": payload.get("policy_version"),
        "report_sha256": report_sha256,
        "expected_distribution": payload.get("expected_distribution"),
        "metrics": {key: metrics[key] for key in required_metrics},
        "gate_failures": gate_failures,
    }


def build_manifest(
    *,
    root: Path,
    source_sha: str,
    pytest_log: Path,
    benchmark_json: Path,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    env = os.environ if environment is None else environment
    source_sha = _validate_sha(source_sha, name="source_sha")

    missing_inputs = [item for item in _REQUIRED_INPUTS if not (root / item).is_file()]
    if not (root / "pyproject.toml").is_file():
        missing_inputs.append("pyproject.toml")
    if missing_inputs:
        raise ValueError(f"required baseline inputs are missing: {missing_inputs}")
    if not pytest_log.is_file():
        raise ValueError(f"pytest log does not exist: {pytest_log}")
    if not benchmark_json.is_file():
        raise ValueError(f"benchmark report does not exist: {benchmark_json}")

    workflow_sha_raw = env.get("GITHUB_SHA", "").strip().lower()
    workflow_sha = (
        _validate_sha(workflow_sha_raw, name="GITHUB_SHA") if workflow_sha_raw else None
    )

    inputs = {item: {"sha256": _sha256_file(root / item)} for item in _REQUIRED_INPUTS}

    return {
        "schema_version": "1.0",
        "project": {
            "name": "toxicjoin",
            "version": _project_version(root),
        },
        "source": {
            "repository": env.get("GITHUB_REPOSITORY"),
            "source_sha": source_sha,
            "workflow_sha": workflow_sha,
            "source_sha_matches_workflow_sha": (
                workflow_sha is not None and source_sha == workflow_sha
            ),
            "event_name": env.get("GITHUB_EVENT_NAME"),
            "ref": env.get("GITHUB_REF"),
            "workflow": env.get("GITHUB_WORKFLOW"),
            "run_id": env.get("GITHUB_RUN_ID"),
            "run_attempt": env.get("GITHUB_RUN_ATTEMPT"),
        },
        "runtime": {
            "python": platform.python_version(),
            "implementation": platform.python_implementation(),
        },
        "inputs": inputs,
        "validation": {
            "pytest": {
                "passed": _parse_pytest_count(pytest_log),
                "log_sha256": _sha256_file(pytest_log),
            },
            "benchmark": _benchmark_summary(_read_json(benchmark_json)),
        },
    }


def _write_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    ) as handle:
        handle.write(data)
        temporary = Path(handle.name)
    temporary.replace(path)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate a machine-readable ToxicJoin ground-truth baseline manifest."
    )
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--pytest-log", type=Path, required=True)
    parser.add_argument("--benchmark-json", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        manifest = build_manifest(
            root=args.root.resolve(),
            source_sha=args.source_sha,
            pytest_log=args.pytest_log.resolve(),
            benchmark_json=args.benchmark_json.resolve(),
        )
        _write_atomic(args.output.resolve(), manifest)
    except (OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        raise SystemExit(f"baseline generation failed: {error}") from None


if __name__ == "__main__":
    main()
