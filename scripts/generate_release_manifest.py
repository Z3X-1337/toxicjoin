from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import tempfile
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_SHA256_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

_REQUIRED_WORKFLOWS = (
    "CI",
    "CodeQL",
    "Supply Chain Security",
    "Governance Dependency Evidence",
    "Adversarial Mutation Evidence",
    "Compositional Ablation Evidence",
    "Ground Truth Baseline",
    "Secret History Security",
)

_BASELINE_WORKFLOW = "Ground Truth Baseline"
_BASELINE_ARTIFACT = "toxicjoin-ground-truth-baseline"
_MAX_ARTIFACT_BYTES = 64 * 1024 * 1024


def _validate_sha(value: str, *, name: str) -> str:
    normalized = value.strip().lower()
    if not _GIT_SHA_RE.fullmatch(normalized):
        raise ValueError(f"{name} must be a full 40-character Git SHA")
    return normalized


def _validate_sha256(value: str, *, name: str) -> str:
    normalized = value.strip().lower()
    if not _SHA256_RE.fullmatch(normalized):
        raise ValueError(f"{name} must be a lowercase 64-character SHA-256")
    return normalized


def _validate_digest(value: str, *, name: str) -> str:
    normalized = value.strip().lower()
    if not _SHA256_DIGEST_RE.fullmatch(normalized):
        raise ValueError(f"{name} must be a sha256:<64-hex> digest")
    return normalized


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _project_version(root: Path) -> str:
    payload = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    version = payload.get("project", {}).get("version")
    if not isinstance(version, str) or not version:
        raise ValueError("pyproject.toml does not contain project.version")
    return version


def _canonical_sha256(payload: dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _run_sort_key(run: dict[str, Any]) -> tuple[int, int, int]:
    return (
        int(run.get("run_number") or 0),
        int(run.get("run_attempt") or 0),
        int(run.get("id") or 0),
    )


def _latest_exact_run(
    runs: list[dict[str, Any]], *, workflow_name: str, source_sha: str
) -> dict[str, Any] | None:
    candidates = [
        run
        for run in runs
        if run.get("name") == workflow_name
        and str(run.get("head_sha", "")).lower() == source_sha
        and run.get("head_branch") == "main"
    ]
    if not candidates:
        return None
    return max(candidates, key=_run_sort_key)


def select_gate_runs(
    *, runs: list[dict[str, Any]], source_sha: str
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    source_sha = _validate_sha(source_sha, name="source_sha")
    selected: dict[str, dict[str, Any]] = {}
    pending: list[str] = []

    for workflow_name in _REQUIRED_WORKFLOWS:
        run = _latest_exact_run(runs, workflow_name=workflow_name, source_sha=source_sha)
        if run is None:
            pending.append(f"{workflow_name}:missing")
            continue
        if run.get("status") != "completed":
            pending.append(f"{workflow_name}:{run.get('status') or 'unknown'}")
            continue
        conclusion = run.get("conclusion")
        if conclusion != "success":
            raise ValueError(
                f"required workflow {workflow_name!r} concluded {conclusion!r} "
                f"on source {source_sha}"
            )
        selected[workflow_name] = run

    return selected, pending


def _sanitize_run(run: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(run["id"]),
        "name": str(run["name"]),
        "run_number": int(run.get("run_number") or 0),
        "run_attempt": int(run.get("run_attempt") or 0),
        "event": run.get("event"),
        "head_branch": run.get("head_branch"),
        "head_sha": str(run.get("head_sha", "")).lower(),
        "status": run.get("status"),
        "conclusion": run.get("conclusion"),
        "html_url": run.get("html_url"),
        "created_at": run.get("created_at"),
        "updated_at": run.get("updated_at"),
    }


def _sanitize_artifact(artifact: dict[str, Any]) -> dict[str, Any]:
    raw_digest = artifact.get("digest")
    digest: str | None = None
    if isinstance(raw_digest, str) and raw_digest:
        digest = _validate_digest(raw_digest, name=f"artifact {artifact.get('name')} digest")
    return {
        "id": int(artifact["id"]),
        "name": str(artifact["name"]),
        "digest": digest,
        "expired": bool(artifact.get("expired", False)),
        "size_in_bytes": int(artifact.get("size_in_bytes") or 0),
        "created_at": artifact.get("created_at"),
        "expires_at": artifact.get("expires_at"),
    }


def _find_baseline_artifact(artifacts: list[dict[str, Any]]) -> dict[str, Any]:
    matches = [artifact for artifact in artifacts if artifact.get("name") == _BASELINE_ARTIFACT]
    if len(matches) != 1:
        raise ValueError(
            f"expected exactly one {_BASELINE_ARTIFACT!r} artifact, found {len(matches)}"
        )
    artifact = matches[0]
    if artifact.get("expired"):
        raise ValueError("ground-truth baseline artifact is expired")
    digest = artifact.get("digest")
    if not isinstance(digest, str):
        raise ValueError("ground-truth baseline artifact is missing digest")
    _validate_digest(digest, name="ground-truth baseline artifact digest")
    return artifact


def _baseline_summary(payload: dict[str, Any], *, source_sha: str) -> dict[str, Any]:
    if payload.get("schema_version") != "1.1":
        raise ValueError("ground-truth baseline schema_version must be 1.1")

    source = payload.get("source")
    if not isinstance(source, dict):
        raise ValueError("ground-truth baseline is missing source")
    if str(source.get("source_sha", "")).lower() != source_sha:
        raise ValueError("ground-truth baseline source_sha does not match release source")
    if str(source.get("checked_out_sha", "")).lower() != source_sha:
        raise ValueError("ground-truth baseline checked_out_sha does not match release source")
    if source.get("exact_checkout_verified") is not True:
        raise ValueError("ground-truth baseline did not verify exact checkout")

    validation = payload.get("validation")
    if not isinstance(validation, dict):
        raise ValueError("ground-truth baseline is missing validation")
    pytest_payload = validation.get("pytest")
    benchmark = validation.get("benchmark")
    if not isinstance(pytest_payload, dict) or not isinstance(benchmark, dict):
        raise ValueError("ground-truth baseline validation is incomplete")

    passed = pytest_payload.get("passed")
    if not isinstance(passed, int) or passed <= 0:
        raise ValueError("ground-truth baseline pytest passed count is invalid")
    log_sha256 = pytest_payload.get("log_sha256")
    if not isinstance(log_sha256, str):
        raise ValueError("ground-truth baseline pytest log SHA-256 is missing")
    _validate_sha256(log_sha256, name="ground-truth baseline pytest log SHA-256")

    gate_failures = benchmark.get("gate_failures")
    if not isinstance(gate_failures, list) or gate_failures:
        raise ValueError("ground-truth baseline benchmark gate is not clean")
    report_sha256 = benchmark.get("report_sha256")
    if not isinstance(report_sha256, str):
        raise ValueError("ground-truth baseline benchmark report SHA-256 is missing")
    _validate_sha256(report_sha256, name="ground-truth baseline benchmark report SHA-256")

    metrics = benchmark.get("metrics")
    if not isinstance(metrics, dict):
        raise ValueError("ground-truth baseline benchmark metrics are missing")

    return {
        "schema_version": payload["schema_version"],
        "source_sha": source_sha,
        "pytest": {
            "passed": passed,
            "log_sha256": log_sha256,
        },
        "benchmark": {
            "schema_version": benchmark.get("schema_version"),
            "benchmark_version": benchmark.get("benchmark_version"),
            "policy_version": benchmark.get("policy_version"),
            "report_sha256": report_sha256,
            "expected_distribution": benchmark.get("expected_distribution"),
            "metrics": metrics,
            "gate_failures": [],
        },
    }


def build_release_manifest(
    *,
    root: Path,
    source_sha: str,
    checked_out_sha: str,
    current_main_sha: str,
    selected_runs: dict[str, dict[str, Any]],
    artifacts_by_run: dict[int, list[dict[str, Any]]],
    baseline_payload: dict[str, Any],
    baseline_json_bytes: bytes,
    environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    env = os.environ if environment is None else environment
    source_sha = _validate_sha(source_sha, name="source_sha")
    checked_out_sha = _validate_sha(checked_out_sha, name="checked_out_sha")
    current_main_sha = _validate_sha(current_main_sha, name="current_main_sha")
    if checked_out_sha != source_sha:
        raise ValueError("checked_out_sha does not match source_sha")
    if current_main_sha != source_sha:
        raise ValueError("source_sha is not the current main SHA")

    missing = [name for name in _REQUIRED_WORKFLOWS if name not in selected_runs]
    if missing:
        raise ValueError(f"required workflow runs are missing: {missing}")

    gates: dict[str, Any] = {}
    for workflow_name in _REQUIRED_WORKFLOWS:
        run = selected_runs[workflow_name]
        if str(run.get("head_sha", "")).lower() != source_sha:
            raise ValueError(f"workflow {workflow_name!r} is not bound to source_sha")
        if run.get("status") != "completed" or run.get("conclusion") != "success":
            raise ValueError(f"workflow {workflow_name!r} is not successful")
        run_id = int(run["id"])
        artifacts = [_sanitize_artifact(item) for item in artifacts_by_run.get(run_id, [])]
        gates[workflow_name] = {
            "run": _sanitize_run(run),
            "artifacts": artifacts,
        }

    baseline_run_id = int(selected_runs[_BASELINE_WORKFLOW]["id"])
    baseline_artifact = _find_baseline_artifact(artifacts_by_run.get(baseline_run_id, []))
    baseline_summary = _baseline_summary(baseline_payload, source_sha=source_sha)

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "project": {
            "name": "toxicjoin",
            "version": _project_version(root),
        },
        "release": {
            "source_sha": source_sha,
            "checked_out_sha": checked_out_sha,
            "current_main_sha": current_main_sha,
            "exact_checkout_verified": True,
            "current_main_verified": True,
        },
        "generator": {
            "repository": env.get("GITHUB_REPOSITORY"),
            "workflow": env.get("GITHUB_WORKFLOW"),
            "run_id": env.get("GITHUB_RUN_ID"),
            "run_attempt": env.get("GITHUB_RUN_ATTEMPT"),
            "event_name": env.get("GITHUB_EVENT_NAME"),
        },
        "gates": gates,
        "gate_summary": {
            "required": len(_REQUIRED_WORKFLOWS),
            "successful": len(gates),
            "all_required_workflows_passed": len(gates) == len(_REQUIRED_WORKFLOWS),
        },
        "ground_truth_baseline": {
            "artifact": _sanitize_artifact(baseline_artifact),
            "baseline_json_sha256": _sha256_bytes(baseline_json_bytes),
            "summary": baseline_summary,
        },
    }
    payload["manifest_sha256"] = _canonical_sha256(payload)
    return payload


class GitHubApi:
    def __init__(self, *, repository: str, token: str) -> None:
        if not repository or "/" not in repository:
            raise ValueError("GitHub repository must be in owner/name form")
        if not token:
            raise ValueError("GitHub token is required")
        self.repository = repository
        self.token = token

    def _request(self, path: str) -> bytes:
        request = urllib.request.Request(
            f"https://api.github.com{path}",
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": f"Bearer {self.token}",
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "toxicjoin-release-manifest",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                data = response.read(_MAX_ARTIFACT_BYTES + 1)
        except urllib.error.HTTPError as error:
            raise ValueError(f"GitHub API request failed with HTTP {error.code}") from None
        except urllib.error.URLError as error:
            raise ValueError("GitHub API request failed") from error
        if len(data) > _MAX_ARTIFACT_BYTES:
            raise ValueError("GitHub API response exceeded safety limit")
        return data

    def get_json(self, path: str) -> dict[str, Any]:
        payload = json.loads(self._request(path).decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("GitHub API response must be a JSON object")
        return payload

    def list_runs(self, *, source_sha: str) -> list[dict[str, Any]]:
        query = urllib.parse.urlencode({"head_sha": source_sha, "per_page": 100})
        payload = self.get_json(f"/repos/{self.repository}/actions/runs?{query}")
        runs = payload.get("workflow_runs")
        if not isinstance(runs, list):
            raise ValueError("GitHub Actions runs response is malformed")
        return [item for item in runs if isinstance(item, dict)]

    def list_artifacts(self, *, run_id: int) -> list[dict[str, Any]]:
        payload = self.get_json(
            f"/repos/{self.repository}/actions/runs/{run_id}/artifacts?per_page=100"
        )
        artifacts = payload.get("artifacts")
        if not isinstance(artifacts, list):
            raise ValueError("GitHub Actions artifacts response is malformed")
        return [item for item in artifacts if isinstance(item, dict)]

    def download_artifact(self, *, artifact_id: int) -> bytes:
        return self._request(f"/repos/{self.repository}/actions/artifacts/{artifact_id}/zip")


def collect_gate_runs(
    *,
    client: GitHubApi,
    source_sha: str,
    wait_seconds: int,
    poll_seconds: int,
) -> dict[str, dict[str, Any]]:
    deadline = time.monotonic() + max(0, wait_seconds)
    last_pending: list[str] = []
    while True:
        runs = client.list_runs(source_sha=source_sha)
        selected, pending = select_gate_runs(runs=runs, source_sha=source_sha)
        if not pending:
            return selected
        last_pending = pending
        if time.monotonic() >= deadline:
            raise ValueError(
                "required workflows did not become ready before timeout: "
                + ", ".join(last_pending)
            )
        time.sleep(max(1, poll_seconds))


def _read_baseline_from_zip(data: bytes) -> tuple[dict[str, Any], bytes]:
    if len(data) > _MAX_ARTIFACT_BYTES:
        raise ValueError("ground-truth baseline artifact exceeds safety limit")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            members = [
                name
                for name in archive.namelist()
                if name == "baseline.json" or name.endswith("/baseline.json")
            ]
            if len(members) != 1:
                raise ValueError(
                    f"expected exactly one baseline.json in artifact, found {len(members)}"
                )
            baseline_bytes = archive.read(members[0])
    except zipfile.BadZipFile:
        raise ValueError("ground-truth baseline artifact is not a valid ZIP") from None
    payload = json.loads(baseline_bytes.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("baseline.json must contain a JSON object")
    return payload, baseline_bytes


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
        description="Generate an exact-revision ToxicJoin release manifest from GitHub Actions evidence."
    )
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--checked-out-sha", required=True)
    parser.add_argument("--current-main-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--wait-seconds", type=int, default=900)
    parser.add_argument("--poll-seconds", type=int, default=15)
    args = parser.parse_args()

    try:
        source_sha = _validate_sha(args.source_sha, name="source_sha")
        repository = os.environ.get("GITHUB_REPOSITORY", "")
        token = os.environ.get("GITHUB_TOKEN", "")
        client = GitHubApi(repository=repository, token=token)
        selected_runs = collect_gate_runs(
            client=client,
            source_sha=source_sha,
            wait_seconds=args.wait_seconds,
            poll_seconds=args.poll_seconds,
        )
        artifacts_by_run = {
            int(run["id"]): client.list_artifacts(run_id=int(run["id"]))
            for run in selected_runs.values()
        }
        baseline_run_id = int(selected_runs[_BASELINE_WORKFLOW]["id"])
        baseline_artifact = _find_baseline_artifact(artifacts_by_run[baseline_run_id])
        baseline_zip = client.download_artifact(artifact_id=int(baseline_artifact["id"]))
        baseline_payload, baseline_json_bytes = _read_baseline_from_zip(baseline_zip)
        manifest = build_release_manifest(
            root=args.root.resolve(),
            source_sha=source_sha,
            checked_out_sha=args.checked_out_sha,
            current_main_sha=args.current_main_sha,
            selected_runs=selected_runs,
            artifacts_by_run=artifacts_by_run,
            baseline_payload=baseline_payload,
            baseline_json_bytes=baseline_json_bytes,
        )
        _write_atomic(args.output.resolve(), manifest)
    except (OSError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        raise SystemExit(f"release manifest generation failed: {error}") from None


if __name__ == "__main__":
    main()
