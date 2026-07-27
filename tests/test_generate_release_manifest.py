from __future__ import annotations

import importlib.util
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "generate_release_manifest.py"
SPEC = importlib.util.spec_from_file_location("generate_release_manifest", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _root(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "toxicjoin"\nversion = "0.1.0"\n',
        encoding="utf-8",
    )
    return tmp_path


def _run(name: str, source_sha: str, *, run_number: int, conclusion: str = "success") -> dict[str, Any]:
    return {
        "id": 1000 + run_number,
        "name": name,
        "run_number": run_number,
        "run_attempt": 1,
        "event": "push",
        "head_branch": "main",
        "head_sha": source_sha,
        "status": "completed",
        "conclusion": conclusion,
        "html_url": f"https://github.example/runs/{1000 + run_number}",
        "created_at": "2026-07-27T00:00:00Z",
        "updated_at": "2026-07-27T00:01:00Z",
    }


def _runs(source_sha: str) -> list[dict[str, Any]]:
    return [
        _run(name, source_sha, run_number=index)
        for index, name in enumerate(MODULE._REQUIRED_WORKFLOWS, start=1)
    ]


def _baseline(source_sha: str) -> dict[str, Any]:
    return {
        "schema_version": "1.1",
        "source": {
            "source_sha": source_sha,
            "checked_out_sha": source_sha,
            "exact_checkout_verified": True,
        },
        "validation": {
            "pytest": {
                "passed": 760,
                "log_sha256": "a" * 64,
            },
            "benchmark": {
                "schema_version": "1.0",
                "benchmark_version": "1.0",
                "policy_version": "0.2.0",
                "report_sha256": "b" * 64,
                "expected_distribution": {"ALLOW": 10, "REWRITE": 10, "BLOCK": 10},
                "gate_failures": [],
                "metrics": {
                    "total_cases": 30,
                    "false_allow_count": 0,
                    "unsafe_effective_allow_count": 0,
                },
            },
        },
    }


def _artifacts(selected: dict[str, dict[str, Any]]) -> dict[int, list[dict[str, Any]]]:
    result = {int(run["id"]): [] for run in selected.values()}
    baseline_run_id = int(selected[MODULE._BASELINE_WORKFLOW]["id"])
    result[baseline_run_id] = [
        {
            "id": 9001,
            "name": MODULE._BASELINE_ARTIFACT,
            "digest": "sha256:" + "c" * 64,
            "expired": False,
            "size_in_bytes": 1234,
            "created_at": "2026-07-27T00:02:00Z",
            "expires_at": "2026-08-26T00:02:00Z",
        }
    ]
    return result


def test_build_release_manifest_binds_current_main_and_all_gates(tmp_path: Path) -> None:
    source_sha = "d" * 40
    selected, pending = MODULE.select_gate_runs(runs=_runs(source_sha), source_sha=source_sha)
    assert pending == []

    baseline_payload = _baseline(source_sha)
    baseline_bytes = json.dumps(baseline_payload, sort_keys=True).encode("utf-8")
    manifest = MODULE.build_release_manifest(
        root=_root(tmp_path),
        source_sha=source_sha,
        checked_out_sha=source_sha,
        current_main_sha=source_sha,
        selected_runs=selected,
        artifacts_by_run=_artifacts(selected),
        baseline_payload=baseline_payload,
        baseline_json_bytes=baseline_bytes,
        environment={
            "GITHUB_REPOSITORY": "Z3X-1337/toxicjoin",
            "GITHUB_WORKFLOW": "Generated Release Manifest",
            "GITHUB_RUN_ID": "42",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_EVENT_NAME": "workflow_run",
        },
    )

    assert manifest["schema_version"] == "1.0"
    assert manifest["release"]["source_sha"] == source_sha
    assert manifest["release"]["current_main_verified"] is True
    assert manifest["gate_summary"] == {
        "required": len(MODULE._REQUIRED_WORKFLOWS),
        "successful": len(MODULE._REQUIRED_WORKFLOWS),
        "all_required_workflows_passed": True,
    }
    assert set(manifest["gates"]) == set(MODULE._REQUIRED_WORKFLOWS)
    assert manifest["ground_truth_baseline"]["summary"]["pytest"]["passed"] == 760
    assert len(manifest["manifest_sha256"]) == 64


def test_select_gate_runs_rejects_newer_failed_run() -> None:
    source_sha = "e" * 40
    runs = _runs(source_sha)
    runs.append(_run("CI", source_sha, run_number=999, conclusion="failure"))

    with pytest.raises(ValueError, match="required workflow 'CI' concluded 'failure'"):
        MODULE.select_gate_runs(runs=runs, source_sha=source_sha)


def test_select_gate_runs_reports_missing_workflow() -> None:
    source_sha = "f" * 40
    runs = [run for run in _runs(source_sha) if run["name"] != "Secret History Security"]

    selected, pending = MODULE.select_gate_runs(runs=runs, source_sha=source_sha)

    assert "Secret History Security" not in selected
    assert pending == ["Secret History Security:missing"]


def test_build_release_manifest_rejects_noncurrent_source(tmp_path: Path) -> None:
    source_sha = "1" * 40
    selected, pending = MODULE.select_gate_runs(runs=_runs(source_sha), source_sha=source_sha)
    assert pending == []

    with pytest.raises(ValueError, match="source_sha is not the current main SHA"):
        MODULE.build_release_manifest(
            root=_root(tmp_path),
            source_sha=source_sha,
            checked_out_sha=source_sha,
            current_main_sha="2" * 40,
            selected_runs=selected,
            artifacts_by_run=_artifacts(selected),
            baseline_payload=_baseline(source_sha),
            baseline_json_bytes=b"{}",
            environment={},
        )


def test_build_release_manifest_rejects_baseline_source_mismatch(tmp_path: Path) -> None:
    source_sha = "3" * 40
    selected, pending = MODULE.select_gate_runs(runs=_runs(source_sha), source_sha=source_sha)
    assert pending == []
    baseline_payload = _baseline("4" * 40)

    with pytest.raises(ValueError, match="baseline source_sha does not match release source"):
        MODULE.build_release_manifest(
            root=_root(tmp_path),
            source_sha=source_sha,
            checked_out_sha=source_sha,
            current_main_sha=source_sha,
            selected_runs=selected,
            artifacts_by_run=_artifacts(selected),
            baseline_payload=baseline_payload,
            baseline_json_bytes=json.dumps(baseline_payload).encode("utf-8"),
            environment={},
        )


def test_build_release_manifest_requires_baseline_artifact_digest(tmp_path: Path) -> None:
    source_sha = "5" * 40
    selected, pending = MODULE.select_gate_runs(runs=_runs(source_sha), source_sha=source_sha)
    assert pending == []
    artifacts = _artifacts(selected)
    baseline_run_id = int(selected[MODULE._BASELINE_WORKFLOW]["id"])
    artifacts[baseline_run_id][0]["digest"] = None

    with pytest.raises(ValueError, match="baseline artifact is missing digest"):
        MODULE.build_release_manifest(
            root=_root(tmp_path),
            source_sha=source_sha,
            checked_out_sha=source_sha,
            current_main_sha=source_sha,
            selected_runs=selected,
            artifacts_by_run=artifacts,
            baseline_payload=_baseline(source_sha),
            baseline_json_bytes=b"{}",
            environment={},
        )


def test_artifact_download_does_not_forward_bearer_to_signed_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signed_url = "https://signed.example/artifact.zip?sig=test"
    authenticated_headers: dict[str, str] = {}
    signed_headers: dict[str, str] = {}

    class RedirectingOpener:
        def open(self, request: urllib.request.Request, timeout: int) -> Any:
            authenticated_headers.update(dict(request.header_items()))
            raise urllib.error.HTTPError(
                request.full_url,
                302,
                "Found",
                {"Location": signed_url},
                None,
            )

    class SignedResponse:
        def __enter__(self) -> "SignedResponse":
            return self

        def __exit__(self, *args: Any) -> None:
            return None

        def read(self, limit: int) -> bytes:
            return b"artifact-zip"

    def fake_build_opener(*handlers: Any) -> RedirectingOpener:
        return RedirectingOpener()

    def fake_urlopen(request: urllib.request.Request, timeout: int) -> SignedResponse:
        assert request.full_url == signed_url
        signed_headers.update(dict(request.header_items()))
        return SignedResponse()

    monkeypatch.setattr(urllib.request, "build_opener", fake_build_opener)
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    client = MODULE.GitHubApi(repository="Z3X-1337/toxicjoin", token="test-token")
    assert client.download_artifact(artifact_id=123) == b"artifact-zip"

    assert authenticated_headers.get("Authorization") == "Bearer test-token"
    assert "Authorization" not in signed_headers
