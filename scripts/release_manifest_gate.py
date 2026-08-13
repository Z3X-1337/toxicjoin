from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

import generate_release_manifest as legacy
from release_manifest_artifacts import (
    ArtifactBundle,
    GATE_SPECS,
    GateSpec,
    build_artifact_bundle,
    canonical_sha256,
)

MODE_CANDIDATE = "candidate"
MODE_RELEASE = "release"
REQUIRED_WORKFLOWS = tuple(GATE_SPECS)


class Phase7GitHubApi(legacy.GitHubApi):
    def list_jobs(self, *, run_id: int) -> list[dict[str, Any]]:
        payload = self.get_json(
            f"/repos/{self.repository}/actions/runs/{run_id}/jobs?per_page=100"
        )
        jobs = payload.get("jobs")
        if not isinstance(jobs, list):
            raise ValueError("GitHub Actions jobs response is malformed")
        return [item for item in jobs if isinstance(item, dict)]


def run_sort_key(run: dict[str, Any]) -> tuple[int, int, int]:
    return (
        int(run.get("run_number") or 0),
        int(run.get("run_attempt") or 0),
        int(run.get("id") or 0),
    )


def select_gate_runs(
    *,
    runs: list[dict[str, Any]],
    source_sha: str,
    expected_head_branch: str,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    source_sha = legacy._validate_sha(source_sha, name="source_sha")
    if not expected_head_branch or expected_head_branch != expected_head_branch.strip():
        raise ValueError("expected_head_branch is invalid")
    selected: dict[str, dict[str, Any]] = {}
    pending: list[str] = []
    for workflow_name in REQUIRED_WORKFLOWS:
        candidates = [
            run
            for run in runs
            if run.get("name") == workflow_name
            and str(run.get("head_sha", "")).lower() == source_sha
            and run.get("head_branch") == expected_head_branch
        ]
        if not candidates:
            pending.append(f"{workflow_name}:missing")
            continue
        run = max(candidates, key=run_sort_key)
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


def collect_gate_runs(
    *,
    client: Phase7GitHubApi,
    source_sha: str,
    expected_head_branch: str,
    wait_seconds: int,
    poll_seconds: int,
) -> dict[str, dict[str, Any]]:
    deadline = time.monotonic() + max(0, wait_seconds)
    while True:
        selected, pending = select_gate_runs(
            runs=client.list_runs(source_sha=source_sha),
            source_sha=source_sha,
            expected_head_branch=expected_head_branch,
        )
        if not pending:
            return selected
        if time.monotonic() >= deadline:
            raise ValueError(
                "required workflows did not become ready before timeout: "
                + ", ".join(pending)
            )
        time.sleep(max(1, poll_seconds))


def required_artifact_metadata(
    artifacts: list[dict[str, Any]], names: tuple[str, ...]
) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    for name in names:
        matches = [artifact for artifact in artifacts if artifact.get("name") == name]
        if len(matches) != 1:
            raise ValueError(
                f"expected exactly one artifact {name!r}, found {len(matches)}"
            )
        result[name] = matches[0]
    return result


def validate_required_jobs(
    jobs: list[dict[str, Any]],
    names: tuple[str, ...],
    *,
    workflow: str,
) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for name in names:
        matches = [job for job in jobs if job.get("name") == name]
        if len(matches) != 1:
            raise ValueError(
                f"workflow {workflow!r} expected exactly one job {name!r}"
            )
        job = matches[0]
        if job.get("status") != "completed" or job.get("conclusion") != "success":
            raise ValueError(f"workflow {workflow!r} job {name!r} is not successful")
        summaries.append(
            {
                "id": int(job["id"]),
                "name": name,
                "status": "completed",
                "conclusion": "success",
                "started_at": job.get("started_at"),
                "completed_at": job.get("completed_at"),
            }
        )
    return summaries


def collect_artifact_bundles(
    *,
    client: Phase7GitHubApi,
    selected_runs: dict[str, dict[str, Any]],
) -> tuple[
    dict[str, dict[str, ArtifactBundle]],
    dict[str, list[dict[str, Any]]],
]:
    bundles_by_workflow: dict[str, dict[str, ArtifactBundle]] = {}
    jobs_by_workflow: dict[str, list[dict[str, Any]]] = {}
    for workflow_name, run in selected_runs.items():
        run_id = int(run["id"])
        spec = GATE_SPECS[workflow_name]
        metadata = required_artifact_metadata(
            client.list_artifacts(run_id=run_id),
            spec.required_artifacts,
        )
        bundles_by_workflow[workflow_name] = {
            name: build_artifact_bundle(
                item,
                client.download_artifact(artifact_id=int(item["id"])),
            )
            for name, item in metadata.items()
        }
        jobs_by_workflow[workflow_name] = client.list_jobs(run_id=run_id)
    return bundles_by_workflow, jobs_by_workflow


def build_release_manifest(
    *,
    root: Path,
    mode: str,
    source_sha: str,
    checked_out_sha: str,
    expected_head_branch: str,
    current_main_sha: str,
    base_main_sha: str,
    selected_runs: dict[str, dict[str, Any]],
    bundles_by_workflow: dict[str, dict[str, ArtifactBundle]],
    jobs_by_workflow: dict[str, list[dict[str, Any]]],
    environment: dict[str, str] | None = None,
    gate_specs: dict[str, GateSpec] | None = None,
) -> dict[str, Any]:
    specs = GATE_SPECS if gate_specs is None else gate_specs
    if mode not in {MODE_CANDIDATE, MODE_RELEASE}:
        raise ValueError("mode must be candidate or release")
    source_sha = legacy._validate_sha(source_sha, name="source_sha")
    checked_out_sha = legacy._validate_sha(checked_out_sha, name="checked_out_sha")
    current_main_sha = legacy._validate_sha(current_main_sha, name="current_main_sha")
    base_main_sha = legacy._validate_sha(base_main_sha, name="base_main_sha")
    if checked_out_sha != source_sha:
        raise ValueError("checked_out_sha does not match source_sha")
    if mode == MODE_RELEASE:
        if (
            expected_head_branch != "main"
            or current_main_sha != source_sha
            or base_main_sha != source_sha
        ):
            raise ValueError("release mode requires source_sha to be current main")
    else:
        if expected_head_branch == "main":
            raise ValueError("candidate mode requires a non-main head branch")
        if current_main_sha != base_main_sha:
            raise ValueError("candidate base is stale relative to current main")

    missing = [name for name in REQUIRED_WORKFLOWS if name not in selected_runs]
    if missing:
        raise ValueError(f"required workflow runs are missing: {missing}")
    gates: dict[str, Any] = {}
    artifact_count = 0
    for workflow_name in REQUIRED_WORKFLOWS:
        run = selected_runs[workflow_name]
        if run.get("status") != "completed" or run.get("conclusion") != "success":
            raise ValueError(f"workflow {workflow_name!r} is not successful")
        if (
            str(run.get("head_sha", "")).lower() != source_sha
            or run.get("head_branch") != expected_head_branch
        ):
            raise ValueError(
                f"workflow {workflow_name!r} is stale or bound to another branch"
            )
        spec = specs[workflow_name]
        bundles = bundles_by_workflow.get(workflow_name, {})
        if set(bundles) != set(spec.required_artifacts):
            raise ValueError(f"workflow {workflow_name!r} artifact set is incomplete")
        jobs = validate_required_jobs(
            jobs_by_workflow.get(workflow_name, []),
            spec.required_jobs,
            workflow=workflow_name,
        )
        claims = spec.validator(bundles, source_sha) if spec.validator else {}
        artifact_count += len(bundles)
        gates[workflow_name] = {
            "run": legacy._sanitize_run(run),
            "required_jobs": jobs,
            "artifacts": [bundle.metadata for bundle in bundles.values()],
            "verified_claims": claims,
            "status": "verified",
        }

    env = os.environ if environment is None else environment
    payload: dict[str, Any] = {
        "schema_version": "2.0",
        "project": {
            "name": "toxicjoin",
            "version": legacy._project_version(root),
        },
        "identity": {
            "mode": mode,
            "source_sha": source_sha,
            "checked_out_sha": checked_out_sha,
            "expected_head_branch": expected_head_branch,
            "current_main_sha": current_main_sha,
            "base_main_sha": base_main_sha,
            "exact_checkout_verified": True,
            "current_main_verified": (
                current_main_sha == base_main_sha
                if mode == MODE_CANDIDATE
                else current_main_sha == source_sha
            ),
            "candidate_is_not_release_identity": mode == MODE_CANDIDATE,
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
            "required_workflows": len(REQUIRED_WORKFLOWS),
            "successful_workflows": len(gates),
            "required_artifacts": artifact_count,
            "all_required_gates_verified": len(gates) == len(REQUIRED_WORKFLOWS),
            "missing": [],
            "stale": [],
            "skipped": [],
            "inapplicable": [],
        },
        "claim_boundaries": {
            "live_datahub": "exact-source-live-oss",
            "browser_e2e": "real-production-container",
            "public_demo_uses_synthetic_fixture": True,
            "static_runtime_fallback_enabled": False,
            "disclosure_state_topology": "SINGLE_NODE",
            "multi_replica_supported": False,
            "postgresql_canonical": False,
            "phase8_started": False,
            "immutable_release_created": False,
        },
    }
    payload["manifest_sha256"] = canonical_sha256(payload)
    return payload
