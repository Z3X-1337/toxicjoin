from __future__ import annotations

import argparse
import json
import os
import tempfile
import tomllib
from pathlib import Path
from typing import Any

import generate_release_manifest as legacy
from release_manifest_artifacts import (
    ArtifactBundle,
    GATE_SPECS,
    GateSpec,
    canonical_sha256,
    json_member,
    member_by_basename,
    sha256_bytes,
    verify_sha256sums,
)
from release_manifest_gate import (
    MODE_CANDIDATE,
    MODE_RELEASE,
    Phase7GitHubApi,
    build_release_manifest,
    collect_artifact_bundles,
    collect_gate_runs,
)


def validate_ci_authoritative(
    bundles: dict[str, ArtifactBundle], source_sha: str
) -> dict[str, Any]:
    """Validate CI evidence using the checksum contract emitted by each producer."""
    benchmark, benchmark_raw = json_member(
        bundles["toxicjoin-benchmark"],
        "benchmark.json",
    )
    metrics = benchmark.get("metrics")
    if benchmark.get("schema_version") != "1.0" or not isinstance(metrics, dict):
        raise ValueError("benchmark evidence schema is invalid")
    if metrics.get("total_cases") != 30 or metrics.get("fully_passed") != 30:
        raise ValueError("benchmark did not pass all 30 cases")
    if metrics.get("false_allow_count") != 0 or metrics.get("unsafe_effective_allow_count") != 0:
        raise ValueError("benchmark contains unsafe allows")

    ppmc, ppmc_raw = json_member(
        bundles["toxicjoin-ppmc-hard-gate"],
        "ppmc-hard-gate.json",
    )
    if ppmc.get("schema_version") != "1.0" or ppmc.get("gate_passed") is not True:
        raise ValueError("PPMC hard gate is not verified")
    claimed_evidence_sha = legacy._validate_sha256(
        str(ppmc.get("evidence_sha256", "")),
        name="PPMC evidence_sha256",
    )
    canonical_payload = {
        key: value for key, value in ppmc.items() if key != "evidence_sha256"
    }
    actual_evidence_sha = canonical_sha256(canonical_payload)
    if actual_evidence_sha != claimed_evidence_sha:
        raise ValueError("PPMC evidence_sha256 mismatch")
    _, checksum_raw = member_by_basename(
        bundles["toxicjoin-ppmc-hard-gate"],
        "ppmc-hard-gate.sha256",
    )
    detached_checksum = legacy._validate_sha256(
        checksum_raw.decode("utf-8").strip().split()[0],
        name="PPMC detached checksum",
    )
    if detached_checksum != claimed_evidence_sha:
        raise ValueError("PPMC detached checksum mismatch")

    for name in ("pytest-3.11.15", "pytest-3.12.13", "toxicjoin-container-log"):
        if not any(data.strip() for data in bundles[name].members.values()):
            raise ValueError(f"{name} is empty")
    return {
        "benchmark_json_sha256": sha256_bytes(benchmark_raw),
        "benchmark_total_cases": 30,
        "benchmark_false_allow_count": 0,
        "ppmc_json_sha256": sha256_bytes(ppmc_raw),
        "ppmc_evidence_sha256": claimed_evidence_sha,
        "ppmc_gate_passed": True,
        "container_job_verified": True,
        "source_sha": source_sha,
    }


def validate_phase4_authoritative(
    bundles: dict[str, ArtifactBundle], source_sha: str
) -> dict[str, Any]:
    """Validate parity and native reports using the Phase 4 emitted schema."""
    parity = bundles["phase4-portability-parity"]
    parity_entries = verify_sha256sums(parity)
    parity_payload, parity_raw = json_member(
        parity,
        "phase4-parity-comparison.json",
    )
    comparisons = parity_payload.get("comparisons")
    if parity_payload.get("schema_version") != "1.0":
        raise ValueError("Phase 4 parity schema is invalid")
    if parity_payload.get("passed") is not True:
        raise ValueError("Phase 4 parity evidence is not verified")
    if not isinstance(comparisons, list) or len(comparisons) != 2:
        raise ValueError("Phase 4 parity comparisons are incomplete")
    for comparison in comparisons:
        if not isinstance(comparison, dict) or comparison.get("passed") is not True:
            raise ValueError("Phase 4 parity comparison failed")
        checks = comparison.get("checks")
        if not isinstance(checks, dict) or not checks:
            raise ValueError("Phase 4 parity checks are missing")
        if not all(value is True for value in checks.values()):
            raise ValueError("Phase 4 parity invariant failed")

    native_names = [
        name for name in bundles if name != "phase4-portability-parity"
    ]
    native_summaries: list[dict[str, Any]] = []
    for name in sorted(native_names):
        bundle = bundles[name]
        manifest_entries = verify_sha256sums(bundle)
        report, report_raw = json_member(
            bundle,
            "phase4-portability-evidence.json",
        )
        git = report.get("git")
        pytest_report = report.get("pytest")
        traceback_report = report.get("traceback_secret_redaction")
        worktree = report.get("worktree")
        if report.get("schema_version") != "1.0":
            raise ValueError(f"Phase 4 native evidence {name!r} schema is invalid")
        if not isinstance(git, dict) or git.get("commit_sha") != source_sha:
            raise ValueError(f"Phase 4 native evidence {name!r} source mismatch")
        if not isinstance(pytest_report, dict):
            raise ValueError(f"Phase 4 native evidence {name!r} lacks pytest data")
        passed = pytest_report.get("passed")
        if not isinstance(passed, int) or passed <= 0:
            raise ValueError(f"Phase 4 native evidence {name!r} has no passing tests")
        if pytest_report.get("failed") != 0 or pytest_report.get("errors") != 0:
            raise ValueError(f"Phase 4 native evidence {name!r} has test failures")
        if not isinstance(traceback_report, dict) or traceback_report.get("passed") is not True:
            raise ValueError(f"Phase 4 native evidence {name!r} failed traceback proof")
        if not isinstance(worktree, dict) or worktree.get("clean") is not True:
            raise ValueError(f"Phase 4 native evidence {name!r} has a dirty worktree")
        native_summaries.append(
            {
                "artifact": name,
                "python_version": report.get("environment", {}).get("python_version"),
                "system": report.get("environment", {}).get("system"),
                "passed": passed,
                "manifest_entries": manifest_entries,
                "report_sha256": sha256_bytes(report_raw),
            }
        )
    if len(native_summaries) != 4:
        raise ValueError("Phase 4 native platform evidence is incomplete")
    return {
        "parity_report_sha256": sha256_bytes(parity_raw),
        "parity_manifest_entries": parity_entries,
        "comparison_count": 2,
        "native_artifact_count": 4,
        "native": native_summaries,
    }


def install_authoritative_validators() -> None:
    ci = GATE_SPECS["CI"]
    GATE_SPECS["CI"] = GateSpec(
        required_artifacts=ci.required_artifacts,
        validator=validate_ci_authoritative,
        required_jobs=ci.required_jobs,
    )
    phase4 = GATE_SPECS["Phase 4 Portability Evidence"]
    GATE_SPECS["Phase 4 Portability Evidence"] = GateSpec(
        required_artifacts=phase4.required_artifacts,
        validator=validate_phase4_authoritative,
        required_jobs=phase4.required_jobs,
    )


install_authoritative_validators()


def write_atomic(path: Path, payload: dict[str, object]) -> None:
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
        description="Generate a fail-closed exact-revision ToxicJoin release manifest."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument(
        "--mode",
        choices=(MODE_CANDIDATE, MODE_RELEASE),
        required=True,
    )
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--checked-out-sha", required=True)
    parser.add_argument("--expected-head-branch", required=True)
    parser.add_argument("--current-main-sha", required=True)
    parser.add_argument("--base-main-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--wait-seconds", type=int, default=6900)
    parser.add_argument("--poll-seconds", type=int, default=20)
    args = parser.parse_args()

    try:
        source_sha = legacy._validate_sha(args.source_sha, name="source_sha")
        client = Phase7GitHubApi(
            repository=os.environ.get("GITHUB_REPOSITORY", ""),
            token=os.environ.get("GITHUB_TOKEN", ""),
        )
        selected_runs = collect_gate_runs(
            client=client,
            source_sha=source_sha,
            expected_head_branch=args.expected_head_branch,
            wait_seconds=args.wait_seconds,
            poll_seconds=args.poll_seconds,
        )
        bundles_by_workflow, jobs_by_workflow = collect_artifact_bundles(
            client=client,
            selected_runs=selected_runs,
        )
        manifest = build_release_manifest(
            root=args.root.resolve(),
            mode=args.mode,
            source_sha=source_sha,
            checked_out_sha=args.checked_out_sha,
            expected_head_branch=args.expected_head_branch,
            current_main_sha=args.current_main_sha,
            base_main_sha=args.base_main_sha,
            selected_runs=selected_runs,
            bundles_by_workflow=bundles_by_workflow,
            jobs_by_workflow=jobs_by_workflow,
        )
        write_atomic(args.output.resolve(), manifest)
    except (
        OSError,
        ValueError,
        json.JSONDecodeError,
        tomllib.TOMLDecodeError,
    ) as error:
        raise SystemExit(f"release manifest generation failed: {error}") from None


if __name__ == "__main__":
    main()
