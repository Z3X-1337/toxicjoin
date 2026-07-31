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


def install_authoritative_ci_validator() -> None:
    current = GATE_SPECS["CI"]
    GATE_SPECS["CI"] = GateSpec(
        required_artifacts=current.required_artifacts,
        validator=validate_ci_authoritative,
        required_jobs=current.required_jobs,
    )


install_authoritative_ci_validator()


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
