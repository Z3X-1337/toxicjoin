from __future__ import annotations

import argparse
import json
import os
import tempfile
import tomllib
from pathlib import Path

import generate_release_manifest as legacy
from release_manifest_gate import (
    MODE_CANDIDATE,
    MODE_RELEASE,
    Phase7GitHubApi,
    build_release_manifest,
    collect_artifact_bundles,
    collect_gate_runs,
)


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
