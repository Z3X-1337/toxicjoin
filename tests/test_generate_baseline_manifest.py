from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "generate_baseline_manifest.py"
SPEC = importlib.util.spec_from_file_location("generate_baseline_manifest", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _fixture_root(tmp_path: Path) -> tuple[Path, Path, Path]:
    for relative in MODULE._REQUIRED_INPUTS:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(relative + "\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "toxicjoin"\nversion = "0.1.0"\n',
        encoding="utf-8",
    )
    pytest_log = tmp_path / "pytest.log"
    pytest_log.write_text("756 passed, 1 warning in 105.42s\n", encoding="utf-8")
    benchmark = tmp_path / "benchmark.json"
    benchmark.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "benchmark_version": "1.0",
                "policy_version": "0.2.0",
                "report_sha256": "a" * 64,
                "expected_distribution": {"ALLOW": 10, "REWRITE": 10, "BLOCK": 10},
                "gate_failures": [],
                "metrics": {
                    "total_cases": 30,
                    "initial_accuracy": 1.0,
                    "effective_accuracy": 1.0,
                    "reason_accuracy": 1.0,
                    "full_case_accuracy": 1.0,
                    "false_allow_count": 0,
                    "unsafe_effective_allow_count": 0,
                    "rewrite_remediated_count": 6,
                    "rewrite_fail_closed_count": 4,
                    "verified_execution_count": 16,
                },
            }
        ),
        encoding="utf-8",
    )
    return tmp_path, pytest_log, benchmark


def test_build_manifest_binds_exact_source_and_evidence(tmp_path: Path) -> None:
    root, pytest_log, benchmark = _fixture_root(tmp_path)
    source_sha = "b" * 40
    manifest = MODULE.build_manifest(
        root=root,
        source_sha=source_sha,
        checked_out_sha=source_sha,
        pytest_log=pytest_log,
        benchmark_json=benchmark,
        environment={
            "GITHUB_SHA": source_sha,
            "GITHUB_REPOSITORY": "Z3X-1337/toxicjoin",
            "GITHUB_EVENT_NAME": "push",
            "GITHUB_REF": "refs/heads/main",
            "GITHUB_WORKFLOW": "Ground Truth Baseline",
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1",
        },
    )

    assert manifest["schema_version"] == "1.1"
    assert manifest["source"]["source_sha"] == source_sha
    assert manifest["source"]["checked_out_sha"] == source_sha
    assert manifest["source"]["exact_checkout_verified"] is True
    assert manifest["source"]["event_sha_matches_source_sha"] is True
    assert manifest["validation"]["pytest"]["passed"] == 756
    assert manifest["validation"]["benchmark"]["metrics"]["total_cases"] == 30
    assert manifest["validation"]["benchmark"]["gate_failures"] == []
    assert set(manifest["inputs"]) == set(MODULE._REQUIRED_INPUTS)


def test_build_manifest_rejects_checkout_mismatch(tmp_path: Path) -> None:
    root, pytest_log, benchmark = _fixture_root(tmp_path)

    with pytest.raises(ValueError, match="checked_out_sha does not match source_sha"):
        MODULE.build_manifest(
            root=root,
            source_sha="b" * 40,
            checked_out_sha="c" * 40,
            pytest_log=pytest_log,
            benchmark_json=benchmark,
            environment={},
        )


def test_build_manifest_rejects_failed_benchmark(tmp_path: Path) -> None:
    root, pytest_log, benchmark = _fixture_root(tmp_path)
    payload = json.loads(benchmark.read_text(encoding="utf-8"))
    payload["gate_failures"] = ["false_allow_detected"]
    benchmark.write_text(json.dumps(payload), encoding="utf-8")

    source_sha = "c" * 40
    with pytest.raises(ValueError, match="benchmark gate failed"):
        MODULE.build_manifest(
            root=root,
            source_sha=source_sha,
            checked_out_sha=source_sha,
            pytest_log=pytest_log,
            benchmark_json=benchmark,
            environment={},
        )


def test_build_manifest_rejects_missing_required_input(tmp_path: Path) -> None:
    root, pytest_log, benchmark = _fixture_root(tmp_path)
    (root / "uv.lock").unlink()

    source_sha = "d" * 40
    with pytest.raises(ValueError, match="required baseline inputs are missing"):
        MODULE.build_manifest(
            root=root,
            source_sha=source_sha,
            checked_out_sha=source_sha,
            pytest_log=pytest_log,
            benchmark_json=benchmark,
            environment={},
        )
