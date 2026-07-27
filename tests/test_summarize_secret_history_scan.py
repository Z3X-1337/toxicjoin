from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "summarize_secret_history_scan.py"
SPEC = importlib.util.spec_from_file_location("summarize_secret_history_scan", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _write_report(path: Path, findings: list[dict]) -> Path:
    path.write_text(json.dumps(findings), encoding="utf-8")
    return path


def test_clean_scan_produces_clean_summary(tmp_path: Path) -> None:
    report = _write_report(tmp_path / "report.json", [])
    summary = MODULE.build_summary(
        report=report,
        scan_exit_code=0,
        source_sha="a" * 40,
        scanner_version="8.30.1",
        scanner_archive_sha256="b" * 64,
        commit_count=123,
        ref_count=7,
    )

    assert summary["scan"]["status"] == "CLEAN"
    assert summary["scan"]["finding_count"] == 0
    assert summary["git_scope"] == {
        "log_opts": "--all",
        "commit_count": 123,
        "ref_count": 7,
    }


def test_findings_are_sanitized_without_secret_material(tmp_path: Path) -> None:
    marker = "DO-NOT-LEAK-THIS-SECRET"
    report = _write_report(
        tmp_path / "report.json",
        [
            {
                "RuleID": "generic-api-key",
                "File": "example.env",
                "Commit": "c" * 40,
                "StartLine": 4,
                "EndLine": 4,
                "Secret": marker,
                "Match": f"TOKEN={marker}",
                "Entropy": 4.2,
                "Author": "Example",
                "Email": "example@example.invalid",
            }
        ],
    )

    summary = MODULE.build_summary(
        report=report,
        scan_exit_code=1,
        source_sha="d" * 40,
        scanner_version="8.30.1",
        scanner_archive_sha256="e" * 64,
        commit_count=10,
        ref_count=2,
    )
    serialized = json.dumps(summary, sort_keys=True)

    assert summary["scan"]["status"] == "FINDINGS"
    assert summary["scan"]["finding_count"] == 1
    assert marker not in serialized
    assert "example@example.invalid" not in serialized
    assert summary["scan"]["findings"] == [
        {
            "rule_id": "generic-api-key",
            "file": "example.env",
            "commit": "c" * 40,
            "start_line": 4,
            "end_line": 4,
        }
    ]


def test_inconsistent_success_with_findings_fails_closed(tmp_path: Path) -> None:
    report = _write_report(
        tmp_path / "report.json",
        [
            {
                "RuleID": "generic-api-key",
                "File": "example.env",
                "Commit": "f" * 40,
                "StartLine": 1,
                "EndLine": 1,
            }
        ],
    )

    with pytest.raises(ValueError, match="success while reporting findings"):
        MODULE.build_summary(
            report=report,
            scan_exit_code=0,
            source_sha="1" * 40,
            scanner_version="8.30.1",
            scanner_archive_sha256="2" * 64,
            commit_count=5,
            ref_count=1,
        )


def test_invalid_source_sha_fails_closed(tmp_path: Path) -> None:
    report = _write_report(tmp_path / "report.json", [])

    with pytest.raises(ValueError, match="source_sha"):
        MODULE.build_summary(
            report=report,
            scan_exit_code=0,
            source_sha="short",
            scanner_version="8.30.1",
            scanner_archive_sha256="3" * 64,
            commit_count=5,
            ref_count=1,
        )
