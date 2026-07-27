from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "summarize_secret_history.py"
SPEC = importlib.util.spec_from_file_location("summarize_secret_history", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def _report(tmp_path: Path, findings: list[dict]) -> Path:
    path = tmp_path / "gitleaks-report.json"
    path.write_text(json.dumps(findings), encoding="utf-8")
    return path


def test_summary_never_copies_secret_payload(tmp_path: Path) -> None:
    synthetic_secret = "super-secret-value-must-not-escape"
    report = _report(
        tmp_path,
        [
            {
                "RuleID": "generic-api-key",
                "Secret": synthetic_secret,
                "Match": f"token={synthetic_secret}",
                "Line": f"API_TOKEN={synthetic_secret}",
                "File": ".env.old",
                "Commit": "a" * 40,
            }
        ],
    )

    summary = MODULE.build_summary(
        report_path=report,
        source_sha="b" * 40,
        checked_out_sha="b" * 40,
        commit_count=123,
        ref_count=7,
        scanner_version="8.30.1",
        scanner_asset_sha256="c" * 64,
        scanner_exit_code=1,
    )

    serialized = json.dumps(summary, sort_keys=True)
    assert synthetic_secret not in serialized
    assert ".env.old" not in serialized
    assert "a" * 40 not in serialized
    assert summary["result"] == {
        "clean": False,
        "finding_count": 1,
        "rule_counts": {"generic-api-key": 1},
    }


def test_clean_summary_binds_exact_checkout(tmp_path: Path) -> None:
    report = _report(tmp_path, [])
    summary = MODULE.build_summary(
        report_path=report,
        source_sha="d" * 40,
        checked_out_sha="d" * 40,
        commit_count=50,
        ref_count=3,
        scanner_version="8.30.1",
        scanner_asset_sha256="e" * 64,
        scanner_exit_code=0,
    )

    assert summary["source"]["exact_checkout_verified"] is True
    assert summary["result"]["clean"] is True
    assert summary["result"]["finding_count"] == 0
    assert summary["coverage"]["git_log_opts"] == "--all"


def test_summary_rejects_checkout_mismatch(tmp_path: Path) -> None:
    report = _report(tmp_path, [])
    with pytest.raises(ValueError, match="checked-out revision"):
        MODULE.build_summary(
            report_path=report,
            source_sha="f" * 40,
            checked_out_sha="0" * 40,
            commit_count=10,
            ref_count=2,
            scanner_version="8.30.1",
            scanner_asset_sha256="1" * 64,
            scanner_exit_code=0,
        )


def test_summary_rejects_inconsistent_scanner_result(tmp_path: Path) -> None:
    report = _report(tmp_path, [{"RuleID": "generic-api-key"}])
    with pytest.raises(ValueError, match="success while findings are present"):
        MODULE.build_summary(
            report_path=report,
            source_sha="2" * 40,
            checked_out_sha="2" * 40,
            commit_count=10,
            ref_count=2,
            scanner_version="8.30.1",
            scanner_asset_sha256="3" * 64,
            scanner_exit_code=0,
        )
