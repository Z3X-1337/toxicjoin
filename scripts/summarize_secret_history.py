from __future__ import annotations

import argparse
import json
import re
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _validate_hex(value: str, *, pattern: re.Pattern[str], name: str) -> str:
    normalized = value.strip().lower()
    if not pattern.fullmatch(normalized):
        raise ValueError(f"{name} has invalid format")
    return normalized


def _load_report(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("gitleaks report root must be a list")
    findings: list[dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("gitleaks report entries must be objects")
        findings.append(item)
    return findings


def build_summary(
    *,
    report_path: Path,
    source_sha: str,
    checked_out_sha: str,
    commit_count: int,
    ref_count: int,
    scanner_version: str,
    scanner_asset_sha256: str,
    scanner_exit_code: int,
) -> dict[str, Any]:
    source_sha = _validate_hex(source_sha, pattern=_GIT_SHA_RE, name="source_sha")
    checked_out_sha = _validate_hex(
        checked_out_sha,
        pattern=_GIT_SHA_RE,
        name="checked_out_sha",
    )
    if source_sha != checked_out_sha:
        raise ValueError("checked-out revision does not match source revision")
    if commit_count < 1:
        raise ValueError("commit_count must be positive")
    if ref_count < 1:
        raise ValueError("ref_count must be positive")
    scanner_version = scanner_version.strip()
    if not scanner_version:
        raise ValueError("scanner_version is required")
    scanner_asset_sha256 = _validate_hex(
        scanner_asset_sha256,
        pattern=_SHA256_RE,
        name="scanner_asset_sha256",
    )
    if scanner_exit_code < 0 or scanner_exit_code > 255:
        raise ValueError("scanner_exit_code must be in range 0..255")

    findings = _load_report(report_path)
    rule_counts: Counter[str] = Counter()
    for finding in findings:
        rule_id = finding.get("RuleID")
        rule_counts[rule_id if isinstance(rule_id, str) and rule_id else "UNKNOWN"] += 1

    finding_count = len(findings)
    scanner_error = scanner_exit_code not in (0, 1)
    clean = scanner_exit_code == 0 and finding_count == 0
    if scanner_exit_code == 0 and finding_count:
        raise ValueError("scanner reported success while findings are present")
    if scanner_exit_code == 1 and finding_count == 0:
        raise ValueError("scanner reported findings but report is empty")

    return {
        "schema_version": "1.0",
        "source": {
            "source_sha": source_sha,
            "checked_out_sha": checked_out_sha,
            "exact_checkout_verified": True,
        },
        "scanner": {
            "name": "gitleaks",
            "version": scanner_version,
            "asset_sha256": scanner_asset_sha256,
            "exit_code": scanner_exit_code,
            "scanner_error": scanner_error,
        },
        "coverage": {
            "git_log_opts": "--all",
            "commit_count": commit_count,
            "ref_count": ref_count,
        },
        "result": {
            "clean": clean,
            "finding_count": finding_count,
            "rule_counts": dict(sorted(rule_counts.items())),
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
        description="Create a sanitized summary for a full-history Gitleaks scan."
    )
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--checked-out-sha", required=True)
    parser.add_argument("--commit-count", type=int, required=True)
    parser.add_argument("--ref-count", type=int, required=True)
    parser.add_argument("--scanner-version", required=True)
    parser.add_argument("--scanner-asset-sha256", required=True)
    parser.add_argument("--scanner-exit-code", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        summary = build_summary(
            report_path=args.report.resolve(),
            source_sha=args.source_sha,
            checked_out_sha=args.checked_out_sha,
            commit_count=args.commit_count,
            ref_count=args.ref_count,
            scanner_version=args.scanner_version,
            scanner_asset_sha256=args.scanner_asset_sha256,
            scanner_exit_code=args.scanner_exit_code,
        )
        _write_atomic(args.output.resolve(), summary)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"secret-history summary failed: {error}") from None


if __name__ == "__main__":
    main()
