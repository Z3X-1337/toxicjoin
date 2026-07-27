from __future__ import annotations

import argparse
import hashlib
import json
import re
import tempfile
from pathlib import Path
from typing import Any

_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_sha(value: str, *, name: str) -> str:
    normalized = value.strip().lower()
    if not _GIT_SHA_RE.fullmatch(normalized):
        raise ValueError(f"{name} must be a full 40-character Git SHA")
    return normalized


def _validate_sha256(value: str, *, name: str) -> str:
    normalized = value.strip().lower()
    if not _SHA256_RE.fullmatch(normalized):
        raise ValueError(f"{name} must be a 64-character SHA-256 digest")
    return normalized


def _read_findings(path: Path) -> list[dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise ValueError("gitleaks report must be a JSON array")
    findings: list[dict[str, Any]] = []
    for item in payload:
        if not isinstance(item, dict):
            raise ValueError("gitleaks finding must be a JSON object")
        findings.append(item)
    return findings


def _sanitized_finding(item: dict[str, Any]) -> dict[str, Any]:
    rule_id = item.get("RuleID")
    file_path = item.get("File")
    commit = item.get("Commit")
    start_line = item.get("StartLine")
    end_line = item.get("EndLine")

    if not isinstance(rule_id, str) or not rule_id:
        raise ValueError("gitleaks finding is missing RuleID")
    if not isinstance(file_path, str) or not file_path:
        raise ValueError("gitleaks finding is missing File")
    if not isinstance(commit, str) or not _GIT_SHA_RE.fullmatch(commit.lower()):
        raise ValueError("gitleaks finding has invalid Commit")
    if not isinstance(start_line, int) or start_line < 1:
        raise ValueError("gitleaks finding has invalid StartLine")
    if not isinstance(end_line, int) or end_line < start_line:
        raise ValueError("gitleaks finding has invalid EndLine")

    return {
        "rule_id": rule_id,
        "file": file_path,
        "commit": commit.lower(),
        "start_line": start_line,
        "end_line": end_line,
    }


def build_summary(
    *,
    report: Path,
    scan_exit_code: int,
    source_sha: str,
    scanner_version: str,
    scanner_archive_sha256: str,
    commit_count: int,
    ref_count: int,
) -> dict[str, Any]:
    source_sha = _validate_sha(source_sha, name="source_sha")
    scanner_archive_sha256 = _validate_sha256(
        scanner_archive_sha256,
        name="scanner_archive_sha256",
    )
    if not scanner_version.strip():
        raise ValueError("scanner_version must not be empty")
    if commit_count < 1:
        raise ValueError("commit_count must be at least 1")
    if ref_count < 1:
        raise ValueError("ref_count must be at least 1")

    findings = _read_findings(report)
    sanitized = [_sanitized_finding(item) for item in findings]

    if scan_exit_code == 0 and findings:
        raise ValueError("gitleaks returned success while reporting findings")
    if scan_exit_code == 1 and not findings:
        raise ValueError("gitleaks reported findings but report is empty")

    if scan_exit_code == 0:
        status = "CLEAN"
    elif scan_exit_code == 1:
        status = "FINDINGS"
    else:
        status = "SCANNER_ERROR"

    return {
        "schema_version": "1.0",
        "source_sha": source_sha,
        "scanner": {
            "name": "gitleaks",
            "version": scanner_version.strip(),
            "archive_sha256": scanner_archive_sha256,
        },
        "git_scope": {
            "log_opts": "--all",
            "commit_count": commit_count,
            "ref_count": ref_count,
        },
        "scan": {
            "exit_code": scan_exit_code,
            "status": status,
            "raw_report_sha256": _sha256_file(report),
            "finding_count": len(sanitized),
            "unique_rule_count": len({item["rule_id"] for item in sanitized}),
            "unique_file_count": len({item["file"] for item in sanitized}),
            "unique_commit_count": len({item["commit"] for item in sanitized}),
            "findings": sanitized,
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
        description="Sanitize Gitleaks full-history output into non-secret release evidence."
    )
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--scan-exit-code", type=int, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--scanner-version", required=True)
    parser.add_argument("--scanner-archive-sha256", required=True)
    parser.add_argument("--commit-count", type=int, required=True)
    parser.add_argument("--ref-count", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    try:
        summary = build_summary(
            report=args.report.resolve(),
            scan_exit_code=args.scan_exit_code,
            source_sha=args.source_sha,
            scanner_version=args.scanner_version,
            scanner_archive_sha256=args.scanner_archive_sha256,
            commit_count=args.commit_count,
            ref_count=args.ref_count,
        )
        _write_atomic(args.output.resolve(), summary)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise SystemExit(f"secret-history summary failed: {error}") from None


if __name__ == "__main__":
    main()
