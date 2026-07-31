"""Cross-platform full-suite evidence and parity comparison for Product Readiness Phase 4."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_FILENAME = "phase4-portability-evidence.json"
CHECKSUM_FILENAME = "SHA256SUMS"
TRACEBACK_MARKER = b"phase4-traceback-secret-marker-32-bytes!!"


class PortabilityEvidenceError(RuntimeError):
    """Fail-closed Phase 4 evidence error."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _command_output(command: list[str]) -> str | None:
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return completed.stdout.strip()


def _git_identity() -> dict[str, str | None]:
    return {
        "commit_sha": _command_output(["git", "rev-parse", "HEAD"]),
        "tree_sha": _command_output(["git", "rev-parse", "HEAD^{tree}"]),
    }


def _canonical_path(value: str | os.PathLike[str]) -> str:
    return os.path.normcase(os.path.realpath(os.fspath(value)))


def traceback_redaction_invariant() -> dict[str, Any]:
    """Exercise the real proof-handoff constructor and inspect only its real source frames."""

    from toxicjoin.agent import proof_handoff as proof_handoff_module
    from toxicjoin.agent.proof_handoff import (
        AgentProofHandoffAuthorityError,
        DataHubAgentProofHandoffAuthority,
    )

    try:
        DataHubAgentProofHandoffAuthority(
            integrity_key=TRACEBACK_MARKER,
            provenance_integrity_key=TRACEBACK_MARKER,
        )
    except AgentProofHandoffAuthorityError as error:
        target_file = proof_handoff_module.__file__
        if target_file is None:
            raise PortabilityEvidenceError("proof_handoff module has no source filename")
        target = _canonical_path(target_file)
        marker_text = TRACEBACK_MARKER.decode("ascii")
        frames: list[dict[str, Any]] = []
        traceback = error.__traceback__
        while traceback is not None:
            frame = traceback.tb_frame
            if _canonical_path(frame.f_code.co_filename) == target:
                rendered = "\n".join(repr(value) for value in frame.f_locals.values())
                frames.append(
                    {
                        "function": frame.f_code.co_name,
                        "line": traceback.tb_lineno,
                        "filename": Path(frame.f_code.co_filename).name,
                        "locals_keys": sorted(str(key) for key in frame.f_locals),
                        "secret_marker_present": marker_text in rendered,
                    }
                )
            traceback = traceback.tb_next

        passed = (
            error.code == "AGENT_PROOF_INTEGRITY_KEY_INVALID"
            and error.__context__ is None
            and error.__cause__ is None
            and len(frames) >= 1
            and any(item["function"] == "__init__" for item in frames)
            and not any(item["secret_marker_present"] for item in frames)
        )
        return {
            "passed": passed,
            "error_code": error.code,
            "context_is_none": error.__context__ is None,
            "cause_is_none": error.__cause__ is None,
            "target_frame_count": len(frames),
            "target_functions": [item["function"] for item in frames],
            "frames": frames,
        }
    raise PortabilityEvidenceError("proof-handoff constructor unexpectedly succeeded")


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_junit(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise PortabilityEvidenceError(f"JUnit report missing: {path}")
    root = ET.parse(path).getroot()
    testcases = [element for element in root.iter() if _local_name(element.tag) == "testcase"]
    outcomes: list[str] = []
    inventory: list[str] = []
    counts = {"passed": 0, "failed": 0, "errors": 0, "skipped": 0}

    for case in testcases:
        filename = (case.attrib.get("file") or case.attrib.get("classname") or "unknown").replace(
            "\\", "/"
        )
        name = case.attrib.get("name") or "unknown"
        case_id = f"{filename}::{name}"
        child_names = {_local_name(child.tag) for child in case}
        if "failure" in child_names:
            outcome = "failed"
        elif "error" in child_names:
            outcome = "error"
        elif "skipped" in child_names:
            outcome = "skipped"
        else:
            outcome = "passed"
        counts["errors" if outcome == "error" else outcome] += 1
        inventory.append(case_id)
        outcomes.append(f"{case_id}={outcome}")

    inventory.sort()
    outcomes.sort()
    return {
        "tests": len(testcases),
        **counts,
        "inventory_sha256": _sha256_bytes(("\n".join(inventory) + "\n").encode("utf-8")),
        "outcomes_sha256": _sha256_bytes(("\n".join(outcomes) + "\n").encode("utf-8")),
        "inventory": inventory,
        "outcomes": outcomes,
    }


def _run_pytest(log_path: Path, junit_path: Path) -> tuple[int, list[str]]:
    command = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "--junitxml",
        str(junit_path),
    ]
    with log_path.open("w", encoding="utf-8", newline="\n") as log:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert process.stdout is not None
        for line in process.stdout:
            sys.stdout.write(line)
            log.write(line)
        return process.wait(), command


def _worktree_status() -> dict[str, Any]:
    output = _command_output(["git", "status", "--porcelain=v1", "--untracked-files=all"])
    entries = [] if not output else output.splitlines()
    unexpected = [entry for entry in entries if ".toxicjoin/phase4-" not in entry.replace("\\", "/")]
    return {"clean": not unexpected, "entries": entries, "unexpected_entries": unexpected}


def run_suite(output_dir: Path) -> int:
    output_dir.mkdir(parents=True, exist_ok=True)
    log_path = output_dir / "pytest.log"
    junit_path = output_dir / "pytest-junit.xml"
    return_code, command = _run_pytest(log_path, junit_path)
    junit = parse_junit(junit_path)
    traceback = traceback_redaction_invariant()
    worktree = _worktree_status()
    version = platform.python_version()
    evidence = {
        "schema_version": "1.0",
        "phase": "Phase 4 - Windows Portability and Toolchain Parity",
        "generated_at": _now(),
        "git": _git_identity(),
        "environment": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "os_name": os.name,
            "path_separator": os.sep,
            "python_version": version,
            "python_minor": ".".join(version.split(".")[:2]),
            "python_executable": sys.executable,
        },
        "pytest": {
            "command": command,
            "return_code": return_code,
            **junit,
        },
        "traceback_secret_redaction": traceback,
        "worktree": worktree,
    }
    evidence_path = output_dir / EVIDENCE_FILENAME
    _write_json(evidence_path, evidence)
    checksum_targets = [log_path, junit_path, evidence_path]
    checksums = "".join(f"{_sha256_file(path)}  {path.name}\n" for path in checksum_targets)
    (output_dir / CHECKSUM_FILENAME).write_text(checksums, encoding="utf-8", newline="\n")

    passed = (
        return_code == 0
        and junit["failed"] == 0
        and junit["errors"] == 0
        and traceback["passed"]
        and worktree["clean"]
    )
    return 0 if passed else 1


def _load_evidence(input_dir: Path) -> list[dict[str, Any]]:
    paths = sorted(input_dir.rglob(EVIDENCE_FILENAME))
    if not paths:
        raise PortabilityEvidenceError(f"no {EVIDENCE_FILENAME} files under {input_dir}")
    return [json.loads(path.read_text(encoding="utf-8")) for path in paths]


def compare_evidence(input_dir: Path, output_dir: Path) -> int:
    records = _load_evidence(input_dir)
    grouped: dict[str, dict[str, dict[str, Any]]] = {}
    for record in records:
        system = record["environment"]["system"]
        if system not in {"Linux", "Windows"}:
            continue
        minor = record["environment"]["python_minor"]
        if system in grouped.setdefault(minor, {}):
            raise PortabilityEvidenceError(f"duplicate {system} evidence for Python {minor}")
        grouped[minor][system] = record

    comparisons: list[dict[str, Any]] = []
    overall = True
    for minor in ("3.11", "3.12"):
        pair = grouped.get(minor, {})
        linux = pair.get("Linux")
        windows = pair.get("Windows")
        if linux is None or windows is None:
            comparisons.append(
                {"python_minor": minor, "passed": False, "reason": "missing Linux/Windows pair"}
            )
            overall = False
            continue
        linux_pytest = linux["pytest"]
        windows_pytest = windows["pytest"]
        checks = {
            "git_tree_match": linux["git"]["tree_sha"] == windows["git"]["tree_sha"],
            "inventory_match": (
                linux_pytest["inventory_sha256"] == windows_pytest["inventory_sha256"]
            ),
            "outcomes_match": linux_pytest["outcomes_sha256"] == windows_pytest["outcomes_sha256"],
            "counts_match": all(
                linux_pytest[key] == windows_pytest[key]
                for key in ("tests", "passed", "failed", "errors", "skipped")
            ),
            "linux_suite_passed": linux_pytest["return_code"] == 0,
            "windows_suite_passed": windows_pytest["return_code"] == 0,
            "linux_traceback_invariant": linux["traceback_secret_redaction"]["passed"],
            "windows_traceback_invariant": windows["traceback_secret_redaction"]["passed"],
            "linux_target_frames_real": (
                linux["traceback_secret_redaction"]["target_frame_count"] >= 1
            ),
            "windows_target_frames_real": (
                windows["traceback_secret_redaction"]["target_frame_count"] >= 1
            ),
            "linux_worktree_clean": linux["worktree"]["clean"],
            "windows_worktree_clean": windows["worktree"]["clean"],
        }
        passed = all(checks.values())
        overall = overall and passed
        comparisons.append(
            {
                "python_minor": minor,
                "passed": passed,
                "checks": checks,
                "linux": {
                    "python_version": linux["environment"]["python_version"],
                    "pytest": {
                        key: linux_pytest[key]
                        for key in (
                            "tests",
                            "passed",
                            "failed",
                            "errors",
                            "skipped",
                            "inventory_sha256",
                            "outcomes_sha256",
                        )
                    },
                    "target_frame_count": linux["traceback_secret_redaction"][
                        "target_frame_count"
                    ],
                },
                "windows": {
                    "python_version": windows["environment"]["python_version"],
                    "pytest": {
                        key: windows_pytest[key]
                        for key in (
                            "tests",
                            "passed",
                            "failed",
                            "errors",
                            "skipped",
                            "inventory_sha256",
                            "outcomes_sha256",
                        )
                    },
                    "target_frame_count": windows["traceback_secret_redaction"][
                        "target_frame_count"
                    ],
                },
            }
        )

    output_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "schema_version": "1.0",
        "phase": "Phase 4 - Windows Portability and Toolchain Parity",
        "generated_at": _now(),
        "passed": overall,
        "evidence_records": len(records),
        "comparisons": comparisons,
    }
    report_path = output_dir / "phase4-parity-comparison.json"
    _write_json(report_path, report)
    (output_dir / CHECKSUM_FILENAME).write_text(
        f"{_sha256_file(report_path)}  {report_path.name}\n",
        encoding="utf-8",
        newline="\n",
    )
    return 0 if overall else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser("run-suite")
    run_parser.add_argument("--output-dir", type=Path, required=True)
    compare_parser = subparsers.add_parser("compare")
    compare_parser.add_argument("--input-dir", type=Path, required=True)
    compare_parser.add_argument("--output-dir", type=Path, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "run-suite":
        return run_suite(args.output_dir)
    if args.command == "compare":
        return compare_evidence(args.input_dir, args.output_dir)
    raise PortabilityEvidenceError(f"unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
