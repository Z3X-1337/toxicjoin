from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "toxicjoin_phase4_portability", ROOT / "scripts" / "phase4_portability.py"
)
assert SPEC is not None and SPEC.loader is not None
PORTABILITY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PORTABILITY
SPEC.loader.exec_module(PORTABILITY)


def test_canonical_path_normalizes_windows_and_posix_separators(monkeypatch) -> None:
    monkeypatch.setattr(PORTABILITY.os.path, "realpath", lambda value: str(value).replace("\\", "/"))
    monkeypatch.setattr(PORTABILITY.os.path, "normcase", lambda value: value.lower())
    assert PORTABILITY._canonical_path(r"C:\Repo\src\toxicjoin\agent\proof_handoff.py") == (
        "c:/repo/src/toxicjoin/agent/proof_handoff.py"
    )


def test_parse_junit_produces_stable_inventory_and_outcomes(tmp_path: Path) -> None:
    junit = tmp_path / "pytest-junit.xml"
    junit.write_text(
        """<?xml version='1.0' encoding='utf-8'?>
<testsuites><testsuite tests='2' failures='0' errors='0' skipped='1'>
<testcase classname='tests.test_alpha' name='test_pass' file='tests/test_alpha.py' />
<testcase classname='tests.test_beta' name='test_skip' file='tests\\test_beta.py'>
<skipped type='pytest.skip' message='documented' />
</testcase></testsuite></testsuites>
""",
        encoding="utf-8",
    )
    result = PORTABILITY.parse_junit(junit)
    assert result["tests"] == 2
    assert result["passed"] == 1
    assert result["skipped"] == 1
    assert result["failed"] == 0
    assert result["errors"] == 0
    assert all("\\" not in item for item in result["inventory"])


def _record(system: str, version: str, inventory: str, outcomes: str) -> dict:
    return {
        "git": {"tree_sha": "tree"},
        "environment": {
            "system": system,
            "python_version": version,
            "python_minor": ".".join(version.split(".")[:2]),
        },
        "pytest": {
            "return_code": 0,
            "tests": 2,
            "passed": 2,
            "failed": 0,
            "errors": 0,
            "skipped": 0,
            "inventory_sha256": inventory,
            "outcomes_sha256": outcomes,
        },
        "traceback_secret_redaction": {"passed": True, "target_frame_count": 1},
        "worktree": {"clean": True},
    }


def test_compare_evidence_requires_exact_linux_windows_parity(tmp_path: Path) -> None:
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    for system, version in (
        ("Linux", "3.11.15"),
        ("Windows", "3.11.9"),
        ("Linux", "3.12.13"),
        ("Windows", "3.12.10"),
    ):
        target = input_dir / f"{system}-{version}"
        target.mkdir(parents=True)
        (target / PORTABILITY.EVIDENCE_FILENAME).write_text(
            json.dumps(_record(system, version, "inventory", "outcomes")),
            encoding="utf-8",
        )
    assert PORTABILITY.compare_evidence(input_dir, output_dir) == 0
    report = json.loads((output_dir / "phase4-parity-comparison.json").read_text())
    assert report["passed"] is True


def test_compare_evidence_fails_on_outcome_drift(tmp_path: Path) -> None:
    input_dir = tmp_path / "input"
    output_dir = tmp_path / "output"
    records = [
        _record("Linux", "3.11.15", "inventory", "outcomes"),
        _record("Windows", "3.11.9", "inventory", "different"),
        _record("Linux", "3.12.13", "inventory", "outcomes"),
        _record("Windows", "3.12.10", "inventory", "outcomes"),
    ]
    for index, record in enumerate(records):
        target = input_dir / str(index)
        target.mkdir(parents=True)
        (target / PORTABILITY.EVIDENCE_FILENAME).write_text(
            json.dumps(record), encoding="utf-8"
        )
    assert PORTABILITY.compare_evidence(input_dir, output_dir) == 1
