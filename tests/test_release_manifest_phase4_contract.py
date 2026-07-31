from __future__ import annotations

import hashlib
import io
import json
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import generate_release_manifest_v2 as MANIFEST_V2  # noqa: E402
import release_manifest_artifacts as ARTIFACTS  # noqa: E402


def zip_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def bundle(name: str, files: dict[str, bytes]) -> ARTIFACTS.ArtifactBundle:
    checksums = "".join(
        f"{hashlib.sha256(data).hexdigest()}  {path}\n"
        for path, data in files.items()
    ).encode()
    archive_files = dict(files)
    archive_files["SHA256SUMS"] = checksums
    data = zip_bytes(archive_files)
    metadata: dict[str, Any] = {
        "id": 1,
        "name": name,
        "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
        "expired": False,
        "size_in_bytes": len(data),
        "created_at": "2026-07-31T00:00:00Z",
        "expires_at": "2026-08-30T00:00:00Z",
    }
    return ARTIFACTS.build_artifact_bundle(metadata, data)


def native_report(source_sha: str, *, clean: bool = True) -> bytes:
    return json.dumps(
        {
            "schema_version": "1.0",
            "git": {"commit_sha": source_sha, "tree_sha": "1" * 40},
            "environment": {"python_version": "3.12.13", "system": "Linux"},
            "pytest": {"passed": 865, "failed": 0, "errors": 0, "skipped": 0},
            "traceback_secret_redaction": {"passed": True},
            "worktree": {"clean": clean},
        },
        indent=2,
    ).encode()


def parity_report() -> bytes:
    return json.dumps(
        {
            "schema_version": "1.0",
            "passed": True,
            "comparisons": [
                {"passed": True, "checks": {"inventory": True, "outcomes": True}},
                {"passed": True, "checks": {"inventory": True, "outcomes": True}},
            ],
        },
        indent=2,
    ).encode()


def phase4_bundles(source_sha: str, *, clean: bool = True) -> dict[str, ARTIFACTS.ArtifactBundle]:
    bundles = {
        "phase4-portability-parity": bundle(
            "phase4-portability-parity",
            {"phase4-parity-comparison.json": parity_report()},
        )
    }
    for name in (
        "phase4-portability-ubuntu-24.04-python-3.11.15",
        "phase4-portability-ubuntu-24.04-python-3.12.13",
        "phase4-portability-windows-2025-python-3.11.9",
        "phase4-portability-windows-2025-python-3.12.10",
    ):
        bundles[name] = bundle(
            name,
            {"phase4-portability-evidence.json": native_report(source_sha, clean=clean)},
        )
    return bundles


def test_phase4_validator_accepts_exact_source_emitted_schema() -> None:
    source_sha = "a" * 40
    result = MANIFEST_V2.validate_phase4_authoritative(
        phase4_bundles(source_sha),
        source_sha,
    )
    assert result["native_artifact_count"] == 4
    assert result["comparison_count"] == 2
    assert all(item["passed"] == 865 for item in result["native"])


def test_phase4_validator_rejects_dirty_native_worktree() -> None:
    source_sha = "b" * 40
    with pytest.raises(ValueError, match="dirty worktree"):
        MANIFEST_V2.validate_phase4_authoritative(
            phase4_bundles(source_sha, clean=False),
            source_sha,
        )
