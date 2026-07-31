from __future__ import annotations

import hashlib
import io
import json
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import phase8_release_manifest as RELEASE  # noqa: E402
import release_manifest_artifacts as ARTIFACTS  # noqa: E402


def zip_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def artifact_bundle(name: str, files: dict[str, bytes]) -> ARTIFACTS.ArtifactBundle:
    data = zip_bytes(files)
    metadata: dict[str, Any] = {
        "id": 1,
        "name": name,
        "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
        "expired": False,
        "size_in_bytes": len(data),
        "created_at": "2026-08-01T00:00:00Z",
        "expires_at": "2026-10-30T00:00:00Z",
    }
    return ARTIFACTS.build_artifact_bundle(metadata, data)


def test_release_manifest_validator_requires_durable_retrieval() -> None:
    source_sha = "c" * 40
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "status": "verified",
        "source": {
            "source_sha": source_sha,
            "checked_out_sha": source_sha,
            "exact_checkout_verified": True,
        },
        "retention": {
            "storage_backend": "git-content-addressed",
            "independent_of_actions_expiry": True,
            "catalog_sha256": "d" * 64,
            "object_count": 4,
            "lifecycle_classes": ["current", "historical"],
            "purpose_classes": [
                "operational",
                "preview",
                "replay-only",
                "submission",
            ],
            "large_binary_policy": "digest-indexed-release-asset-in-phase9",
            "immutable_release_created": False,
        },
        "retrieval": {
            "requested_sha256": "e" * 64,
            "retrieved_sha256": "e" * 64,
            "verified": True,
        },
    }
    payload["report_sha256"] = ARTIFACTS.canonical_sha256(payload)
    report_raw = json.dumps(payload, sort_keys=True).encode()
    sums = hashlib.sha256(report_raw).hexdigest() + "  phase8-retention-proof.json\n"
    bundle = artifact_bundle(
        RELEASE.ARTIFACT_NAME,
        {
            "phase8-retention-proof.json": report_raw,
            "SHA256SUMS": sums.encode(),
        },
    )
    result = RELEASE.validate_phase8({RELEASE.ARTIFACT_NAME: bundle}, source_sha)
    assert result["retrieval_verified"] is True
    payload["retrieval"]["retrieved_sha256"] = "f" * 64
    payload["report_sha256"] = ARTIFACTS.canonical_sha256(
        {key: value for key, value in payload.items() if key != "report_sha256"}
    )
    invalid_raw = json.dumps(payload, sort_keys=True).encode()
    invalid_sums = hashlib.sha256(invalid_raw).hexdigest()
    invalid = artifact_bundle(
        RELEASE.ARTIFACT_NAME,
        {
            "phase8-retention-proof.json": invalid_raw,
            "SHA256SUMS": (
                invalid_sums + "  phase8-retention-proof.json\n"
            ).encode(),
        },
    )
    with pytest.raises(ValueError, match="digest mismatch"):
        RELEASE.validate_phase8({RELEASE.ARTIFACT_NAME: invalid}, source_sha)


def test_phase8_generator_installs_gate_in_isolated_process() -> None:
    code = """
import release_manifest_artifacts as artifacts
from phase8_release_manifest import install_phase8_gate
install_phase8_gate()
import release_manifest_gate as gate
assert gate.REQUIRED_WORKFLOWS[-1] == 'Phase 8 Durable Evidence Retention'
assert len(gate.REQUIRED_WORKFLOWS) == 12
assert 'Phase 8 Durable Evidence Retention' in artifacts.GATE_SPECS
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        env={"PYTHONPATH": str(SCRIPTS)},
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr


def test_phase5_retention_trigger_is_non_secret() -> None:
    from phase5_retention_policy import phase5_retention_claim

    claim = phase5_retention_claim()
    assert claim["credential_reflection_limit"] == 0
    assert claim["raw_credentials_retained"] is False
