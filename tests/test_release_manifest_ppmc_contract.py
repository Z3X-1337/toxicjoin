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
    data = zip_bytes(files)
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


def ci_bundles(ppmc: dict[str, Any], checksum: str) -> dict[str, ARTIFACTS.ArtifactBundle]:
    benchmark = {
        "schema_version": "1.0",
        "metrics": {
            "total_cases": 30,
            "fully_passed": 30,
            "false_allow_count": 0,
            "unsafe_effective_allow_count": 0,
        },
    }
    return {
        "toxicjoin-benchmark": bundle(
            "toxicjoin-benchmark",
            {"benchmark.json": json.dumps(benchmark).encode()},
        ),
        "toxicjoin-ppmc-hard-gate": bundle(
            "toxicjoin-ppmc-hard-gate",
            {
                "ppmc-hard-gate.json": json.dumps(ppmc, indent=2).encode(),
                "ppmc-hard-gate.sha256": f"{checksum}\n".encode(),
            },
        ),
        "toxicjoin-container-log": bundle(
            "toxicjoin-container-log", {"container.log": b"ready\n"}
        ),
        "pytest-3.11.15": bundle(
            "pytest-3.11.15", {"pytest.log": b"passed\n"}
        ),
        "pytest-3.12.13": bundle(
            "pytest-3.12.13", {"pytest.log": b"passed\n"}
        ),
    }


def test_ppmc_checksum_binds_canonical_payload_without_evidence_field() -> None:
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "gate_passed": True,
        "gate_id": "contract-test",
    }
    evidence_sha = ARTIFACTS.canonical_sha256(payload)
    payload["evidence_sha256"] = evidence_sha

    result = MANIFEST_V2.validate_ci_authoritative(
        ci_bundles(payload, evidence_sha),
        "a" * 40,
    )

    assert result["ppmc_evidence_sha256"] == evidence_sha
    assert result["ppmc_gate_passed"] is True


def test_ppmc_checksum_rejects_raw_pretty_json_hash() -> None:
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "gate_passed": True,
        "gate_id": "contract-test",
    }
    payload["evidence_sha256"] = ARTIFACTS.canonical_sha256(payload)
    raw_pretty_hash = hashlib.sha256(json.dumps(payload, indent=2).encode()).hexdigest()

    with pytest.raises(ValueError, match="detached checksum mismatch"):
        MANIFEST_V2.validate_ci_authoritative(
            ci_bundles(payload, raw_pretty_hash),
            "b" * 40,
        )
