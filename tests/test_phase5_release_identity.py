from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from phase5_release_identity import validate_live_datahub_release_gate  # noqa: E402


def _manifest(source_sha: str) -> dict[str, object]:
    return {
        "gates": {
            "Phase 5 Exact-SHA Live DataHub Evidence": {
                "status": "verified",
                "run": {"head_sha": source_sha},
                "verified_claims": {
                    "live_datahub_verified": True,
                    "credential_reflections": 0,
                    "evidence_index_sha256": "a" * 64,
                },
            }
        }
    }


def test_release_identity_accepts_exact_clean_live_datahub_gate() -> None:
    source_sha = "b" * 40
    claims = validate_live_datahub_release_gate(_manifest(source_sha), source_sha)
    assert claims["credential_reflections"] == 0


def test_release_identity_rejects_stale_or_reflective_evidence() -> None:
    source_sha = "b" * 40
    with pytest.raises(ValueError, match="release SHA"):
        validate_live_datahub_release_gate(_manifest(source_sha), "c" * 40)
    manifest = _manifest(source_sha)
    manifest["gates"]["Phase 5 Exact-SHA Live DataHub Evidence"]["verified_claims"][
        "credential_reflections"
    ] = 1
    with pytest.raises(ValueError, match="credential reflections"):
        validate_live_datahub_release_gate(manifest, source_sha)
