from __future__ import annotations

from typing import Any


def validate_live_datahub_release_gate(manifest: dict[str, Any], source_sha: str) -> dict[str, Any]:
    gate = manifest.get("gates", {}).get("Phase 5 Exact-SHA Live DataHub Evidence")
    if not isinstance(gate, dict) or gate.get("status") != "verified":
        raise ValueError("Phase 5 Live DataHub release gate is missing or unverified")
    run = gate.get("run")
    claims = gate.get("verified_claims")
    if not isinstance(run, dict) or run.get("head_sha") != source_sha:
        raise ValueError("Phase 5 Live DataHub evidence is not bound to the release SHA")
    if not isinstance(claims, dict) or claims.get("live_datahub_verified") is not True:
        raise ValueError("Phase 5 Live DataHub verification claim is missing")
    if claims.get("credential_reflections") != 0:
        raise ValueError("Phase 5 evidence contains credential reflections")
    if not isinstance(claims.get("evidence_index_sha256"), str):
        raise ValueError("Phase 5 evidence index digest is missing")
    return claims
