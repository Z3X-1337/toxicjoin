from __future__ import annotations

from typing import Any

from release_manifest_artifacts import (
    ArtifactBundle,
    GATE_SPECS,
    GateSpec,
    json_member,
    sha256_bytes,
    verify_report_self_hash,
    verify_sha256sums,
)

WORKFLOW_NAME = "Phase 8 Durable Evidence Retention"
ARTIFACT_NAME = "phase8-durable-evidence-retention"


def validate_phase8(
    bundles: dict[str, ArtifactBundle],
    source_sha: str,
) -> dict[str, Any]:
    bundle = bundles[ARTIFACT_NAME]
    manifest_entries = verify_sha256sums(bundle)
    payload, raw = json_member(bundle, "phase8-retention-proof.json")
    if payload.get("schema_version") != "1.0" or payload.get("status") != "verified":
        raise ValueError("Phase 8 retention proof schema/status is invalid")
    source = payload.get("source")
    retention = payload.get("retention")
    retrieval = payload.get("retrieval")
    if not isinstance(source, dict) or source.get("source_sha") != source_sha:
        raise ValueError("Phase 8 retention proof source mismatch")
    if source.get("checked_out_sha") != source_sha:
        raise ValueError("Phase 8 retention proof checkout mismatch")
    if source.get("exact_checkout_verified") is not True:
        raise ValueError("Phase 8 exact checkout was not verified")
    if not isinstance(retention, dict):
        raise ValueError("Phase 8 retention summary is missing")
    if retention.get("storage_backend") != "git-content-addressed":
        raise ValueError("Phase 8 retention backend is not durable Git storage")
    if retention.get("independent_of_actions_expiry") is not True:
        raise ValueError("Phase 8 still depends on expiring Actions artifacts")
    if retention.get("large_binary_policy") != "digest-indexed-release-asset-in-phase9":
        raise ValueError("Phase 8 large binary policy is invalid")
    if retention.get("immutable_release_created") is not False:
        raise ValueError("Phase 8 created an immutable release prematurely")
    if set(retention.get("lifecycle_classes", [])) != {"current", "historical"}:
        raise ValueError("Phase 8 lifecycle classification is incomplete")
    if set(retention.get("purpose_classes", [])) != {
        "operational",
        "preview",
        "replay-only",
        "submission",
    }:
        raise ValueError("Phase 8 purpose classification is incomplete")
    if not isinstance(retention.get("object_count"), int) or retention["object_count"] < 4:
        raise ValueError("Phase 8 retained object count is incomplete")
    if not isinstance(retrieval, dict) or retrieval.get("verified") is not True:
        raise ValueError("Phase 8 retrieval proof is missing")
    if retrieval.get("requested_sha256") != retrieval.get("retrieved_sha256"):
        raise ValueError("Phase 8 retrieved object digest mismatch")
    verify_report_self_hash(payload)
    return {
        "retention_report_sha256": sha256_bytes(raw),
        "sha256sums_entries": manifest_entries,
        "storage_backend": "git-content-addressed",
        "independent_of_actions_expiry": True,
        "retained_object_count": retention["object_count"],
        "retrieval_verified": True,
        "catalog_sha256": retention["catalog_sha256"],
        "large_binary_policy": retention["large_binary_policy"],
    }


def install_phase8_gate() -> None:
    GATE_SPECS[WORKFLOW_NAME] = GateSpec(
        required_artifacts=(ARTIFACT_NAME,),
        validator=validate_phase8,
        required_jobs=("retention-proof",),
    )


def decorate_phase8_claim_boundaries(manifest: dict[str, Any]) -> dict[str, Any]:
    boundaries = manifest.get("claim_boundaries")
    if not isinstance(boundaries, dict):
        raise ValueError("release manifest claim boundaries are missing")
    boundaries["phase8_started"] = True
    boundaries["durable_evidence_retention"] = "git-content-addressed"
    boundaries["evidence_independent_of_actions_expiry"] = True
    manifest["schema_version"] = "2.1"
    manifest.pop("manifest_sha256", None)
    from release_manifest_artifacts import canonical_sha256

    manifest["manifest_sha256"] = canonical_sha256(manifest)
    return manifest
