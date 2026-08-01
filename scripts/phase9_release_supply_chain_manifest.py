from __future__ import annotations

from typing import Any

from release_manifest_artifacts import GATE_SPECS, GateSpec, canonical_sha256

WORKFLOW_NAME = "Supply Chain Security"
DEPENDENCY_REVIEW_ARTIFACT = "dependency-review-api-status"


def install_phase9_supply_chain_gate(*, mode: str) -> None:
    """Make the PR-only dependency-review artifact explicit by manifest mode.

    GitHub's Dependency Review API compares a pull-request base/head range. A
    push to main has no pull-request range, so the artifact is required for a
    candidate manifest and intentionally non-applicable for an exact-main
    release manifest. All exact-lock audits and SBOM artifacts remain required
    in both modes.
    """
    spec = GATE_SPECS[WORKFLOW_NAME]
    required = spec.required_artifacts
    if mode == "release":
        required = tuple(
            name for name in required if name != DEPENDENCY_REVIEW_ARTIFACT
        )
    elif mode != "candidate":
        raise ValueError(f"unsupported release manifest mode: {mode!r}")

    GATE_SPECS[WORKFLOW_NAME] = GateSpec(
        required_artifacts=required,
        validator=spec.validator,
        required_jobs=spec.required_jobs,
    )


def decorate_phase9_supply_chain_claim(
    manifest: dict[str, Any],
    *,
    mode: str,
) -> dict[str, Any]:
    boundaries = manifest.get("claim_boundaries")
    if not isinstance(boundaries, dict):
        raise ValueError("release manifest claim boundaries are missing")

    boundaries["dependency_review_candidate_artifact_required"] = True
    if mode == "candidate":
        boundaries["dependency_review_exact_main_applicability"] = "pending-merge"
    elif mode == "release":
        boundaries["dependency_review_exact_main_applicability"] = (
            "not-applicable-without-pull-request-range"
        )
    else:
        raise ValueError(f"unsupported release manifest mode: {mode!r}")

    manifest.pop("manifest_sha256", None)
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    return manifest
