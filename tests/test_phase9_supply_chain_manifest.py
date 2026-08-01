from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import generate_release_manifest_v3 as V3  # noqa: E402
import phase9_supply_chain_manifest as PHASE9  # noqa: E402
import release_manifest_artifacts as ARTIFACTS  # noqa: E402


@pytest.fixture(autouse=True)
def restore_supply_chain_gate() -> Iterator[None]:
    original = ARTIFACTS.GATE_SPECS[PHASE9.WORKFLOW_NAME]
    yield
    ARTIFACTS.GATE_SPECS[PHASE9.WORKFLOW_NAME] = original


def test_candidate_keeps_dependency_review_artifact_required() -> None:
    original = ARTIFACTS.GATE_SPECS[PHASE9.WORKFLOW_NAME]

    PHASE9.install_phase9_supply_chain_gate(mode="candidate")

    assert ARTIFACTS.GATE_SPECS[PHASE9.WORKFLOW_NAME] == original
    assert PHASE9.DEPENDENCY_REVIEW_ARTIFACT in original.required_artifacts


def test_release_excludes_only_pr_range_artifact() -> None:
    original = ARTIFACTS.GATE_SPECS[PHASE9.WORKFLOW_NAME]

    PHASE9.install_phase9_supply_chain_gate(mode="release")

    release = ARTIFACTS.GATE_SPECS[PHASE9.WORKFLOW_NAME]
    assert release.validator is original.validator
    assert release.required_jobs == original.required_jobs
    assert release.required_artifacts == tuple(
        name
        for name in original.required_artifacts
        if name != PHASE9.DEPENDENCY_REVIEW_ARTIFACT
    )
    assert set(release.required_artifacts) == {
        "web-supply-chain",
        "hosted-replay-supply-chain",
        "python-supply-chain-agent-registry",
        "python-supply-chain-datahub",
    }


def test_release_claim_records_non_applicability_and_rehashes() -> None:
    manifest = {
        "schema_version": "2.1",
        "claim_boundaries": {},
        "manifest_sha256": "0" * 64,
    }

    result = PHASE9.decorate_phase9_supply_chain_claim(
        manifest,
        mode="release",
    )

    assert result["claim_boundaries"] == {
        "dependency_review_candidate_artifact_required": True,
        "dependency_review_exact_main_applicability": (
            "not-applicable-without-pull-request-range"
        ),
    }
    claimed = result.pop("manifest_sha256")
    assert claimed == ARTIFACTS.canonical_sha256(result)


def test_candidate_claim_does_not_pretend_main_review_exists() -> None:
    manifest = {"claim_boundaries": {}}

    result = PHASE9.decorate_phase9_supply_chain_claim(
        manifest,
        mode="candidate",
    )

    assert (
        result["claim_boundaries"]["dependency_review_exact_main_applicability"]
        == "pending-merge"
    )


def test_mode_parser_is_explicit_and_fail_closed() -> None:
    assert V3._manifest_mode(["--mode", "candidate"]) == "candidate"
    assert V3._manifest_mode(["--mode=release"]) == "release"
    with pytest.raises(ValueError, match="--mode is required"):
        V3._manifest_mode([])
    with pytest.raises(ValueError, match="requires a value"):
        V3._manifest_mode(["--mode"])
    with pytest.raises(ValueError, match="unsupported"):
        PHASE9.install_phase9_supply_chain_gate(mode="other")
