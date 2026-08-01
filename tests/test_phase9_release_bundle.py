from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PHASE9_WORKFLOW = ROOT / ".github/workflows/phase9-immutable-release.yml"
GENERATED_MANIFEST_WORKFLOW = ROOT / ".github/workflows/generated-release-manifest.yml"
sys.path.insert(0, str(ROOT / "scripts"))

import phase9_release_bundle as bundle  # noqa: E402
import phase9_release_verify as verify  # noqa: E402


def test_phase9_config_matches_project_version() -> None:
    config = bundle.load_json(ROOT / "config/phase9-release.json")
    bundle.validate_config(config, ROOT)
    assert config["tag"] == "v0.1.0"
    assert len(config["required_sboms"]) == 4


def test_templates_preserve_truth_boundaries() -> None:
    notes = (ROOT / "docs/releases/v0.1.0.md").read_text(encoding="utf-8")
    for term in ("SINGLE_NODE", "PostgreSQL", "Replay", "Devpost"):
        assert term in notes
    assert "{{SOURCE_SHA}}" in notes
    assert "{{MANIFEST_SHA256}}" in notes


def test_safe_zip_rejects_path_traversal(tmp_path: Path) -> None:
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as handle:
        handle.writestr("../sbom.cdx.json", b"{}")
    with pytest.raises(ValueError, match="unsafe ZIP member"):
        bundle.safe_read_member(archive, "sbom.cdx.json")


def test_cyclonedx_requires_components() -> None:
    bad = json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": []}).encode()
    with pytest.raises(ValueError, match="no components"):
        bundle.validate_sbom(bad, "bad.cdx.json")


def test_release_verifier_binds_annotated_tag_and_assets(tmp_path: Path) -> None:
    asset = tmp_path / "release-manifest.json"
    asset.write_text("{}\n", encoding="utf-8")
    digest = hashlib.sha256(asset.read_bytes()).hexdigest()
    (tmp_path / "SHA256SUMS").write_text(f"{digest}  {asset.name}\n", encoding="utf-8")
    source = "a" * 40
    manifest = "b" * 64
    config = {"tag": "v0.1.0", "release_name": "ToxicJoin v0.1.0"}
    release = {
        "id": 1,
        "html_url": "https://example.invalid/release",
        "tag_name": "v0.1.0",
        "name": "ToxicJoin v0.1.0",
        "draft": False,
        "prerelease": False,
        "body": f"{source} {manifest} SINGLE_NODE PostgreSQL Replay",
        "assets": [{"name": "release-manifest.json"}, {"name": "SHA256SUMS"}],
    }
    ref = {"object": {"type": "tag", "sha": "c" * 40}}
    tag_object = {"object": {"type": "commit", "sha": source}}
    report = verify.verify(
        config=config, release=release, ref=ref, tag_object=tag_object,
        asset_dir=tmp_path, source_sha=source, manifest_sha256=manifest,
    )
    assert report["status"] == "verified"
    assert report["tag_resolved_sha"] == source


def test_exact_main_publisher_accepts_nested_workflow_run_only() -> None:
    phase9 = PHASE9_WORKFLOW.read_text(encoding="utf-8")
    generated = GENERATED_MANIFEST_WORKFLOW.read_text(encoding="utf-8")

    publisher = phase9.split("  publish-and-verify-release:\n", 1)[1]
    publisher_condition = publisher.split("    runs-on:", 1)[0]
    release_manifest = generated.split("  release-manifest:\n", 1)[1]
    release_manifest_condition = release_manifest.split("    runs-on:", 1)[0]

    assert 'workflows: ["Generated Release Manifest"]' in phase9
    assert "github.event_name == 'workflow_run'" in publisher_condition
    assert "github.event.workflow_run.event == 'workflow_run'" in publisher_condition
    assert "github.event.workflow_run.event == 'push'" not in publisher_condition

    assert 'workflows: ["Ground Truth Baseline"]' in generated
    assert "github.event.workflow_run.event == 'push'" in release_manifest_condition
