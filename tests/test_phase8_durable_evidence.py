from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import phase8_durable_evidence as DURABLE  # noqa: E402

CATALOG = ROOT / "evidence/retained/catalog.json"


def test_content_addressed_json_is_forced_to_lf() -> None:
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8").splitlines()
    assert "config/phase8-evidence-retention.json text eol=lf" in attributes
    assert "evidence/retained/**/*.json text eol=lf" in attributes


def test_committed_catalog_is_content_addressed_and_complete() -> None:
    verified = DURABLE.verify_catalog(root=ROOT, catalog_path=CATALOG)
    assert verified.payload["store"]["independent_of_actions_expiry"] is True
    assert len(verified.objects) >= 4
    assert {item.lifecycle for item in verified.objects} == {"current", "historical"}
    assert {item.purpose for item in verified.objects} == {
        "operational",
        "preview",
        "replay-only",
        "submission",
    }


def test_retrieval_from_empty_destination_preserves_digest(tmp_path: Path) -> None:
    verified = DURABLE.verify_catalog(root=ROOT, catalog_path=CATALOG)
    digest = verified.payload["primary_retrieval_sha256"]
    destination = tmp_path / "fresh" / f"{digest}.json"
    item = DURABLE.retrieve_object(
        catalog=verified,
        digest=digest,
        destination=destination,
    )
    assert destination.is_file()
    assert hashlib.sha256(destination.read_bytes()).hexdigest() == item.digest


def test_catalog_tampering_fails_closed(tmp_path: Path) -> None:
    store = tmp_path / "repo"
    source = ROOT / "evidence/retained"
    target = store / "evidence/retained"
    target.parent.mkdir(parents=True)
    import shutil

    shutil.copytree(source, target)
    catalog_path = target / "catalog.json"
    payload = json.loads(catalog_path.read_text(encoding="utf-8"))
    entry = payload["entries"][0]
    object_path = store / entry["path"]
    object_path.write_bytes(object_path.read_bytes() + b"tamper")
    with pytest.raises(ValueError, match="size mismatch|digest mismatch"):
        DURABLE.verify_catalog(root=store, catalog_path=catalog_path)


def test_proof_report_binds_exact_checkout_and_self_hash(tmp_path: Path) -> None:
    verified = DURABLE.verify_catalog(root=ROOT, catalog_path=CATALOG)
    digest = verified.payload["primary_retrieval_sha256"]
    destination = tmp_path / f"{digest}.json"
    item = DURABLE.retrieve_object(
        catalog=verified,
        digest=digest,
        destination=destination,
    )
    source_sha = "a" * 40
    report = DURABLE.build_proof_report(
        source_sha=source_sha,
        checked_out_sha=source_sha,
        catalog=verified,
        retrieved=item,
        retrieved_path=destination,
        command="phase8-test",
        generated_at="2026-08-01T00:00:00Z",
    )
    claimed = report.pop("report_sha256")
    assert DURABLE.sha256_bytes(DURABLE.canonical_json_bytes(report)) == claimed
    assert report["retention"]["storage_backend"] == "git-content-addressed"
    assert report["retrieval"]["verified"] is True
    with pytest.raises(ValueError, match="does not match"):
        DURABLE.build_proof_report(
            source_sha="a" * 40,
            checked_out_sha="b" * 40,
            catalog=verified,
            retrieved=item,
            retrieved_path=destination,
            command="phase8-test",
        )
