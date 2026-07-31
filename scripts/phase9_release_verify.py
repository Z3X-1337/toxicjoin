from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain an object")
    return value


def resolve_tag_commit(ref: dict[str, Any], tag_object: dict[str, Any] | None) -> str:
    obj = ref.get("object")
    if not isinstance(obj, dict):
        raise ValueError("tag ref object is missing")
    if obj.get("type") == "commit":
        return str(obj.get("sha", ""))
    if obj.get("type") != "tag" or tag_object is None:
        raise ValueError("tag ref does not resolve to a commit or annotated tag")
    target = tag_object.get("object")
    if not isinstance(target, dict) or target.get("type") != "commit":
        raise ValueError("annotated tag does not target a commit")
    return str(target.get("sha", ""))


def verify_checksums(asset_dir: Path) -> dict[str, str]:
    checksum_file = asset_dir / "SHA256SUMS"
    if not checksum_file.is_file():
        raise ValueError("SHA256SUMS is missing")
    verified: dict[str, str] = {}
    for line in checksum_file.read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        if not HEX_64.fullmatch(digest) or Path(name).name != name:
            raise ValueError("invalid SHA256SUMS entry")
        path = asset_dir / name
        if not path.is_file() or sha256_file(path) != digest:
            raise ValueError(f"release asset checksum mismatch: {name}")
        verified[name] = digest
    return verified


def verify(
    *, config: dict[str, Any], release: dict[str, Any], ref: dict[str, Any],
    tag_object: dict[str, Any] | None, asset_dir: Path, source_sha: str,
    manifest_sha256: str,
) -> dict[str, Any]:
    if not HEX_40.fullmatch(source_sha):
        raise ValueError("invalid source SHA")
    resolved = resolve_tag_commit(ref, tag_object)
    if resolved != source_sha:
        raise ValueError("tag does not resolve to the exact release commit")
    if release.get("tag_name") != config.get("tag"):
        raise ValueError("release tag mismatch")
    if release.get("name") != config.get("release_name"):
        raise ValueError("release name mismatch")
    if release.get("draft") is not False or release.get("prerelease") is not False:
        raise ValueError("release is not published stable identity")
    body = str(release.get("body", ""))
    required_text = [source_sha, manifest_sha256, "SINGLE_NODE", "PostgreSQL", "Replay"]
    if any(value not in body for value in required_text):
        raise ValueError("release notes do not bind identity and claim boundaries")
    checksums = verify_checksums(asset_dir)
    expected_names = set(checksums) | {"SHA256SUMS"}
    remote_names = {
        str(item.get("name")) for item in release.get("assets", []) if isinstance(item, dict)
    }
    if remote_names != expected_names:
        raise ValueError("GitHub Release asset set does not match SHA256SUMS")
    report: dict[str, Any] = {
        "schema_version": "1.0",
        "status": "verified",
        "tag": config["tag"],
        "release_name": config["release_name"],
        "source_sha": source_sha,
        "tag_resolved_sha": resolved,
        "manifest_sha256": manifest_sha256,
        "asset_count": len(remote_names),
        "verified_assets": checksums,
        "draft": release["draft"],
        "prerelease": release["prerelease"],
        "release_id": release.get("id"),
        "release_url": release.get("html_url"),
    }
    report["report_sha256"] = hashlib.sha256(canonical_json_bytes(report)).hexdigest()
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--release-json", type=Path, required=True)
    parser.add_argument("--tag-ref-json", type=Path, required=True)
    parser.add_argument("--tag-object-json", type=Path)
    parser.add_argument("--asset-dir", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = verify(
        config=load(args.config), release=load(args.release_json),
        ref=load(args.tag_ref_json),
        tag_object=load(args.tag_object_json) if args.tag_object_json else None,
        asset_dir=args.asset_dir, source_sha=args.source_sha,
        manifest_sha256=args.manifest_sha256,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
