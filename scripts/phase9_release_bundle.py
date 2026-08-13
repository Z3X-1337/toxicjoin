from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import tomllib
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

HEX_40 = re.compile(r"^[0-9a-f]{40}$")
HEX_64 = re.compile(r"^[0-9a-f]{64}$")


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def verify_self_hash(payload: dict[str, Any], field: str) -> str:
    claimed = payload.get(field)
    if not isinstance(claimed, str) or not HEX_64.fullmatch(claimed):
        raise ValueError(f"{field} is missing or malformed")
    body = {key: value for key, value in payload.items() if key != field}
    actual = sha256_bytes(canonical_json_bytes(body))
    if actual != claimed:
        raise ValueError(f"{field} mismatch")
    return claimed


def validate_manifest(manifest: dict[str, Any], source_sha: str, mode: str) -> str:
    if not HEX_40.fullmatch(source_sha):
        raise ValueError("source SHA must be 40 lowercase hexadecimal characters")
    manifest_hash = verify_self_hash(manifest, "manifest_sha256")
    identity = manifest.get("identity")
    summary = manifest.get("gate_summary")
    boundaries = manifest.get("claim_boundaries")
    if not isinstance(identity, dict) or not isinstance(summary, dict):
        raise ValueError("Release Manifest identity or gate summary is missing")
    if identity.get("mode") != mode:
        raise ValueError("Release Manifest mode mismatch")
    if identity.get("source_sha") != source_sha or identity.get("checked_out_sha") != source_sha:
        raise ValueError("Release Manifest is not bound to the exact source SHA")
    if summary.get("all_required_gates_verified") is not True:
        raise ValueError("Release Manifest gates are not fully verified")
    for key in ("missing", "stale", "skipped", "inapplicable"):
        if summary.get(key) != []:
            raise ValueError(f"Release Manifest blocker list {key!r} is not empty")
    if not isinstance(boundaries, dict):
        raise ValueError("Release Manifest claim boundaries are missing")
    if boundaries.get("disclosure_state_topology") != "SINGLE_NODE":
        raise ValueError("unexpected disclosure topology")
    if boundaries.get("postgresql_canonical") is not False:
        raise ValueError("PostgreSQL must not be claimed as canonical")
    if boundaries.get("public_demo_uses_synthetic_fixture") is not True:
        raise ValueError("public demo fixture boundary is missing")
    if boundaries.get("static_runtime_fallback_enabled") is not False:
        raise ValueError("static runtime fallback must remain disabled")
    return manifest_hash


def validate_config(config: dict[str, Any], root: Path) -> None:
    if config.get("schema_version") != "1.0":
        raise ValueError("unsupported Phase 9 config schema")
    version = config.get("version")
    tag = config.get("tag")
    if not isinstance(version, str) or tag != f"v{version}":
        raise ValueError("tag must be exactly v<project version>")
    project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    if project.get("project", {}).get("version") != version:
        raise ValueError("Phase 9 version does not match pyproject.toml")
    if config.get("source_branch") != "main":
        raise ValueError("immutable release source branch must be main")
    if config.get("draft") is not False or config.get("prerelease") is not False:
        raise ValueError("configured version must be a published stable release")
    if config.get("immutable_identity") is not True:
        raise ValueError("immutable identity flag must be true")
    sboms = config.get("required_sboms")
    if not isinstance(sboms, dict) or len(sboms) != 4:
        raise ValueError("exactly four SBOM sources are required")


def safe_read_member(archive: Path, member: str) -> bytes:
    with zipfile.ZipFile(archive) as handle:
        names = handle.namelist()
        for name in names:
            pure = PurePosixPath(name)
            if pure.is_absolute() or ".." in pure.parts or "\\" in name:
                raise ValueError(f"unsafe ZIP member in {archive.name}")
        if names.count(member) != 1:
            raise ValueError(f"{archive.name} must contain exactly one {member}")
        return handle.read(member)


def validate_sbom(data: bytes, name: str) -> dict[str, Any]:
    payload = json.loads(data)
    if not isinstance(payload, dict) or payload.get("bomFormat") != "CycloneDX":
        raise ValueError(f"{name} is not a CycloneDX SBOM")
    if payload.get("specVersion") not in {"1.5", "1.6"}:
        raise ValueError(f"{name} uses an unsupported CycloneDX version")
    components = payload.get("components")
    if not isinstance(components, list) or not components:
        raise ValueError(f"{name} has no components")
    return payload


def render_template(path: Path, replacements: dict[str, str]) -> str:
    content = path.read_text(encoding="utf-8")
    for key, value in replacements.items():
        content = content.replace("{{" + key + "}}", value)
    if re.search(r"\{\{[A-Z0-9_]+\}\}", content):
        raise ValueError(f"unresolved template placeholder in {path}")
    return content


def deterministic_zip(output: Path, files: list[Path], base: Path) -> None:
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as handle:
        for path in sorted(files, key=lambda item: item.name):
            info = zipfile.ZipInfo(path.relative_to(base).as_posix(), (1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            handle.writestr(info, path.read_bytes())


def assemble(
    *, root: Path, config_path: Path, manifest_path: Path, artifact_dir: Path,
    output_dir: Path, source_sha: str, mode: str, generated_at: str,
) -> dict[str, Any]:
    config = load_json(config_path)
    validate_config(config, root)
    manifest = load_json(manifest_path)
    manifest_hash = validate_manifest(manifest, source_sha, mode)
    output_dir.mkdir(parents=True, exist_ok=True)

    release_manifest_path = output_dir / "release-manifest.json"
    release_manifest_path.write_bytes(manifest_path.read_bytes())

    sbom_outputs: list[Path] = []
    sbom_sources: list[dict[str, Any]] = []
    supply_gate = manifest.get("gates", {}).get("Supply Chain Security", {})
    artifact_records = {
        item.get("name"): item
        for item in supply_gate.get("artifacts", [])
        if isinstance(item, dict)
    }
    for artifact_name, sbom_config in config["required_sboms"].items():
        record = artifact_records.get(artifact_name)
        if not isinstance(record, dict):
            raise ValueError(f"manifest is missing supply-chain artifact {artifact_name}")
        archive = artifact_dir / f"{artifact_name}.zip"
        if not archive.is_file():
            raise ValueError(f"downloaded artifact is missing: {archive.name}")
        expected_zip_digest = str(record.get("digest", "")).removeprefix("sha256:")
        if sha256_file(archive) != expected_zip_digest:
            raise ValueError(f"artifact ZIP digest mismatch for {artifact_name}")
        member = str(sbom_config["member"])
        output_name = str(sbom_config["output"])
        data = safe_read_member(archive, member)
        sbom = validate_sbom(data, output_name)
        output = output_dir / output_name
        output.write_bytes(data)
        sbom_outputs.append(output)
        sbom_sources.append({
            "artifact": artifact_name,
            "artifact_id": record.get("id"),
            "artifact_digest": record.get("digest"),
            "member": member,
            "output": output_name,
            "output_sha256": sha256_bytes(data),
            "cyclonedx_spec_version": sbom["specVersion"],
            "component_count": len(sbom["components"]),
        })

    index_body: dict[str, Any] = {
        "schema_version": "1.0",
        "release": {
            "version": config["version"],
            "tag": config["tag"],
            "name": config["release_name"],
            "source_sha": source_sha,
            "source_branch": config["source_branch"],
            "manifest_sha256": manifest_hash,
            "mode": mode,
            "generated_at": generated_at,
        },
        "gate_summary": manifest["gate_summary"],
        "claim_boundaries": manifest["claim_boundaries"],
        "sboms": sbom_sources,
        "durable_evidence": manifest.get("gates", {}).get(
            "Phase 8 Durable Evidence Retention", {}
        ).get("verified_claims", {}),
    }
    index_body["evidence_index_sha256"] = sha256_bytes(canonical_json_bytes(index_body))
    evidence_index = output_dir / "release-evidence-index.json"
    evidence_index.write_text(json.dumps(index_body, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    replacements = {
        "TAG": config["tag"],
        "SOURCE_SHA": source_sha,
        "MANIFEST_SHA256": manifest_hash,
        "EVIDENCE_INDEX_SHA256": index_body["evidence_index_sha256"],
    }
    notes = output_dir / "RELEASE_NOTES.md"
    notes.write_text(
        render_template(root / config["release_notes_template"], replacements),
        encoding="utf-8",
    )
    reproducibility = output_dir / "REPRODUCIBILITY.md"
    reproducibility.write_text(
        render_template(root / config["reproducibility_template"], replacements),
        encoding="utf-8",
    )

    provenance_body = {
        "schema_version": "1.0",
        "source_sha": source_sha,
        "tag": config["tag"],
        "manifest_sha256": manifest_hash,
        "evidence_index_sha256": index_body["evidence_index_sha256"],
        "config_sha256": sha256_file(config_path),
        "generated_at": generated_at,
        "mode": mode,
        "sbom_sources": sbom_sources,
    }
    provenance_body["provenance_sha256"] = sha256_bytes(canonical_json_bytes(provenance_body))
    provenance = output_dir / "release-provenance.json"
    provenance.write_text(json.dumps(provenance_body, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    bundle_inputs = [
        release_manifest_path, evidence_index, notes, reproducibility, provenance, *sbom_outputs
    ]
    bundle = output_dir / f"toxicjoin-{config['tag']}-evidence.zip"
    deterministic_zip(bundle, bundle_inputs, output_dir)

    checksum_targets = sorted([*bundle_inputs, bundle], key=lambda item: item.name)
    checksums = output_dir / "SHA256SUMS"
    checksums.write_text(
        "".join(f"{sha256_file(path)}  {path.name}\n" for path in checksum_targets),
        encoding="utf-8",
    )

    result = {
        "schema_version": "1.0",
        "status": "verified",
        "mode": mode,
        "tag": config["tag"],
        "release_name": config["release_name"],
        "source_sha": source_sha,
        "manifest_sha256": manifest_hash,
        "evidence_index_sha256": index_body["evidence_index_sha256"],
        "asset_count": len(checksum_targets) + 1,
        "assets": [path.name for path in checksum_targets] + [checksums.name],
        "checksums_sha256": sha256_file(checksums),
        "bundle_sha256": sha256_file(bundle),
        "release_side_effects": False,
    }
    result["report_sha256"] = sha256_bytes(canonical_json_bytes(result))
    report = output_dir / "phase9-release-bundle-report.json"
    report.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("."))
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--mode", choices=("candidate", "release"), required=True)
    parser.add_argument("--generated-at", default=os.environ.get("PHASE9_GENERATED_AT", ""))
    args = parser.parse_args()
    generated_at = args.generated_at or "1970-01-01T00:00:00Z"
    result = assemble(
        root=args.root.resolve(), config_path=args.config, manifest_path=args.manifest,
        artifact_dir=args.artifact_dir, output_dir=args.output_dir,
        source_sha=args.source_sha, mode=args.mode, generated_at=generated_at,
    )
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
