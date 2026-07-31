from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any

from phase5_retention_policy import phase5_retention_claim

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
LIFECYCLES = {"current", "historical"}
PURPOSES = {"operational", "preview", "replay-only", "submission"}
PROVENANCE = {"commands", "environment", "timestamps", "tool_versions"}


@dataclass(frozen=True)
class VerifiedObject:
    object_id: str
    digest: str
    path: Path
    size_bytes: int
    lifecycle: str
    purpose: str


@dataclass(frozen=True)
class VerifiedCatalog:
    payload: dict[str, Any]
    catalog_sha256: str
    objects: tuple[VerifiedObject, ...]


def canonical_json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _digest(value: object, *, name: str) -> str:
    value = str(value).lower()
    if not SHA256_RE.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _git_sha(value: object, *, name: str) -> str:
    value = str(value).lower()
    if not SHA1_RE.fullmatch(value):
        raise ValueError(f"{name} must be a lowercase 40-character Git SHA")
    return value


def _safe_path(value: object, *, name: str) -> PurePosixPath:
    path = PurePosixPath(str(value))
    if path.is_absolute() or not path.parts or ".." in path.parts or "" in path.parts:
        raise ValueError(f"{name} must be a safe relative path")
    return path


def _json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"failed to read JSON object {path}: {error}") from None
    if not isinstance(value, dict):
        raise ValueError(f"JSON object {path} must contain an object")
    return value


def verify_catalog(*, root: Path, catalog_path: Path) -> VerifiedCatalog:
    root, catalog_path = root.resolve(), catalog_path.resolve()
    if root not in catalog_path.parents:
        raise ValueError "catalog path must be inside the repository root")
    payload = _json(catalog_path)
    if payload.get("schema_version") != "1.0":
        raise ValueError("durable evidence catalog schema must be 1.0")
    claimed = _digest(payload.get("catalog_sha256"), name="catalog_sha256")
    body = {k: v for k, v in payload.items() if k != "catalog_sha256"}
    if sha256_bytes(canonical_json_bytes(body)) != claimed:
        raise ValueError("catalog_sha256 mismatch")
    _git_sha(payload.get("baseline_main_sha"), name="baseline_main_sha")

    store = payload.get("store")
    if not isinstance(store, dict):
        raise ValueError("catalog store definition is missing")
    if store.get("algorithm") != "sha256":
        raise ValueError "catalog algorithm must be sha256")
    if store.get("storage_backend") != "git-content-addressed":
        raise ValueError("catalog storage backend must be git-content-addressed")
    if store.get("independent_of_actions_expiry") is not True:
        raise ValueError "catalog must be independent of GitHub Actions expiry")
    maximum = store.get("maximum_committed_object_bytes")
    if not isinstance(maximum, int) or maximum <= 0:
        raise ValueError "catalog maximum object size is invalid")
    if store.get("large_binary_policy") != "digest-indexed-release-asset-in-phase9":
        raise ValueError("catalog large-binary policy must defer assets to Phase 9")

    taxonomy = payload.get("classification_taxonomy")
    if not isinstance(taxonomy, dict):
        raise ValueError("classification taxonomy is missing")
    if set(taxonomy.get("lifecycle", [])) != LIFECYCLES:
        raise ValueError("lifecycle taxonomy is incomplete")
    if set(taxonomy.get("purpose", [])) != PURPOSES:
        raise ValueError("purpose taxonomy is incomplete")

    entries = payload.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("catalog entries are missing")
    ids: set[str] = set()
    digests: set[str] = set()
    lifecycles: set[str] = set()
    purposes: set[str] = set()
    objects: list[VerifiedObject] = []
    for index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ValueError(f"catalog entry {index} must be an object")
        object_id = str(entry.get("id", ""))
        if not object_id or object_id in ids:
            raise ValueError "catalog object IDs must be non-empty and unique")
        ids.add(object_id)
        digest = _digest(entry.get("sha256"), name=f"entries[{index}].sha256")
        if digest in digests:
            raise ValueError "catalog digests must be unique")
        digests.add(digest)
        relative = _safe_path(entry.get("path"), name=f"entries[{index}].path")
        expected = (
            PurePosixPath("evidence/retained/objects/sha256")
            / digest[:2]
            / f"{digest}.json"
        )
        if relative != expected:
            raise ValueError(f"catalog entry {object_id!r} path is not content-addressed")
        absolute = (root / Path(*relative.parts)).resolve()
        if root not in absolute.parents:
            raise ValueError(f"catalog entry {object_id!r} escaped repository root")
        try:
            data = absolute.read_bytes()
        except OSError as error:
            raise ValueError(f"catalog object {object_id!r} is not retrievable: {error}") from None
        if len(data) > maximum:
            raise ValueError(f"catalog object {object_id!r} exceeds committed size policy")
        if len(data) != entry.get("size_bytes"):
            raise ValueError(f"catalog object {object_id!r} size mismatch")
        if sha256_bytes(data) != digest:
            raise ValueError(f"catalog object {object_id!r} digest mismatch")
        if entry.get("media_type") != "application/json":
            raise ValueError(f"catalog object {object_id!r} has unsupported media type")
        lifecycle, purpose = str(entry.get("lifecycle", "")), str(entry.get("purpose", ""))
        if lifecycle not in LIFECYCLES:
            raise ValueError(f"catalog object {object_id!r} lifecycle is invalid")
        if purpose not in PURPOSES:
            raise ValueError(f"catalog object {object_id!r} purpose is invalid")
        lifecycles.add(lifecycle)
        purposes.add(purpose)
        _git_sha(entry.get("source_sha"), name=f"entries[{index}].source_sha")
        _git_sha(entry.get("related_main_sha"), name=f"entries[{index}].related_main_sha")
        provenance = entry.get("provenance")
        if not isinstance(provenance, dict) or not PROVENANCE.issubset(provenance):
            raise ValueError(f"catalog object {object_id!r} provenance is incomplete")
        commands = provenance.get("commands")
        if not isinstance(commands, list) or not commands or not all(
            isinstance(command, str) and command.strip() for command in commands
        ):
            raise ValueError(f"catalog object {object_id!r} commands are incomplete")
        for field in ("environment", "timestamps", "tool_versions"):
            value = provenance.get(field)
            if not isinstance(value, dict) or not value:
                raise ValueError(f"catalog object {object_id!r} {field} is incomplete")
        objects.append(VerifiedObject(object_id, digest, absolute, len(data), lifecycle, purpose))

    if lifecycles != LIFECYCLES:
        raise ValueError "catalog does not represent current and historical evidence")
    if purposes != PURPOSES:
        raise ValueError("catalog does not represent all evidence purposes")
    primary = _digest(payload.get("primary_retrieval_sha256"), name="primary_retrieval_sha256")
    if primary not in digests:
        raise ValueError("primary retrieval object is not in the catalog")
    return VerifiedCatalog(payload, claimed, tuple(objects))


def retrieve_object(*, catalog: VerifiedCatalog, digest: str, destination: Path) -> VerifiedObject:
    digest = _digest(digest, name="retrieval digest")
    matches = [item for item in catalog.objects if item.digest == digest]
    if len(matches) != 1:
        raise ValueError("retrieval digest must identify exactly one retained object")
    item = matches[0]
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=destination.parent, prefix=f".{destination.name}.", suffix=".tmp", delete=False
    ) as handle:
        temporary = Path(handle.name)
        with item.path.open("rb") as source:
            shutil.copyfileobj(source, handle)
    temporary.replace(destination)
    if sha256_bytes(destination.read_bytes()) != item.digest:
        raise ValueError "retrieved object failed post-copy integrity verification")
    return item


def _write(path: Path, payload: dict[str, Any]) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent, prefix=f".{path.name}.",
        suffix=".tmp", delete=False
    ) as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        temporary = Path(handle.name)
    temporary.replace(path)


def build_proof_report(
    *, source_sha: str, checked_out_sha: str, catalog: VerifiedCatalog,
    retrieved: VerifiedObject, retrieved_path: Path, command: str,
    generated_at: str | None = None,
) -> dict[str, Any]:
    source_sha = _git_sha(source_sha, name="source_sha")
    checked_out_sha = _git_sha(checked_out_sha, name="checked_out_sha")
    if source_sha != checked_out_sha:
        raise ValueError("checked_out_sha does not match source_sha")
    generated_at = generated_at or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "status": "verified",
        "source": {
            "repository": os.environ.get("GITHUB_REPOSITORY", "Z3X-1337/toxicjoin"),
            "source_sha": source_sha,
            "checked_out_sha": checked_out_sha,
            "exact_checkout_verified": True,
        },
        "retention": {
            "storage_backend": "git-content-addressed",
            "independent_of_actions_expiry": True,
            "catalog_sha256": catalog.catalog_sha256,
            "object_count": len(catalog.objects),
            "total_bytes": sum(item.size_bytes for item in catalog.objects),
            "lifecycle_classes": sorted({item.lifecycle for item in catalog.objects}),
            "purpose_classes": sorted({item.purpose for item in catalog.objects}),
            "large_binary_policy": "digest-indexed-release-asset-in-phase9",
            "immutable_release_created": False,
        },
        "retrieval": {
            "object_id": retrieved.object_id,
            "requested_sha256": retrieved.digest,
            "retrieved_sha256": sha256_bytes(retrieved_path.read_bytes()),
            "size_bytes": retrieved_path.stat().st_size,
            "destination_name": retrieved_path.name,
            "verified": True,
        },
        "provenance": {
            "command": command,
            "generated_at": generated_at,
            "environment": {
                "python": platform.python_version(), "system": platform.system(),
                "machine": platform.machine(), "github_workflow": os.environ.get("GITHUB_WORKFLOW"),
                "github_run_id": os.environ.get("GITHUB_RUN_ID"),
                "github_run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            },
            "tool_versions": {
                "python": platform.python_version(), "retention_schema": "1.0",
                "hash_algorithm": "sha256",
            },
        },
        "phase5_retention": phase5_retention_claim(),
        "claim_boundaries": {
            "phase9_release_required_for_large_binary_assets": True,
            "postgresql_canonical": False, "pr118_modified": False,
            "vercel_mutated": False, "devpost_mutated": False,
        },
    }
    payload["report_sha256"] = sha256_bytes(canonical_json_bytes(payload))
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify and retrieve ToxicJoin durable content-addressed evidence."
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--checked-out-sha", required=True)
    parser.add_argument("--retrieve-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    catalog = verify_catalog(root=args.root, catalog_path=args.catalog)
    primary = str(catalog.payload["primary_retrieval_sha256"])
    retrieved_path = args.retrieve_dir / f"{primary}.json"
    retrieved = retrieve_object(catalog=catalog, digest=primary, destination=retrieved_path)
    command = (
        "python scripts/phase8_durable_evidence.py --root . "
        "--catalog evidence/retained/catalog.json --source-sha $PHASE8_SOURCE_SHA "
        "--checked-out-sha $(git rev-parse HEAD) --retrieve-dir artifacts/phase8/retrieved "
        "--output artifacts/phase8/phase8-retention-proof.json"
    )
    report = build_proof_report(
        source_sha=args.source_sha, checked_out_sha=args.checked_out_sha,
        catalog=catalog, retrieved=retrieved, retrieved_path=retrieved_path, command=command
    )
    _write(args.output, report)


if __name__ == "__main__":
    main()
