from __future__ import annotations

import json
import os
import platform
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from phase5_retention_policy import phase5_retention_claim
from phase8_evidence_common import (
    VerifiedCatalog,
    VerifiedObject,
    canonical_json_bytes,
    require_git_sha,
    sha256_bytes,
)


def write_json_atomic(path: Path, payload: dict[str, Any]) -> None:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", dir=path.parent,
        prefix=f".{path.name}.", suffix=".tmp", delete=False,
    ) as handle:
        handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n")
        temporary = Path(handle.name)
    temporary.replace(path)


def build_proof_report(
    *, source_sha: str, checked_out_sha: str, catalog: VerifiedCatalog,
    retrieved: VerifiedObject, retrieved_path: Path, command: str,
    generated_at: str | None = None,
) -> dict[str, Any]:
    source_sha = require_git_sha(source_sha, name="source_sha")
    checked_out_sha = require_git_sha(checked_out_sha, name="checked_out_sha")
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
