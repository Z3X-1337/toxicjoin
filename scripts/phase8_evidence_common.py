from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

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


def require_digest(value: object, *, name: str) -> str:
    normalized = str(value).lower()
    if not SHA256_RE.fullmatch(normalized):
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return normalized


def require_git_sha(value: object, *, name: str) -> str:
    normalized = str(value).lower()
    if not SHA1_RE.fullmatch(normalized):
        raise ValueError(f"{name} must be a lowercase 40-character Git SHA")
    return normalized


def safe_relative_path(value: object, *, name: str) -> PurePosixPath:
    path = PurePosixPath(str(value))
    if path.is_absolute() or not path.parts or ".." in path.parts or "" in path.parts:
        raise ValueError(f"{name} must be a safe relative path")
    return path


def load_json_object(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"failed to read JSON object {path}: {error}") from None
    if not isinstance(payload, dict):
        raise ValueError(f"JSON object {path} must contain an object")
    return payload
