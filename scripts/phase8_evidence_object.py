from __future__ import annotations

from pathlib import Path, PurePosixPath

from phase8_evidence_common import (
    LIFECYCLES,
    PURPOSES,
    VerifiedObject,
    require_digest,
    require_git_sha,
    safe_relative_path,
    sha256_bytes,
)
from phase8_evidence_policy import validate_provenance


def validate_entry(
    *, root: Path, maximum: int, entry: object, index: int,
    ids: set[str], digests: set[str], lifecycles: set[str], purposes: set[str],
) -> VerifiedObject:
    if not isinstance(entry, dict):
        raise ValueError(f"catalog entry {index} must be an object")
    object_id = str(entry.get("id", ""))
    if not object_id or object_id in ids:
        raise ValueError("catalog object IDs must be non-empty and unique")
    ids.add(object_id)
    digest = require_digest(entry.get("sha256"), name=f"entries[{index}].sha256")
    if digest in digests:
        raise ValueError("catalog digests must be unique")
    digests.add(digest)
    relative = safe_relative_path(entry.get("path"), name=f"entries[{index}].path")
    expected = PurePosixPath("evidence/retained/objects/sha256") / digest[:2] / f"{digest}.json"
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
    if lifecycle not in LIFECYCLES or purpose not in PURPOSES:
        raise ValueError(f"catalog object {object_id!r} classification is invalid")
    lifecycles.add(lifecycle)
    purposes.add(purpose)
    require_git_sha(entry.get("source_sha"), name=f"entries[{index}].source_sha")
    require_git_sha(entry.get("related_main_sha"), name=f"entries[{index}].related_main_sha")
    validate_provenance(object_id, entry.get("provenance"))
    return VerifiedObject(object_id, digest, absolute, len(data), lifecycle, purpose)
