from __future__ import annotations

from pathlib import Path

from phase8_evidence_common import (
    LIFECYCLES,
    PURPOSES,
    VerifiedCatalog,
    canonical_json_bytes,
    load_json_object,
    require_digest,
    require_git_sha,
    sha256_bytes,
)
from phase8_evidence_object import validate_entry
from phase8_evidence_policy import validate_store


def verify_catalog(*, root: Path, catalog_path: Path) -> VerifiedCatalog:
    root, catalog_path = root.resolve(), catalog_path.resolve()
    if root not in catalog_path.parents:
        raise ValueError("catalog path must be inside the repository root")
    payload = load_json_object(catalog_path)
    if payload.get("schema_version") != "1.0":
        raise ValueError("durable evidence catalog schema must be 1.0")
    claimed = require_digest(payload.get("catalog_sha256"), name="catalog_sha256")
    body = {key: value for key, value in payload.items() if key != "catalog_sha256"}
    if sha256_bytes(canonical_json_bytes(body)) != claimed:
        raise ValueError("catalog_sha256 mismatch")
    require_git_sha(payload.get("baseline_main_sha"), name="baseline_main_sha")
    maximum = validate_store(payload)
    entries = payload.get("entries")
    if not isinstance(entries, list) or not entries:
        raise ValueError("catalog entries are missing")
    ids: set[str] = set()
    digests: set[str] = set()
    lifecycles: set[str] = set()
    purposes: set[str] = set()
    objects = tuple(
        validate_entry(
            root=root, maximum=maximum, entry=entry, index=index,
            ids=ids, digests=digests, lifecycles=lifecycles, purposes=purposes,
        )
        for index, entry in enumerate(entries)
    )
    if lifecycles != LIFECYCLES:
        raise ValueError("catalog does not represent current and historical evidence")
    if purposes != PURPOSES:
        raise ValueError("catalog does not represent all evidence purposes")
    primary = require_digest(
        payload.get("primary_retrieval_sha256"), name="primary_retrieval_sha256"
    )
    if primary not in digests:
        raise ValueError("primary retrieval object is not in the catalog")
    return VerifiedCatalog(payload, claimed, objects)
