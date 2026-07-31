from __future__ import annotations

from phase8_evidence_common import LIFECYCLES, PROVENANCE, PURPOSES


def validate_store(payload: dict[str, object]) -> int:
    store = payload.get("store")
    if not isinstance(store, dict):
        raise ValueError("catalog store definition is missing")
    required = {
        "algorithm": "sha256",
        "storage_backend": "git-content-addressed",
        "independent_of_actions_expiry": True,
        "large_binary_policy": "digest-indexed-release-asset-in-phase9",
    }
    for key, expected in required.items():
        if store.get(key) != expected:
            raise ValueError(f"catalog store {key} is invalid")
    maximum = store.get("maximum_committed_object_bytes")
    if not isinstance(maximum, int) or maximum <= 0:
        raise ValueError("catalog maximum object size is invalid")
    taxonomy = payload.get("classification_taxonomy")
    if not isinstance(taxonomy, dict):
        raise ValueError("classification taxonomy is missing")
    if set(taxonomy.get("lifecycle", [])) != LIFECYCLES:
        raise ValueError("lifecycle taxonomy is incomplete")
    if set(taxonomy.get("purpose", [])) != PURPOSES:
        raise ValueError("purpose taxonomy is incomplete")
    return maximum


def validate_provenance(object_id: str, provenance: object) -> None:
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
