"""Shared fail-closed utilities for Product Readiness Phase 5 evidence."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "1.0"
EVIDENCE_INDEX = "phase5-live-datahub-evidence.json"
CHECKSUMS = "SHA256SUMS"
EXPECTED_MCP_ARGS = ("--from", "mcp-server-datahub==0.6.0", "mcp-server-datahub")
MUTATION_PREFIXES = (
    "add_",
    "remove_",
    "set_",
    "update_",
    "create_",
    "delete_",
    "upsert_",
    "patch_",
)
SOURCE_CONTRACT_PATHS = (
    ".github/workflows/phase5-live-datahub.yml",
    "config/datahub-assets.json",
    "config/toolchain.json",
    "pyproject.toml",
    "uv.lock",
    "scripts/phase5_agent_discovery.py",
    "scripts/phase5_bootstrap_document.py",
    "scripts/phase5_evidence_common.py",
    "scripts/phase5_live_contract.py",
    "scripts/phase5_live_datahub.py",
    "scripts/phase5_policy_decision.py",
    "src/toxicjoin/agent/datahub_discovery.py",
    "src/toxicjoin/integrations/datahub_authority.py",
    "src/toxicjoin/integrations/datahub_mcp.py",
    "src/toxicjoin/integrations/datahub_seed.py",
    "src/toxicjoin/integrations/datahub_spike.py",
    "tests/integration/test_datahub_spike.py",
    "tests/test_phase5_live_datahub.py",
)


class Phase5EvidenceError(RuntimeError):
    """Fail-closed Phase 5 evidence error."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _canonical_hash(value: dict[str, Any], *, omit: Iterable[str] = ()) -> str:
    omitted = set(omit)
    payload = {key: item for key, item in value.items() if key not in omitted}
    return _sha256_bytes(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    )


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (
        json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")
    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        temp_path = None
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def _rooted(path: str | Path) -> Path:
    value = Path(path)
    return value if value.is_absolute() else ROOT / value


def _load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise Phase5EvidenceError(f"unable to load JSON evidence: {path}") from exc
    if not isinstance(value, dict):
        raise Phase5EvidenceError(f"JSON evidence must be an object: {path}")
    return value


def _run(command: list[str]) -> str:
    try:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        raise Phase5EvidenceError(f"command failed: {' '.join(command)}") from exc
    return completed.stdout.strip()


def _git_identity() -> tuple[str, str]:
    return _run(["git", "rev-parse", "HEAD"]), _run(
        ["git", "rev-parse", "HEAD^{tree}"]
    )


def _validate_sha(value: str, *, label: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) != 40 or any(ch not in "0123456789abcdef" for ch in normalized):
        raise Phase5EvidenceError(f"{label} must be a 40-character lowercase Git SHA")
    return normalized


def _parse_uv_version(value: str) -> str:
    parts = value.strip().split()
    if len(parts) < 2 or parts[0] != "uv":
        raise Phase5EvidenceError(f"unexpected uv version output: {value!r}")
    return parts[1]


def _contract_hashes() -> dict[str, str]:
    result: dict[str, str] = {}
    for relative in SOURCE_CONTRACT_PATHS:
        path = ROOT / relative
        if not path.is_file():
            raise Phase5EvidenceError(f"required Phase 5 contract file missing: {relative}")
        result[relative] = _sha256_file(path)
    return result


def _credential_separation_from_env() -> dict[str, Any]:
    names = (
        "DATAHUB_GMS_TOKEN",
        "DATAHUB_GMS_READ_TOKEN",
        "DATAHUB_GMS_WRITE_TOKEN",
    )
    values: dict[str, str] = {}
    for name in names:
        if name not in os.environ or not os.environ[name]:
            raise Phase5EvidenceError(f"{name} must be set")
        values[name] = os.environ[name]
    if not all(
        not hmac.compare_digest(values[left], values[right])
        for index, left in enumerate(names)
        for right in names[index + 1 :]
    ):
        raise Phase5EvidenceError(
            "SDK, read-only, and writer credential channels must use distinct values"
        )
    return {
        "sdk_credential_source": "DATAHUB_GMS_TOKEN",
        "read_credential_source": "DATAHUB_GMS_READ_TOKEN",
        "write_credential_source": "DATAHUB_GMS_WRITE_TOKEN",
        "all_present": True,
        "pairwise_distinct": True,
        "credential_values_serialized": False,
    }


def _self_hash_report(report: dict[str, Any], *, field: str = "report_sha256") -> str:
    report[field] = "0" * 64
    report[field] = _canonical_hash(report, omit=(field,))
    return report[field]


def _verify_self_hash(
    report: dict[str, Any], *, label: str, field: str = "report_sha256"
) -> None:
    claimed = report.get(field)
    if not isinstance(claimed, str) or len(claimed) != 64:
        raise Phase5EvidenceError(f"{label} is missing a valid {field}")
    actual = _canonical_hash(report, omit=(field,))
    if not hmac.compare_digest(claimed, actual):
        raise Phase5EvidenceError(f"{label} self-hash mismatch")


def _secret_reflections(paths: Iterable[Path], secrets: Iterable[str]) -> list[str]:
    encoded_secrets = [value.encode("utf-8") for value in secrets if value]
    findings: list[str] = []
    for path in paths:
        if not path.is_file():
            raise Phase5EvidenceError(f"evidence file missing during secret scan: {path}")
        content = path.read_bytes()
        if any(secret in content for secret in encoded_secrets):
            findings.append(path.name)
    return findings


def _artifact_manifest(paths: Iterable[Path], *, base: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for path in sorted(paths, key=lambda item: item.as_posix()):
        if not path.is_file():
            raise Phase5EvidenceError(f"artifact file missing: {path}")
        entries.append(
            {
                "path": path.relative_to(base).as_posix(),
                "size_bytes": path.stat().st_size,
                "sha256": _sha256_file(path),
            }
        )
    return entries
