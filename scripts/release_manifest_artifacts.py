from __future__ import annotations

import hashlib
import io
import json
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any, Callable

import generate_release_manifest as legacy

_MAX_COMPRESSED = 128 * 1024 * 1024
_MAX_UNCOMPRESSED = 256 * 1024 * 1024
_MAX_MEMBERS = 4096


@dataclass(frozen=True)
class ArtifactBundle:
    metadata: dict[str, Any]
    zip_bytes: bytes
    members: dict[str, bytes]


@dataclass(frozen=True)
class GateSpec:
    required_artifacts: tuple[str, ...] = ()
    validator: Callable[[dict[str, ArtifactBundle], str], dict[str, Any]] | None = None
    required_jobs: tuple[str, ...] = ()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_sha256(payload: dict[str, Any], *, ensure_ascii: bool = True) -> str:
    raw = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=ensure_ascii,
    ).encode("utf-8")
    return sha256_bytes(raw)


def safe_zip_members(data: bytes, *, artifact_name: str) -> dict[str, bytes]:
    if len(data) > _MAX_COMPRESSED:
        raise ValueError(f"artifact {artifact_name!r} exceeded compressed safety limit")
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > _MAX_MEMBERS:
                raise ValueError(f"artifact {artifact_name!r} has invalid member count")
            result: dict[str, bytes] = {}
            total = 0
            for info in infos:
                path = PurePosixPath(info.filename)
                if info.is_dir():
                    continue
                if path.is_absolute() or ".." in path.parts or "" in path.parts:
                    raise ValueError(f"artifact {artifact_name!r} contains unsafe path")
                normalized = str(path)
                if normalized in result:
                    raise ValueError(f"artifact {artifact_name!r} contains duplicate path")
                total += int(info.file_size)
                if total > _MAX_UNCOMPRESSED:
                    raise ValueError(f"artifact {artifact_name!r} exceeded safety limit")
                result[normalized] = archive.read(info)
    except zipfile.BadZipFile:
        raise ValueError(f"artifact {artifact_name!r} is not a valid ZIP") from None
    if not result:
        raise ValueError(f"artifact {artifact_name!r} contains no files")
    return result


def build_artifact_bundle(metadata: dict[str, Any], data: bytes) -> ArtifactBundle:
    sanitized = legacy._sanitize_artifact(metadata)
    digest = sanitized.get("digest")
    if not isinstance(digest, str):
        raise ValueError(f"artifact {sanitized['name']!r} is missing digest")
    if sanitized["expired"]:
        raise ValueError(f"artifact {sanitized['name']!r} is expired")
    if sanitized["size_in_bytes"] <= 0:
        raise ValueError(f"artifact {sanitized['name']!r} is empty")
    expected = digest.removeprefix("sha256:")
    actual = sha256_bytes(data)
    if expected != actual:
        raise ValueError(
            f"artifact {sanitized['name']!r} digest mismatch: "
            f"expected={expected} actual={actual}"
        )
    return ArtifactBundle(
        metadata=sanitized,
        zip_bytes=data,
        members=safe_zip_members(data, artifact_name=sanitized["name"]),
    )


def member_by_basename(bundle: ArtifactBundle, basename: str) -> tuple[str, bytes]:
    matches = [
        (name, data)
        for name, data in bundle.members.items()
        if PurePosixPath(name).name == basename
    ]
    if len(matches) != 1:
        raise ValueError(
            f"artifact {bundle.metadata['name']!r} expected exactly one "
            f"{basename!r}, found {len(matches)}"
        )
    return matches[0]


def json_member(bundle: ArtifactBundle, basename: str) -> tuple[dict[str, Any], bytes]:
    _, raw = member_by_basename(bundle, basename)
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError(
            f"artifact {bundle.metadata['name']!r} contains invalid {basename}"
        ) from None
    if not isinstance(payload, dict):
        raise ValueError(f"{basename} must contain a JSON object")
    return payload, raw


def verify_sha256sums(bundle: ArtifactBundle) -> int:
    _, raw = member_by_basename(bundle, "SHA256SUMS")
    count = 0
    for line in raw.decode("utf-8").splitlines():
        if not line.strip():
            continue
        expected, separator, recorded = line.partition("  ")
        if separator != "  ":
            raise ValueError("SHA256SUMS contains malformed line")
        legacy._validate_sha256(expected, name="SHA256SUMS digest")
        basename = PurePosixPath(recorded).name
        matches = [
            data
            for name, data in bundle.members.items()
            if PurePosixPath(name).name == basename
        ]
        if len(matches) != 1 or sha256_bytes(matches[0]) != expected:
            raise ValueError(f"SHA256SUMS verification failed for {recorded!r}")
        count += 1
    if count == 0:
        raise ValueError("SHA256SUMS is empty")
    return count


def verify_report_self_hash(
    payload: dict[str, Any],
    *,
    field: str = "report_sha256",
    ensure_ascii: bool = True,
) -> str:
    claimed = payload.get(field)
    if not isinstance(claimed, str):
        raise ValueError(f"report is missing {field}")
    claimed = legacy._validate_sha256(claimed, name=field)
    body = {key: value for key, value in payload.items() if key != field}
    if canonical_sha256(body, ensure_ascii=ensure_ascii) != claimed:
        raise ValueError(f"{field} mismatch")
    return claimed


def validate_baseline(
    bundles: dict[str, ArtifactBundle], source_sha: str
) -> dict[str, Any]:
    payload, raw = json_member(
        bundles["toxicjoin-ground-truth-baseline"],
        "baseline.json",
    )
    source = payload.get("source")
    validation = payload.get("validation")
    if payload.get("schema_version") != "1.1" or not isinstance(source, dict):
        raise ValueError("ground-truth baseline schema/source is invalid")
    if source.get("source_sha") != source_sha or source.get("checked_out_sha") != source_sha:
        raise ValueError("ground-truth baseline source mismatch")
    if source.get("exact_checkout_verified") is not True or not isinstance(validation, dict):
        raise ValueError("ground-truth baseline validation is incomplete")
    pytest_data = validation.get("pytest")
    benchmark = validation.get("benchmark")
    if not isinstance(pytest_data, dict) or not isinstance(benchmark, dict):
        raise ValueError("ground-truth baseline validation is incomplete")
    passed = pytest_data.get("passed")
    if not isinstance(passed, int) or passed <= 0 or benchmark.get("gate_failures") != []:
        raise ValueError("ground-truth baseline gate is not clean")
    return {
        "baseline_json_sha256": sha256_bytes(raw),
        "pytest_passed": passed,
        "benchmark_report_sha256": legacy._validate_sha256(
            benchmark.get("report_sha256", ""),
            name="baseline benchmark report_sha256",
        ),
    }


def validate_ci(bundles: dict[str, ArtifactBundle], source_sha: str) -> dict[str, Any]:
    benchmark, benchmark_raw = json_member(
        bundles["toxicjoin-benchmark"],
        "benchmark.json",
    )
    metrics = benchmark.get("metrics")
    if benchmark.get("schema_version") != "1.0" or not isinstance(metrics, dict):
        raise ValueError("benchmark evidence schema is invalid")
    if metrics.get("total_cases") != 30 or metrics.get("fully_passed") != 30:
        raise ValueError("benchmark did not pass all 30 cases")
    if metrics.get("false_allow_count") != 0 or metrics.get("unsafe_effective_allow_count") != 0:
        raise ValueError("benchmark contains unsafe allows")
    ppmc, ppmc_raw = json_member(
        bundles["toxicjoin-ppmc-hard-gate"],
        "ppmc-hard-gate.json",
    )
    if ppmc.get("schema_version") != "1.0" or ppmc.get("gate_passed") is not True:
        raise ValueError("PPMC hard gate is not verified")
    _, checksum_raw = member_by_basename(
        bundles["toxicjoin-ppmc-hard-gate"],
        "ppmc-hard-gate.sha256",
    )
    checksum = checksum_raw.decode("utf-8").strip().split()[0]
    if legacy._validate_sha256(checksum, name="PPMC checksum") != sha256_bytes(ppmc_raw):
        raise ValueError("PPMC checksum mismatch")
    for name in ("pytest-3.11.15", "pytest-3.12.13", "toxicjoin-container-log"):
        if not any(data.strip() for data in bundles[name].members.values()):
            raise ValueError(f"{name} is empty")
    return {
        "benchmark_json_sha256": sha256_bytes(benchmark_raw),
        "benchmark_total_cases": 30,
        "benchmark_false_allow_count": 0,
        "ppmc_json_sha256": sha256_bytes(ppmc_raw),
        "ppmc_gate_passed": True,
        "container_job_verified": True,
    }


def validate_phase4(
    bundles: dict[str, ArtifactBundle], source_sha: str
) -> dict[str, Any]:
    parity = bundles["phase4-portability-parity"]
    verify_sha256sums(parity)
    payload, raw = json_member(parity, "phase4-parity-comparison.json")
    comparisons = payload.get("comparisons")
    if payload.get("schema_version") != "1.0" or payload.get("passed") is not True:
        raise ValueError("Phase 4 parity evidence is not verified")
    if not isinstance(comparisons, list) or len(comparisons) != 2:
        raise ValueError("Phase 4 parity comparisons are incomplete")
    for item in comparisons:
        checks = item.get("checks") if isinstance(item, dict) else None
        if not isinstance(item, dict) or item.get("passed") is not True:
            raise ValueError("Phase 4 parity comparison failed")
        if not isinstance(checks, dict) or not checks:
            raise ValueError("Phase 4 parity checks are missing")
        if not all(value is True for value in checks.values()):
            raise ValueError("Phase 4 parity invariant failed")
    native_names = [name for name in bundles if name != "phase4-portability-parity"]
    for name in native_names:
        bundle = bundles[name]
        verify_sha256sums(bundle)
        report, _ = json_member(bundle, "phase4-portability-evidence.json")
        git = report.get("git")
        if report.get("status") != "verified" or not isinstance(git, dict):
            raise ValueError(f"Phase 4 native evidence {name!r} is invalid")
        if git.get("commit") != source_sha:
            raise ValueError(f"Phase 4 native evidence {name!r} source mismatch")
    return {
        "parity_report_sha256": sha256_bytes(raw),
        "comparison_count": 2,
        "native_artifact_count": len(native_names),
    }


def validate_phase5(
    bundles: dict[str, ArtifactBundle], source_sha: str
) -> dict[str, Any]:
    bundle = bundles["phase5-exact-sha-live-datahub-evidence"]
    count = verify_sha256sums(bundle)
    payload, raw = json_member(bundle, "phase5-live-datahub-evidence.json")
    git = payload.get("git")
    if payload.get("status") != "verified" or not isinstance(git, dict):
        raise ValueError("Phase 5 evidence is not verified")
    if git.get("source_sha") != source_sha:
        raise ValueError("Phase 5 evidence source mismatch")
    if payload.get("sanitization", {}).get("credential_reflections") != 0:
        raise ValueError("Phase 5 evidence contains credential reflections")
    verify_report_self_hash(payload)
    return {
        "evidence_index_sha256": sha256_bytes(raw),
        "sha256sums_entries": count,
        "live_datahub_verified": True,
        "credential_reflections": 0,
    }


def validate_phase6(
    bundles: dict[str, ArtifactBundle], source_sha: str
) -> dict[str, Any]:
    bundle = bundles["phase6-browser-e2e-evidence"]
    count = verify_sha256sums(bundle)
    payload, raw = json_member(bundle, "browser-e2e-report.json")
    coverage = payload.get("coverage", {})
    if payload.get("status") != "verified" or payload.get("source", {}).get("source_sha") != source_sha:
        raise ValueError("Phase 6 browser evidence source/status mismatch")
    if len(payload.get("matrix", [])) != 6:
        raise ValueError("Phase 6 browser matrix is incomplete")
    if coverage.get("real_browser_screenshots") is not True:
        raise ValueError("Phase 6 lacks real browser screenshots")
    if coverage.get("fake_or_generated_ui_used") is not False:
        raise ValueError("Phase 6 used fake or generated UI")
    verify_report_self_hash(payload, ensure_ascii=False)
    screenshots = sum(1 for name in bundle.members if name.lower().endswith(".png"))
    if screenshots < 20:
        raise ValueError("Phase 6 screenshot evidence is incomplete")
    return {
        "browser_report_sha256": sha256_bytes(raw),
        "matrix_cells": 6,
        "screenshots": screenshots,
        "sha256sums_entries": count,
    }


def validate_topology(
    bundles: dict[str, ArtifactBundle], source_sha: str
) -> dict[str, Any]:
    bundle = bundles["toxicjoin-disclosure-sequence-evidence"]
    payload, raw = json_member(bundle, "topology-evidence.json")
    if payload.get("schema_version") != "1.0" or payload.get("source_sha") != source_sha:
        raise ValueError("topology evidence source/schema mismatch")
    if payload.get("state_topology") != "SINGLE_NODE":
        raise ValueError("canonical topology must remain SINGLE_NODE before Phase 12")
    if payload.get("multi_replica_supported") is not False:
        raise ValueError("topology evidence falsely claims multi-replica support")
    if payload.get("multi_replica_fail_closed") is not True:
        raise ValueError("topology evidence does not fail closed")
    if payload.get("shared_authoritative_backend") is not False:
        raise ValueError("topology evidence makes a premature shared-state claim")
    if payload.get("postgresql_canonical") is not False:
        raise ValueError("topology evidence makes a premature PostgreSQL claim")
    verify_report_self_hash(payload)
    return {
        "topology_report_sha256": sha256_bytes(raw),
        "state_topology": "SINGLE_NODE",
        "multi_replica_supported": False,
        "multi_replica_fail_closed": True,
        "postgresql_canonical": False,
    }


GATE_SPECS: dict[str, GateSpec] = {
    "CI": GateSpec(
        required_artifacts=(
            "toxicjoin-benchmark",
            "toxicjoin-ppmc-hard-gate",
            "toxicjoin-container-log",
            "pytest-3.11.15",
            "pytest-3.12.13",
        ),
        validator=validate_ci,
        required_jobs=("test (3.11.15)", "test (3.12.13)", "web", "container"),
    ),
    "Ground Truth Baseline": GateSpec(
        required_artifacts=("toxicjoin-ground-truth-baseline",),
        validator=validate_baseline,
    ),
    "CodeQL": GateSpec(),
    "Supply Chain Security": GateSpec(
        required_artifacts=(
            "web-supply-chain",
            "browser-tools-supply-chain",
            "python-supply-chain-agent-registry",
            "python-supply-chain-datahub",
            "dependency-review-api-status",
        )
    ),
    "Governance Dependency Evidence": GateSpec(),
    "Adversarial Mutation Evidence": GateSpec(),
    "Compositional Ablation Evidence": GateSpec(),
    "Phase 4 Portability Evidence": GateSpec(
        required_artifacts=(
            "phase4-portability-parity",
            "phase4-portability-ubuntu-24.04-python-3.11.15",
            "phase4-portability-ubuntu-24.04-python-3.12.13",
            "phase4-portability-windows-2025-python-3.11.9",
            "phase4-portability-windows-2025-python-3.12.10",
        ),
        validator=validate_phase4,
    ),
    "Phase 5 Exact-SHA Live DataHub Evidence": GateSpec(
        required_artifacts=("phase5-exact-sha-live-datahub-evidence",),
        validator=validate_phase5,
    ),
    "Phase 6 Production Browser E2E": GateSpec(
        required_artifacts=("phase6-browser-e2e-evidence",),
        validator=validate_phase6,
    ),
    "Disclosure Sequence Evidence": GateSpec(
        required_artifacts=("toxicjoin-disclosure-sequence-evidence",),
        validator=validate_topology,
        required_jobs=("cumulative-disclosure-evidence",),
    ),
}
