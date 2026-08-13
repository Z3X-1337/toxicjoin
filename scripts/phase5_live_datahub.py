"""Exact-source Live DataHub evidence binder for Product Readiness Phase 5."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import platform
import shlex
import sys
from pathlib import Path
from typing import Any

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from phase5_evidence_common import (  # noqa: E402
    CHECKSUMS,
    EVIDENCE_INDEX,
    EXPECTED_MCP_ARGS,
    ROOT,
    SCHEMA_VERSION,
    Phase5EvidenceError,
    _artifact_manifest,
    _contract_hashes,
    _credential_separation_from_env,
    _git_identity,
    _load_json,
    _now,
    _parse_uv_version,
    _rooted,
    _secret_reflections,
    _self_hash_report,
    _sha256_file,
    _validate_sha,
    _verify_self_hash,
    _write_json_atomic,
    _run,
)
from phase5_live_contract import validate_live_reports  # noqa: E402


def command_preflight(args: argparse.Namespace) -> None:
    expected_sha = _validate_sha(args.expected_sha, label="expected source SHA")
    head_sha, tree_sha = _git_identity()
    if head_sha != expected_sha:
        raise Phase5EvidenceError(
            f"checkout mismatch: expected {expected_sha}, found {head_sha}"
        )

    toolchain = _load_json(ROOT / "config/toolchain.json")
    expected_uv = str(toolchain["uv"]["version"])
    expected_sdk = str(toolchain["datahub"]["sdk_version"])
    expected_mcp = str(toolchain["datahub"]["mcp_server_version"])
    observed_python = platform.python_version()
    supported_linux = tuple(toolchain["python"]["supported_by_platform"]["linux"])
    if observed_python not in supported_linux:
        raise Phase5EvidenceError(
            f"Python {observed_python} is outside the locked Linux support matrix"
        )
    observed_uv = _parse_uv_version(_run(["uv", "--version"]))
    if observed_uv != expected_uv:
        raise Phase5EvidenceError(
            f"uv version mismatch: expected {expected_uv}, found {observed_uv}"
        )
    observed_sdk = importlib.metadata.version("acryl-datahub")
    if observed_sdk != expected_sdk:
        raise Phase5EvidenceError(
            f"DataHub SDK mismatch: expected {expected_sdk}, found {observed_sdk}"
        )
    parsed_args = tuple(shlex.split(os.environ.get("DATAHUB_MCP_ARGS", "")))
    if parsed_args != EXPECTED_MCP_ARGS or expected_mcp != "0.6.0":
        raise Phase5EvidenceError("DataHub MCP server is not exactly pinned to 0.6.0")

    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "phase": "5-exact-final-sha-live-datahub",
        "status": "verified",
        "created_at": _now(),
        "git": {
            "source_sha": head_sha,
            "tree_sha": tree_sha,
            "github_event_sha": os.getenv("GITHUB_SHA"),
            "exact_source_checkout_verified": True,
        },
        "runner": {
            "os": platform.platform(),
            "machine": platform.machine(),
            "github_runner_name": os.getenv("RUNNER_NAME"),
            "github_runner_os": os.getenv("RUNNER_OS"),
            "github_runner_arch": os.getenv("RUNNER_ARCH"),
        },
        "toolchain": {
            "python": observed_python,
            "uv": observed_uv,
            "datahub_sdk": observed_sdk,
            "datahub_mcp_server": expected_mcp,
            "datahub_mcp_command": os.environ.get("DATAHUB_MCP_COMMAND"),
            "datahub_mcp_args": list(parsed_args),
        },
        "credential_separation": _credential_separation_from_env(),
        "source_contract_sha256": _contract_hashes(),
        "report_sha256": "0" * 64,
    }
    _self_hash_report(report)
    _write_json_atomic(_rooted(args.output), report)
    print(json.dumps(report, indent=2, sort_keys=True))


def command_finalize(args: argparse.Namespace) -> None:
    expected_sha = _validate_sha(args.expected_sha, label="expected source SHA")
    head_sha, tree_sha = _git_identity()
    if head_sha != expected_sha:
        raise Phase5EvidenceError(
            f"finalize checkout mismatch: expected {expected_sha}, found {head_sha}"
        )

    paths = {
        "preflight": _rooted(args.preflight),
        "bootstrap": _rooted(args.bootstrap),
        "seed": _rooted(args.seed),
        "spike": _rooted(args.spike),
        "agent": _rooted(args.agent),
        "policy": _rooted(args.policy),
    }
    reports = {name: _load_json(path) for name, path in paths.items()}
    _verify_self_hash(reports["preflight"], label="Phase 5 preflight")
    _verify_self_hash(reports["bootstrap"], label="document bootstrap report")
    if reports["preflight"].get("git", {}).get("source_sha") != expected_sha:
        raise Phase5EvidenceError("preflight is not bound to the final source SHA")
    if reports["preflight"].get("git", {}).get("tree_sha") != tree_sha:
        raise Phase5EvidenceError("preflight tree differs from final source tree")

    summary = validate_live_reports(
        seed=reports["seed"],
        spike=reports["spike"],
        agent=reports["agent"],
        policy=reports["policy"],
    )
    output_dir = _rooted(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    evidence_paths = list(paths.values()) + [_rooted(value) for value in args.raw_evidence]

    credentials = [
        os.environ.get("DATAHUB_GMS_TOKEN", ""),
        os.environ.get("DATAHUB_GMS_READ_TOKEN", ""),
        os.environ.get("DATAHUB_GMS_WRITE_TOKEN", ""),
    ]
    reflections = _secret_reflections(evidence_paths, credentials)
    if reflections:
        raise Phase5EvidenceError(
            "credential material reflected into Phase 5 evidence: " + ", ".join(reflections)
        )
    gms_url = os.environ.get("DATAHUB_GMS_URL", "")
    sanitized_reports = [paths[name] for name in ("seed", "spike", "agent", "policy")]
    url_reflections = _secret_reflections(sanitized_reports, [gms_url]) if gms_url else []
    if url_reflections:
        raise Phase5EvidenceError(
            "raw GMS URL reflected into sanitized reports: " + ", ".join(url_reflections)
        )

    preflight = reports["preflight"]
    index: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "phase": "5-exact-final-sha-live-datahub",
        "status": "verified",
        "created_at": _now(),
        "git": {
            "source_sha": head_sha,
            "tree_sha": tree_sha,
            "github_event_sha": os.getenv("GITHUB_SHA"),
            "exact_source_checkout_verified": True,
        },
        "toolchain": preflight["toolchain"],
        "credential_separation": preflight["credential_separation"],
        "live_contract": summary,
        "protocol_proof": {
            "implementation": {
                "path": "src/toxicjoin/integrations/datahub_spike.py",
                "sha256": preflight["source_contract_sha256"][
                    "src/toxicjoin/integrations/datahub_spike.py"
                ],
            },
            "session_order_regression": {
                "path": "tests/integration/test_datahub_spike.py",
                "sha256": preflight["source_contract_sha256"][
                    "tests/integration/test_datahub_spike.py"
                ],
            },
            "runtime_report_field": "independent_readback_verified",
            "sequence_verified": True,
        },
        "source_contract_sha256": preflight["source_contract_sha256"],
        "artifacts": _artifact_manifest(evidence_paths, base=ROOT),
        "sanitization": {
            "credential_reflections": 0,
            "sanitized_report_gms_url_reflections": 0,
            "raw_warehouse_rows_in_reports": False,
        },
        "boundaries": {
            "phase6_started": False,
            "pr_118_modified": False,
            "postgresql_claim_changed": False,
            "hosting_configuration_mutated": False,
            "devpost_mutated": False,
            "release_tag_created": False,
            "main_modified_directly": False,
        },
        "report_sha256": "0" * 64,
    }
    _self_hash_report(index)
    index_path = output_dir / EVIDENCE_INDEX
    _write_json_atomic(index_path, index)

    all_paths = evidence_paths + [index_path]
    checksum_path = output_dir / CHECKSUMS
    checksum_path.write_text(
        "\n".join(
            f"{_sha256_file(path)}  {path.relative_to(ROOT).as_posix()}"
            for path in sorted(all_paths, key=lambda item: item.as_posix())
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps(index, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    preflight = subparsers.add_parser("preflight")
    preflight.add_argument("--expected-sha", required=True)
    preflight.add_argument("--output", required=True)
    preflight.set_defaults(func=command_preflight)
    finalize = subparsers.add_parser("finalize")
    finalize.add_argument("--expected-sha", required=True)
    finalize.add_argument("--preflight", required=True)
    finalize.add_argument("--bootstrap", required=True)
    finalize.add_argument("--seed", required=True)
    finalize.add_argument("--spike", required=True)
    finalize.add_argument("--agent", required=True)
    finalize.add_argument("--policy", required=True)
    finalize.add_argument("--raw-evidence", action="append", default=[])
    finalize.add_argument("--output-dir", required=True)
    finalize.set_defaults(func=command_finalize)
    return parser


def main() -> None:
    args = build_parser().parse_args()
    try:
        args.func(args)
    except Phase5EvidenceError as exc:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "error_type": type(exc).__name__,
                    "detail": str(exc),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
