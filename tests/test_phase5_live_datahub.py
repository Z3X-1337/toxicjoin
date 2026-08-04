from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from typing import Any

import pytest


SCRIPTS_DIR = Path(__file__).resolve().parents[1] / "scripts"
SCRIPT = SCRIPTS_DIR / "phase5_live_datahub.py"
SPEC = importlib.util.spec_from_file_location("phase5_live_datahub", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
phase5 = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(phase5)

# Sealing helpers belong to the shared evidence module. Reaching them through
# phase5_live_datahub relied on an incidental re-export, which made an unused-import cleanup
# in that script silently break these tests.
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))
from phase5_evidence_common import _canonical_hash  # noqa: E402


def _seal(payload: dict[str, Any]) -> dict[str, Any]:
    value = json.loads(json.dumps(payload))
    value["report_sha256"] = "0" * 64
    value["report_sha256"] = _canonical_hash(
        value,
        omit=("report_sha256",),
    )
    return value


def _seed() -> dict[str, Any]:
    return _seal(
        {
            "schema_version": "1.0",
            "created_at": "2026-07-31T09:00:00Z",
            "status": "seeded",
            "tag_count": 10,
            "term_count": 7,
            "dataset_count": 5,
            "field_count": 19,
            "lineage_count": 4,
            "dataset_urns": [f"urn:li:dataset:{index}" for index in range(5)],
        }
    )


def _spike() -> dict[str, Any]:
    read_tools = ["get_entities", "get_lineage", "list_schema_fields"]
    read_settings = {
        "command": "uvx",
        "args": ["--from", "mcp-server-datahub==0.6.0", "mcp-server-datahub"],
        "gms_scheme": "http",
        "token_present": True,
        "mutation_enabled": False,
        "timeout_seconds": 90.0,
        "role": "read_only",
        "credential_source": "DATAHUB_GMS_READ_TOKEN",
        "document_write_enabled": False,
        "writer_transport_allowlist": [],
    }
    write_settings = {
        "command": "uvx",
        "args": ["--from", "mcp-server-datahub==0.6.0", "mcp-server-datahub"],
        "gms_scheme": "http",
        "token_present": True,
        "mutation_enabled": True,
        "timeout_seconds": 90.0,
        "role": "mutation",
        "credential_source": "DATAHUB_GMS_WRITE_TOKEN",
        "document_write_enabled": True,
        "writer_transport_allowlist": ["save_document"],
    }
    return _seal(
        {
            "schema_version": "1.3",
            "created_at": "2026-07-31T09:01:00Z",
            "status": "verified",
            "read_settings": read_settings,
            "write_settings": write_settings,
            "read_discovered_tools": read_tools,
            "write_server_discovered_tools": ["add_tags", "save_document"],
            "write_discovered_tools": ["save_document"],
            "readback_discovered_tools": read_tools + ["grep_documents"],
            "verified_entities": [f"urn:li:dataset:{index}" for index in range(5)],
            "field_counts": {
                "customers": 4,
                "location_activity": 3,
                "orders": 5,
                "retention_scores": 3,
                "support_cases": 4,
            },
            "lineage_relationship_count": 3,
            "lineage_bound_field_count": 2,
            "lineage_source_count": 6,
            "flagship_lineage_source_keys": ["orders.purchase_amount"],
            "flagship_lineage_categories": ["SENSITIVE_ATTRIBUTE"],
            "unclassified_lineage_source_count": 0,
            "decision_document_urn": "urn:li:document:phase5-test",
            "verification_marker": "TOXICJOIN_MCP_0123456789abcdef0123456789abcdef",
            "marker_sha256": "1" * 64,
            "independent_readback_verified": True,
        }
    )


def _agent() -> dict[str, Any]:
    return _seal(
        {
            "schema_version": "1.1",
            "status": "verified",
            "created_at": "2026-07-31T09:02:00Z",
            "source": "DATAHUB",
            "security_authoritative": False,
            "source_snapshot_sha256": "2" * 64,
            "context_sha256": "3" * 64,
            "catalog_version": "live",
            "dataset_count": 5,
            "field_count": 19,
            "lineage_edge_count": 6,
            "tag_label_count": 9,
            "tag_labels": ["toxicjoin:stable-pseudonym"],
            "glossary_term_label_count": 7,
            "glossary_term_labels": ["StableCustomerIdentifier"],
            "dedicated_read_role": True,
            "mutation_tools_exposed_to_agent": False,
        }
    )


def _policy() -> dict[str, Any]:
    return _seal(
        {
            "schema_version": "1.0",
            "status": "verified",
            "created_at": "2026-07-31T09:03:00Z",
            "policy_version": "0.2.0",
            "live_semantic_decision": "BLOCK",
            "live_semantic_reason_codes": ["COMPOSITIONAL_REIDENTIFICATION_RISK"],
            "wrapped_output_kind": "TRANSFORMED_RAW_VALUE",
            "snapshot_catalog_version": "live",
            "flagship_lineage": {"orders.purchase_amount": "SENSITIVE_ATTRIBUTE"},
            "read_only_mcp": True,
            "save_document_exposed": False,
        }
    )


def test_complete_live_contract_validates() -> None:
    summary = phase5.validate_live_reports(
        seed=_seed(),
        spike=_spike(),
        agent=_agent(),
        policy=_policy(),
    )

    assert summary["governed_reads"]["schema_field_count"] == 19
    assert summary["governed_reads"]["tag_label_count"] == 9
    assert summary["governed_reads"]["glossary_term_label_count"] == 7
    assert summary["session_protocol"]["writer_effective_tools"] == ["save_document"]
    assert summary["session_protocol"]["fresh_process_readback_verified"] is True


def test_zero_or_missing_glossary_evidence_fails_closed() -> None:
    agent = _agent()
    agent["glossary_term_label_count"] = 0
    agent["glossary_term_labels"] = []
    agent = _seal(agent)

    with pytest.raises(phase5.Phase5EvidenceError, match="glossary"):
        phase5.validate_live_reports(
            seed=_seed(),
            spike=_spike(),
            agent=agent,
            policy=_policy(),
        )


def test_writer_surface_broader_than_save_document_fails_closed() -> None:
    spike = _spike()
    spike["write_discovered_tools"] = ["save_document", "add_tags"]
    spike = _seal(spike)

    with pytest.raises(phase5.Phase5EvidenceError, match="effective writer surface"):
        phase5.validate_live_reports(
            seed=_seed(),
            spike=spike,
            agent=_agent(),
            policy=_policy(),
        )


def test_missing_independent_readback_fails_closed() -> None:
    spike = _spike()
    spike["independent_readback_verified"] = False
    spike = _seal(spike)

    with pytest.raises(phase5.Phase5EvidenceError, match="readback"):
        phase5.validate_live_reports(
            seed=_seed(),
            spike=spike,
            agent=_agent(),
            policy=_policy(),
        )


def test_report_hash_tampering_is_rejected() -> None:
    policy = _policy()
    policy["live_semantic_decision"] = "ALLOW"

    with pytest.raises(phase5.Phase5EvidenceError, match="self-hash"):
        phase5.validate_live_reports(
            seed=_seed(),
            spike=_spike(),
            agent=_agent(),
            policy=policy,
        )


def test_secret_reflection_scan_reports_exact_file(tmp_path: Path) -> None:
    clean = tmp_path / "clean.txt"
    leaked = tmp_path / "leaked.txt"
    clean.write_text("sanitized evidence", encoding="utf-8")
    leaked.write_text("prefix PHASE5_READ_SECRET suffix", encoding="utf-8")

    assert phase5._secret_reflections(
        [clean, leaked],
        ["PHASE5_READ_SECRET"],
    ) == ["leaked.txt"]
