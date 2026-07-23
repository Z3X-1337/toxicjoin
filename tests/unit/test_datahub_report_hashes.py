from __future__ import annotations

from datetime import datetime, timezone

from toxicjoin.integrations.datahub_seed import (
    DataHubSeedReport,
    _report_hash as seed_report_hash,
)
from toxicjoin.integrations.datahub_spike import (
    DataHubSpikeReport,
    _report_hash as spike_report_hash,
)


def test_seed_report_hash_matches_persisted_json_representation() -> None:
    payload = {
        "schema_version": "1.0",
        "created_at": datetime(2026, 7, 23, 2, 44, 58, tzinfo=timezone.utc),
        "status": "seeded",
        "tag_count": 9,
        "term_count": 7,
        "dataset_count": 5,
        "field_count": 19,
        "lineage_count": 4,
        "dataset_urns": (
            "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.customers,PROD)",
        ),
        "report_sha256": "0" * 64,
    }
    payload["report_sha256"] = seed_report_hash(payload)
    report = DataHubSeedReport.model_validate(payload)

    persisted = report.model_dump(mode="json")

    assert seed_report_hash(persisted) == report.report_sha256


def test_spike_report_hash_matches_persisted_json_representation() -> None:
    payload = {
        "schema_version": "1.0",
        "created_at": datetime(2026, 7, 23, 2, 45, 24, tzinfo=timezone.utc),
        "status": "verified",
        "settings": {
            "command": "uvx",
            "args": ["--from", "mcp-server-datahub==0.6.0", "mcp-server-datahub"],
            "gms_scheme": "http",
            "token_present": True,
            "mutation_enabled": True,
            "timeout_seconds": 90.0,
        },
        "discovered_tools": ("get_entities", "grep_documents", "save_document"),
        "verified_entities": (
            "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.customers,PROD)",
        ),
        "field_counts": {"customers": 4},
        "lineage_relationship_count": 3,
        "decision_document_urn": "urn:li:document:shared-test",
        "verification_marker": "TOXICJOIN_MCP_0123456789abcdef0123456789abcdef",
        "marker_sha256": "a" * 64,
        "independent_readback_verified": True,
        "report_sha256": "0" * 64,
    }
    payload["report_sha256"] = spike_report_hash(payload)
    report = DataHubSpikeReport.model_validate(payload)

    persisted = report.model_dump(mode="json")

    assert spike_report_hash(persisted) == report.report_sha256
