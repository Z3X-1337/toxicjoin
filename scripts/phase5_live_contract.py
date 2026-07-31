"""Validation contract for exact-source Live DataHub reports."""

from __future__ import annotations

from typing import Any, Iterable

from phase5_evidence_common import (
    EXPECTED_MCP_ARGS,
    MUTATION_PREFIXES,
    Phase5EvidenceError,
    _verify_self_hash,
)


def _assert_no_mutation_tools(tools: Iterable[str], *, label: str) -> None:
    for tool in tools:
        if tool == "save_document" or tool.startswith(MUTATION_PREFIXES):
            raise Phase5EvidenceError(f"{label} exposed mutation-shaped tool: {tool}")


def validate_live_reports(
    *,
    seed: dict[str, Any],
    spike: dict[str, Any],
    agent: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    for label, report in (
        ("seed report", seed),
        ("spike report", spike),
        ("agent discovery report", agent),
        ("live policy report", policy),
    ):
        _verify_self_hash(report, label=label)

    expected_seed_counts = {
        "dataset_count": 5,
        "field_count": 19,
        "tag_count": 10,
        "term_count": 7,
        "lineage_count": 4,
    }
    if seed.get("status") != "seeded":
        raise Phase5EvidenceError("DataHub seed report is not seeded")
    for field, expected in expected_seed_counts.items():
        if seed.get(field) != expected:
            raise Phase5EvidenceError(
                f"DataHub seed {field} mismatch: expected {expected}, got {seed.get(field)!r}"
            )
    if len(seed.get("dataset_urns", [])) != 5:
        raise Phase5EvidenceError("DataHub seed must retain five dataset URNs")

    if spike.get("schema_version") != "1.3" or spike.get("status") != "verified":
        raise Phase5EvidenceError("DataHub spike report is not verified schema 1.3")
    if spike.get("independent_readback_verified") is not True:
        raise Phase5EvidenceError("fresh read-only Decision readback was not verified")
    if spike.get("unclassified_lineage_source_count") != 0:
        raise Phase5EvidenceError("live lineage contains unclassified sources")
    for field in (
        "lineage_relationship_count",
        "lineage_bound_field_count",
        "lineage_source_count",
    ):
        if spike.get(field, 0) < 1:
            raise Phase5EvidenceError(f"live {field} evidence is missing")

    read_settings = spike.get("read_settings")
    write_settings = spike.get("write_settings")
    if not isinstance(read_settings, dict) or not isinstance(write_settings, dict):
        raise Phase5EvidenceError("spike credential-role summaries are missing")
    expected_settings = (
        (read_settings, "read_only", "DATAHUB_GMS_READ_TOKEN", False, False, []),
        (
            write_settings,
            "mutation",
            "DATAHUB_GMS_WRITE_TOKEN",
            True,
            True,
            ["save_document"],
        ),
    )
    for settings, role, source, mutation, document_write, allowlist in expected_settings:
        if settings.get("role") != role:
            raise Phase5EvidenceError(f"spike role mismatch: expected {role}")
        if settings.get("credential_source") != source:
            raise Phase5EvidenceError(f"spike credential source mismatch: expected {source}")
        if settings.get("mutation_enabled") is not mutation:
            raise Phase5EvidenceError(f"spike {role} mutation state mismatch")
        if settings.get("document_write_enabled") is not document_write:
            raise Phase5EvidenceError(f"spike {role} document-write state mismatch")
        if settings.get("writer_transport_allowlist") != allowlist:
            raise Phase5EvidenceError(f"spike {role} writer allowlist mismatch")
        if tuple(settings.get("args", ())) != EXPECTED_MCP_ARGS:
            raise Phase5EvidenceError(f"spike {role} MCP server is not pinned to 0.6.0")

    read_tools = tuple(spike.get("read_discovered_tools", ()))
    readback_tools = tuple(spike.get("readback_discovered_tools", ()))
    raw_writer_tools = tuple(spike.get("write_server_discovered_tools", ()))
    effective_writer_tools = tuple(spike.get("write_discovered_tools", ()))
    _assert_no_mutation_tools(read_tools, label="initial read process")
    _assert_no_mutation_tools(readback_tools, label="fresh readback process")
    if "save_document" not in raw_writer_tools:
        raise Phase5EvidenceError("raw writer server did not expose save_document")
    if effective_writer_tools != ("save_document",):
        raise Phase5EvidenceError("effective writer surface is not exactly save_document")
    document_urn = spike.get("decision_document_urn")
    if not isinstance(document_urn, str) or not document_urn.startswith("urn:li:document:"):
        raise Phase5EvidenceError("Decision document URN is invalid")

    if agent.get("schema_version") != "1.1" or agent.get("status") != "verified":
        raise Phase5EvidenceError("Agent discovery report is not verified schema 1.1")
    if agent.get("source") != "DATAHUB" or agent.get("security_authoritative") is not False:
        raise Phase5EvidenceError("Agent discovery authority boundary is invalid")
    if agent.get("dataset_count") != 5 or agent.get("field_count") != 19:
        raise Phase5EvidenceError("Agent discovery entity/schema counts are incomplete")
    if agent.get("lineage_edge_count", 0) < 5:
        raise Phase5EvidenceError("Agent discovery lineage evidence is incomplete")
    if agent.get("tag_label_count", 0) < 1 or not agent.get("tag_labels"):
        raise Phase5EvidenceError("Agent discovery did not retain live field tags")
    if agent.get("glossary_term_label_count", 0) < 1 or not agent.get(
        "glossary_term_labels"
    ):
        raise Phase5EvidenceError("Agent discovery did not retain live glossary terms")
    if agent.get("dedicated_read_role") is not True:
        raise Phase5EvidenceError("Agent discovery did not use the dedicated read role")
    if agent.get("mutation_tools_exposed_to_agent") is not False:
        raise Phase5EvidenceError("Agent discovery exposed mutation tools")

    if policy.get("schema_version") != "1.0" or policy.get("status") != "verified":
        raise Phase5EvidenceError("live policy report is not verified")
    if policy.get("policy_version") != "0.2.0":
        raise Phase5EvidenceError("live policy report used an unexpected policy version")
    if policy.get("live_semantic_decision") != "BLOCK":
        raise Phase5EvidenceError("live semantic decision did not fail closed as expected")
    if "COMPOSITIONAL_REIDENTIFICATION_RISK" not in policy.get(
        "live_semantic_reason_codes", []
    ):
        raise Phase5EvidenceError("live semantic decision is missing the risk reason")
    if policy.get("read_only_mcp") is not True or policy.get("save_document_exposed") is not False:
        raise Phase5EvidenceError("live policy decision did not use a read-only MCP snapshot")

    return {
        "seed": {**expected_seed_counts, "report_sha256": seed["report_sha256"]},
        "governed_reads": {
            "verified_entity_count": len(spike.get("verified_entities", [])),
            "schema_field_count": sum(spike.get("field_counts", {}).values()),
            "tag_label_count": agent["tag_label_count"],
            "glossary_term_label_count": agent["glossary_term_label_count"],
            "lineage_relationship_count": spike["lineage_relationship_count"],
            "lineage_bound_field_count": spike["lineage_bound_field_count"],
            "lineage_source_count": spike["lineage_source_count"],
        },
        "session_protocol": {
            "sequence": [
                "read_only_snapshot",
                "isolated_save_document_writer",
                "fresh_read_only_readback",
            ],
            "writer_effective_tools": list(effective_writer_tools),
            "writer_closed_before_readback": True,
            "fresh_process_readback_verified": True,
            "decision_document_urn": document_urn,
            "spike_report_sha256": spike["report_sha256"],
        },
        "agent": {
            "context_sha256": agent["context_sha256"],
            "source_snapshot_sha256": agent["source_snapshot_sha256"],
            "report_sha256": agent["report_sha256"],
        },
        "policy": {
            "decision": policy["live_semantic_decision"],
            "reason_codes": policy["live_semantic_reason_codes"],
            "report_sha256": policy["report_sha256"],
        },
    }
