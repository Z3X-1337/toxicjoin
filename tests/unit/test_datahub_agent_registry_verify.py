from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from toxicjoin.integrations.datahub_agent_registry import DataHubAgentRegistryReport
from toxicjoin.integrations.datahub_agent_registry_verify import (
    DataHubAgentRegistryVerificationBindings,
    DataHubAgentRegistryVerificationError,
    _report_hash,
    verify_datahub_agent_registry,
)


class AgentSkillInfo:
    pass


class AIAgentInfo:
    pass


class AIAgentDependencies:
    pass


class ApiProperties:
    pass


class UpstreamLineage:
    pass


class FakeGraph:
    def __init__(self, aspects: dict[tuple[str, type], Any]) -> None:
        self.aspects = aspects
        self.calls: list[tuple[str, type]] = []

    def get_aspect(self, *, entity_urn: str, aspect_type: type) -> Any:
        self.calls.append((entity_urn, aspect_type))
        return self.aspects.get((entity_urn, aspect_type))


def _unused_graph():
    raise AssertionError("explicit fake graph should be used")


def _bindings() -> DataHubAgentRegistryVerificationBindings:
    return DataHubAgentRegistryVerificationBindings(
        get_default_graph=_unused_graph,
        AgentSkillInfoClass=AgentSkillInfo,
        AIAgentInfoClass=AIAgentInfo,
        AIAgentDependenciesClass=AIAgentDependencies,
        ApiPropertiesClass=ApiProperties,
        UpstreamLineageClass=UpstreamLineage,
    )


def _registration() -> DataHubAgentRegistryReport:
    tools = tuple(f"urn:li:api:tool-{index}" for index in range(5))
    datasets = tuple(f"urn:li:dataset:(urn:li:dataPlatform:duckdb,d{index},PROD)" for index in range(5))
    return DataHubAgentRegistryReport(
        created_at="2026-07-23T12:00:00Z",
        status="registered",
        tool_count=5,
        skill_count=1,
        agent_count=1,
        tool_urns=tools,
        skill_urn="urn:li:agentSkill:toxicjoin-compositional-risk-review",
        agent_urn="urn:li:aiAgent:toxicjoin-privacy-firewall-agent",
        consumed_dataset_urns=datasets,
        source_repository_url="https://github.com/Z3X-1337/toxicjoin",
        source_skill_path="skills/compositional-risk-review/SKILL.md",
        report_sha256="a" * 64,
    )


def _aspects(registration: DataHubAgentRegistryReport) -> dict[tuple[str, type], Any]:
    aspects: dict[tuple[str, type], Any] = {
        (registration.skill_urn, AgentSkillInfo): SimpleNamespace(
            sourceRepository=SimpleNamespace(
                url=registration.source_repository_url,
                path=registration.source_skill_path,
            ),
            requiredTools=list(registration.tool_urns),
        ),
        (registration.agent_urn, AIAgentInfo): SimpleNamespace(
            name="ToxicJoin Privacy Firewall Agent"
        ),
        (registration.agent_urn, AIAgentDependencies): SimpleNamespace(
            skills=[registration.skill_urn],
            tools=list(registration.tool_urns),
        ),
        (registration.agent_urn, UpstreamLineage): SimpleNamespace(
            upstreams=[
                SimpleNamespace(dataset=dataset)
                for dataset in registration.consumed_dataset_urns
            ]
        ),
    }
    for index, tool_urn in enumerate(registration.tool_urns):
        aspects[(tool_urn, ApiProperties)] = SimpleNamespace(
            name=f"DataHub MCP tool {index}"
        )
    return aspects


def _write_registration(path: Path, registration: DataHubAgentRegistryReport) -> None:
    path.write_text(registration.model_dump_json(indent=2) + "\n", encoding="utf-8")


def test_readback_verifies_skill_tools_agent_and_dataset_dependencies(tmp_path: Path) -> None:
    registration = _registration()
    registration_path = tmp_path / "registry.json"
    output = tmp_path / "verified.json"
    _write_registration(registration_path, registration)
    graph = FakeGraph(_aspects(registration))

    report = verify_datahub_agent_registry(
        registry_report=registration_path,
        output=output,
        graph=graph,
        bindings=_bindings(),
    )

    assert report.status == "verified"
    assert report.tool_count == 5
    assert report.required_tool_count == 5
    assert report.dependency_tool_count == 5
    assert report.dependency_skill_count == 1
    assert report.consumed_dataset_count == 5
    assert report.agent_urn == registration.agent_urn
    assert report.skill_urn == registration.skill_urn
    assert report.source_repository_url == registration.source_repository_url
    assert report.source_skill_path == registration.source_skill_path

    payload = json.loads(output.read_text(encoding="utf-8"))
    payload_without_hash = dict(payload)
    payload_without_hash.pop("report_sha256")
    assert payload["report_sha256"] == _report_hash(
        {**payload_without_hash, "report_sha256": "0" * 64}
    )


def test_readback_rejects_missing_required_tool_relationship(tmp_path: Path) -> None:
    registration = _registration()
    registration_path = tmp_path / "registry.json"
    _write_registration(registration_path, registration)
    aspects = _aspects(registration)
    aspects[(registration.skill_urn, AgentSkillInfo)].requiredTools = list(
        registration.tool_urns[:-1]
    )

    with pytest.raises(
        DataHubAgentRegistryVerificationError,
        match="required-tools mismatch",
    ):
        verify_datahub_agent_registry(
            registry_report=registration_path,
            output=tmp_path / "verified.json",
            graph=FakeGraph(aspects),
            bindings=_bindings(),
        )


def test_readback_rejects_missing_dataset_dependency(tmp_path: Path) -> None:
    registration = _registration()
    registration_path = tmp_path / "registry.json"
    _write_registration(registration_path, registration)
    aspects = _aspects(registration)
    aspects[(registration.agent_urn, UpstreamLineage)].upstreams = [
        SimpleNamespace(dataset=dataset)
        for dataset in registration.consumed_dataset_urns[:-1]
    ]

    with pytest.raises(
        DataHubAgentRegistryVerificationError,
        match="consumed-dataset lineage mismatch",
    ):
        verify_datahub_agent_registry(
            registry_report=registration_path,
            output=tmp_path / "verified.json",
            graph=FakeGraph(aspects),
            bindings=_bindings(),
        )


def test_readback_rejects_missing_api_entity(tmp_path: Path) -> None:
    registration = _registration()
    registration_path = tmp_path / "registry.json"
    _write_registration(registration_path, registration)
    aspects = _aspects(registration)
    aspects.pop((registration.tool_urns[-1], ApiProperties))

    with pytest.raises(
        DataHubAgentRegistryVerificationError,
        match="API tool properties were not persisted",
    ):
        verify_datahub_agent_registry(
            registry_report=registration_path,
            output=tmp_path / "verified.json",
            graph=FakeGraph(aspects),
            bindings=_bindings(),
        )
