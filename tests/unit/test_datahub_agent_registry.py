from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from toxicjoin.integrations.datahub_agent_registry import (
    DataHubAgentRegistryBindings,
    _load_skill_instructions,
    _report_hash,
    build_agent_registry_plan,
    register_datahub_agent_registry,
)


ROOT = Path(__file__).parents[2]
SKILL = ROOT / "skills" / "compositional-risk-review" / "SKILL.md"


class FakeEmitter:
    def __init__(self) -> None:
        self.emitted: list[Any] = []


class FakeApiParam:
    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs


class FakeApi:
    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.urn = f"urn:li:api:{kwargs['id']}"

    def emit(self, emitter: FakeEmitter) -> str:
        emitter.emitted.append(self)
        return self.urn


class FakeSkillSourceRepository:
    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs


class FakeAgentSkill:
    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.urn = f"urn:li:agentSkill:{kwargs['id']}"

    def emit(self, emitter: FakeEmitter) -> str:
        emitter.emitted.append(self)
        return self.urn


class FakeAgent:
    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.urn = f"urn:li:aiAgent:{kwargs['id']}"

    def emit(self, emitter: FakeEmitter) -> str:
        emitter.emitted.append(self)
        return self.urn


def _unused_graph():
    raise AssertionError("explicit fake emitter should be used")


def _bindings() -> DataHubAgentRegistryBindings:
    return DataHubAgentRegistryBindings(
        get_default_graph=_unused_graph,
        Api=FakeApi,
        ApiParam=FakeApiParam,
        AgentSkill=FakeAgentSkill,
        SkillSourceRepository=FakeSkillSourceRepository,
        Agent=FakeAgent,
    )


def test_skill_is_git_backed_agent_skill_with_enforcement_boundary() -> None:
    content = SKILL.read_text(encoding="utf-8")
    instructions = _load_skill_instructions(SKILL)

    assert content.startswith("---\nname: compositional-risk-review\n")
    assert "description:" in content.split("---", 2)[1]
    assert not instructions.startswith("---")
    assert "deterministic policy engine remains the authority" in instructions
    assert "Never execute a `BLOCK` or unresolved `REWRITE` query" in instructions
    assert "grep_documents" in instructions


def test_registry_plan_links_five_mcp_tools_to_all_governed_datasets() -> None:
    plan = build_agent_registry_plan()

    assert [tool.tool_id for tool in plan.tools] == [
        "toxicjoin-datahub-mcp-get-entities",
        "toxicjoin-datahub-mcp-list-schema-fields",
        "toxicjoin-datahub-mcp-get-lineage",
        "toxicjoin-datahub-mcp-save-document",
        "toxicjoin-datahub-mcp-grep-documents",
    ]
    assert plan.skill_id == "toxicjoin-compositional-risk-review"
    assert plan.agent_id == "toxicjoin-privacy-firewall-agent"
    assert len(plan.consumed_dataset_urns) == 5
    assert all(urn.startswith("urn:li:dataset:") for urn in plan.consumed_dataset_urns)


def test_registry_emits_tools_skill_agent_and_self_verifying_report(tmp_path: Path) -> None:
    emitter = FakeEmitter()
    output = tmp_path / "agent-registry.json"

    report = register_datahub_agent_registry(
        output=output,
        skill_path=SKILL,
        emitter=emitter,
        bindings=_bindings(),
    )

    assert report.status == "registered"
    assert report.tool_count == 5
    assert report.skill_count == 1
    assert report.agent_count == 1
    assert len(report.tool_urns) == 5
    assert report.skill_urn == "urn:li:agentSkill:toxicjoin-compositional-risk-review"
    assert report.agent_urn == "urn:li:aiAgent:toxicjoin-privacy-firewall-agent"
    assert len(report.consumed_dataset_urns) == 5
    assert report.source_repository_url == "https://github.com/Z3X-1337/toxicjoin"
    assert report.source_skill_path == "skills/compositional-risk-review/SKILL.md"

    tools = [item for item in emitter.emitted if isinstance(item, FakeApi)]
    skills = [item for item in emitter.emitted if isinstance(item, FakeAgentSkill)]
    agents = [item for item in emitter.emitted if isinstance(item, FakeAgent)]
    assert len(tools) == 5
    assert len(skills) == 1
    assert len(agents) == 1

    skill = skills[0]
    assert skill.kwargs["required_tools"] == [tool.urn for tool in tools]
    assert skill.kwargs["source_repository"].kwargs == {
        "url": "https://github.com/Z3X-1337/toxicjoin",
        "path": "skills/compositional-risk-review/SKILL.md",
    }
    assert "deterministic policy engine remains the authority" in skill.kwargs[
        "instructions"
    ]

    agent = agents[0]
    assert agent.kwargs["skills"] == [skill.urn]
    assert agent.kwargs["tools"] == [tool.urn for tool in tools]
    assert tuple(agent.kwargs["consumes_datasets"]) == report.consumed_dataset_urns
    assert agent.kwargs["version"] == "0.1.0"

    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["report_sha256"] == report.report_sha256
    payload_without_hash = dict(payload)
    payload_without_hash.pop("report_sha256")
    assert report.report_sha256 == _report_hash(
        {**payload_without_hash, "report_sha256": "0" * 64}
    )

    encoded = output.read_text(encoding="utf-8").lower()
    assert "token" not in encoded
    assert "password" not in encoded
    assert "localhost" not in encoded
