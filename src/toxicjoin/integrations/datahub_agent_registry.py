"""Register ToxicJoin as a reusable DataHub Agent Skill and governed AI Agent.

The Agent Registry graph is deliberately separate from the privacy enforcement path.
The skill documents how agents should gather governed evidence; ToxicJoin's
deterministic policy engine remains the authority for BLOCK / REWRITE / ALLOW.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator

from toxicjoin.demo import default_fixture_catalog
from toxicjoin.models import StrictModel


class DataHubAgentRegistryError(RuntimeError):
    """Fail-closed Agent Registry integration error."""


class DataHubAgentRegistryDependencyError(DataHubAgentRegistryError):
    """Raised when the optional DataHub Agent Registry SDK is unavailable."""


class AgentToolSpec(StrictModel):
    tool_id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    parameters: tuple[tuple[str, str, bool, str], ...]
    returns: tuple[tuple[str, str, bool, str], ...] = ()


class DataHubAgentRegistryPlan(StrictModel):
    version: str = "1.0"
    repository_url: str = "https://github.com/Z3X-1337/toxicjoin"
    skill_path: str = "skills/compositional-risk-review/SKILL.md"
    skill_id: str = "toxicjoin-compositional-risk-review"
    skill_name: str = "Compositional Risk Review"
    agent_id: str = "toxicjoin-privacy-firewall-agent"
    agent_name: str = "ToxicJoin Privacy Firewall Agent"
    tools: tuple[AgentToolSpec, ...]
    consumed_dataset_urns: tuple[str, ...]


class DataHubAgentRegistryReport(StrictModel):
    schema_version: str = "1.0"
    created_at: datetime
    status: str = Field(pattern=r"^registered$")
    tool_count: int = Field(ge=0)
    skill_count: int = Field(ge=0)
    agent_count: int = Field(ge=0)
    tool_urns: tuple[str, ...]
    skill_urn: str = Field(pattern=r"^urn:li:agentSkill:")
    agent_urn: str = Field(pattern=r"^urn:li:aiAgent:")
    consumed_dataset_urns: tuple[str, ...]
    source_repository_url: str
    source_skill_path: str
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("created_at")
    @classmethod
    def normalize_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class DataHubAgentRegistryBindings:
    get_default_graph: Any
    Api: Any
    ApiParam: Any
    AgentSkill: Any
    SkillSourceRepository: Any
    Agent: Any


_TOOL_SPECS: tuple[AgentToolSpec, ...] = (
    AgentToolSpec(
        tool_id="toxicjoin-datahub-mcp-get-entities",
        name="DataHub MCP get_entities",
        description="Read governed DataHub entities by exact URN before policy evaluation.",
        parameters=(("urns", "array<string>", True, "Exact DataHub entity URNs to resolve."),),
        returns=(("entities", "array<object>", True, "Resolved governed entities."),),
    ),
    AgentToolSpec(
        tool_id="toxicjoin-datahub-mcp-list-schema-fields",
        name="DataHub MCP list_schema_fields",
        description="Read governed schema fields with bounded pagination for a dataset URN.",
        parameters=(
            ("urn", "string", True, "Dataset URN whose schema is required."),
            ("keywords", "array<string>", False, "Optional field filters."),
            ("limit", "integer", True, "Bounded page size."),
            ("offset", "integer", True, "Pagination offset."),
        ),
        returns=(("fields", "array<object>", True, "Governed schema-field records."),),
    ),
    AgentToolSpec(
        tool_id="toxicjoin-datahub-mcp-get-lineage",
        name="DataHub MCP get_lineage",
        description="Inspect upstream DataHub lineage for derived or sensitive fields.",
        parameters=(
            ("urn", "string", True, "Asset URN to inspect."),
            ("column", "string", False, "Optional field path for column lineage."),
            ("upstream", "boolean", True, "Read upstream rather than downstream lineage."),
            ("max_hops", "integer", True, "Bounded lineage traversal depth."),
        ),
        returns=(("lineage", "object", True, "Normalized lineage relationships."),),
    ),
    AgentToolSpec(
        tool_id="toxicjoin-datahub-mcp-save-document",
        name="DataHub MCP save_document",
        description="Persist a sanitized ToxicJoin Decision related to governed assets.",
        parameters=(
            ("title", "string", True, "Decision title."),
            ("content", "string", True, "Sanitized decision evidence."),
            ("document_type", "string", True, "Must be Decision for ToxicJoin write-back."),
            ("related_assets", "array<string>", True, "Governed asset URNs related to the decision."),
        ),
        returns=(("document_urn", "string", True, "Persisted DataHub document URN."),),
    ),
    AgentToolSpec(
        tool_id="toxicjoin-datahub-mcp-grep-documents",
        name="DataHub MCP grep_documents",
        description="Verify persisted Decision content from a fresh MCP process.",
        parameters=(
            ("query", "string", True, "Unique decision verification marker."),
            ("urns", "array<string>", True, "Document URNs to search."),
        ),
        returns=(("matches", "array<object>", True, "Persisted document matches and snippets."),),
    ),
)


def build_agent_registry_plan() -> DataHubAgentRegistryPlan:
    """Build the deterministic DataHub Agent Registry graph."""

    dataset_urns = tuple(
        sorted(dataset.urn for dataset in default_fixture_catalog().datasets.values())
    )
    return DataHubAgentRegistryPlan(
        tools=_TOOL_SPECS,
        consumed_dataset_urns=dataset_urns,
    )


def register_datahub_agent_registry(
    *,
    output: str | Path,
    skill_path: str | Path = "skills/compositional-risk-review/SKILL.md",
    emitter: Any | None = None,
    bindings: DataHubAgentRegistryBindings | None = None,
) -> DataHubAgentRegistryReport:
    """Register APIs, Agent Skill, and AI Agent; persist a sanitized report."""

    resolved_bindings = bindings or _load_sdk_bindings()
    plan = build_agent_registry_plan()
    skill_file = Path(skill_path)
    instructions = _load_skill_instructions(skill_file)

    if emitter is not None:
        report = _register(
            emitter=emitter,
            bindings=resolved_bindings,
            plan=plan,
            instructions=instructions,
        )
    else:
        try:
            with resolved_bindings.get_default_graph() as resolved_emitter:
                report = _register(
                    emitter=resolved_emitter,
                    bindings=resolved_bindings,
                    plan=plan,
                    instructions=instructions,
                )
        except Exception as exc:
            raise DataHubAgentRegistryError(
                "unable to register ToxicJoin Agent Registry graph"
            ) from exc

    _write_report_atomic(Path(output), report)
    return report


def _register(
    *,
    emitter: Any,
    bindings: DataHubAgentRegistryBindings,
    plan: DataHubAgentRegistryPlan,
    instructions: str,
) -> DataHubAgentRegistryReport:
    tool_urns: list[str] = []
    for spec in plan.tools:
        tool = bindings.Api(
            id=spec.tool_id,
            name=spec.name,
            subtypes=["MCP_TOOL"],
            description=spec.description,
            external_url="https://github.com/acryldata/mcp-server-datahub",
            parameters=[
                bindings.ApiParam(
                    name=name,
                    data_type=data_type,
                    required=required,
                    description=description,
                )
                for name, data_type, required, description in spec.parameters
            ],
            returns=[
                bindings.ApiParam(
                    name=name,
                    data_type=data_type,
                    required=required,
                    description=description,
                )
                for name, data_type, required, description in spec.returns
            ]
            or None,
        )
        tool_urns.append(str(tool.emit(emitter)))

    skill = bindings.AgentSkill(
        id=plan.skill_id,
        name=plan.skill_name,
        description=(
            "Gather governed DataHub evidence for agent-generated analytical SQL and "
            "apply ToxicJoin compositional-risk review before execution."
        ),
        instructions=instructions,
        source_repository=bindings.SkillSourceRepository(
            url=plan.repository_url,
            path=plan.skill_path,
        ),
        required_tools=tool_urns,
    )
    skill_urn = str(skill.emit(emitter))

    agent = bindings.Agent(
        id=plan.agent_id,
        name=plan.agent_name,
        source_type="EXTERNAL",
        description=(
            "Pre-execution compositional privacy firewall for governed analytical SQL. "
            "The DataHub skill gathers context; deterministic ToxicJoin policy owns "
            "BLOCK, REWRITE, and ALLOW enforcement."
        ),
        instructions=(
            "Adopt the Compositional Risk Review skill before any supported analytical "
            "SQL execution. Never override a deterministic BLOCK, unresolved REWRITE, "
            "metadata failure, rewrite failure, or verification failure."
        ),
        skills=[skill_urn],
        tools=tool_urns,
        consumes_datasets=list(plan.consumed_dataset_urns),
        version="0.1.0",
        version_comment="Initial hackathon Agent Registry integration.",
    )
    agent_urn = str(agent.emit(emitter))

    created_at = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "created_at": created_at,
        "status": "registered",
        "tool_count": len(tool_urns),
        "skill_count": 1,
        "agent_count": 1,
        "tool_urns": tuple(sorted(tool_urns)),
        "skill_urn": skill_urn,
        "agent_urn": agent_urn,
        "consumed_dataset_urns": plan.consumed_dataset_urns,
        "source_repository_url": plan.repository_url,
        "source_skill_path": plan.skill_path,
        "report_sha256": "0" * 64,
    }
    payload["report_sha256"] = _report_hash(payload)
    return DataHubAgentRegistryReport.model_validate(payload)


def _load_skill_instructions(path: Path) -> str:
    try:
        content = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise DataHubAgentRegistryError(f"unable to read Agent Skill: {path}") from exc

    if not content.startswith("---\n"):
        raise DataHubAgentRegistryError("Agent Skill must start with YAML frontmatter")
    closing = content.find("\n---\n", 4)
    if closing == -1:
        raise DataHubAgentRegistryError("Agent Skill YAML frontmatter is not closed")
    body = content[closing + 5 :].strip()
    if not body:
        raise DataHubAgentRegistryError("Agent Skill instructions must not be empty")
    return body


def _load_sdk_bindings() -> DataHubAgentRegistryBindings:
    try:
        from datahub.api.entities.agent.agent import Agent
        from datahub.api.entities.agent.agent_skill import AgentSkill, SkillSourceRepository
        from datahub.api.entities.agent.api import Api, ApiParam
        from datahub.ingestion.graph.client import get_default_graph
    except ImportError as exc:
        raise DataHubAgentRegistryDependencyError(
            "install the Agent Registry preview with: pip install -e '.[agent-registry]'"
        ) from exc

    return DataHubAgentRegistryBindings(
        get_default_graph=get_default_graph,
        Api=Api,
        ApiParam=ApiParam,
        AgentSkill=AgentSkill,
        SkillSourceRepository=SkillSourceRepository,
        Agent=Agent,
    )


def _report_hash(payload: dict[str, Any]) -> str:
    canonical_payload = {
        key: _json_compatible(value)
        for key, value in payload.items()
        if key != "report_sha256"
    }
    canonical = json.dumps(
        canonical_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _write_report_atomic(path: Path, report: DataHubAgentRegistryReport) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (
        json.dumps(
            report.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
        )
        + "\n"
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


def _json_compatible(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, dict):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_compatible(item) for item in value]
    return value


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Register ToxicJoin Agent Skill, MCP tool APIs, and AI Agent in DataHub"
    )
    parser.add_argument(
        "--output",
        default=".toxicjoin/datahub-agent-registry.json",
        help="Sanitized Agent Registry evidence report",
    )
    parser.add_argument(
        "--skill-path",
        default="skills/compositional-risk-review/SKILL.md",
        help="Git-backed Agent Skill definition",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Required explicit acknowledgement that live DataHub metadata will be mutated",
    )
    args = parser.parse_args()

    if not args.yes:
        parser.error("--yes is required because this command mutates live DataHub metadata")

    try:
        report = register_datahub_agent_registry(
            output=args.output,
            skill_path=args.skill_path,
        )
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "error_type": type(exc).__name__,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        raise SystemExit(1) from exc

    print(report.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
