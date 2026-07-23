"""Independent read-back verification for the ToxicJoin DataHub Agent Registry graph."""

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

from toxicjoin.integrations.datahub_agent_registry import DataHubAgentRegistryReport
from toxicjoin.models import StrictModel


class DataHubAgentRegistryVerificationError(RuntimeError):
    """Raised when the persisted Agent Registry graph does not match the report."""


class DataHubAgentRegistryVerificationDependencyError(
    DataHubAgentRegistryVerificationError
):
    """Raised when required DataHub SDK read-back classes are unavailable."""


class DataHubAgentRegistryVerificationReport(StrictModel):
    schema_version: str = "1.0"
    created_at: datetime
    status: str = Field(pattern=r"^verified$")
    agent_urn: str = Field(pattern=r"^urn:li:aiAgent:")
    skill_urn: str = Field(pattern=r"^urn:li:agentSkill:")
    tool_urns: tuple[str, ...]
    tool_count: int = Field(ge=0)
    required_tool_count: int = Field(ge=0)
    dependency_tool_count: int = Field(ge=0)
    dependency_skill_count: int = Field(ge=0)
    consumed_dataset_count: int = Field(ge=0)
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
class DataHubAgentRegistryVerificationBindings:
    get_default_graph: Any
    AgentSkillInfoClass: Any
    AIAgentInfoClass: Any
    AIAgentDependenciesClass: Any
    ApiPropertiesClass: Any
    UpstreamLineageClass: Any


def verify_datahub_agent_registry(
    *,
    registry_report: str | Path,
    output: str | Path,
    graph: Any | None = None,
    bindings: DataHubAgentRegistryVerificationBindings | None = None,
) -> DataHubAgentRegistryVerificationReport:
    """Read persisted DataHub aspects from a fresh graph client and verify relations."""

    registration = DataHubAgentRegistryReport.model_validate_json(
        Path(registry_report).read_text(encoding="utf-8")
    )
    resolved_bindings = bindings or _load_bindings()

    if graph is not None:
        verified = _verify_graph(
            graph=graph,
            bindings=resolved_bindings,
            registration=registration,
        )
    else:
        try:
            with resolved_bindings.get_default_graph() as resolved_graph:
                verified = _verify_graph(
                    graph=resolved_graph,
                    bindings=resolved_bindings,
                    registration=registration,
                )
        except DataHubAgentRegistryVerificationError:
            raise
        except Exception as exc:
            raise DataHubAgentRegistryVerificationError(
                "unable to read back ToxicJoin Agent Registry graph"
            ) from exc

    _write_report_atomic(Path(output), verified)
    return verified


def _verify_graph(
    *,
    graph: Any,
    bindings: DataHubAgentRegistryVerificationBindings,
    registration: DataHubAgentRegistryReport,
) -> DataHubAgentRegistryVerificationReport:
    skill_info = graph.get_aspect(
        entity_urn=registration.skill_urn,
        aspect_type=bindings.AgentSkillInfoClass,
    )
    if skill_info is None:
        raise DataHubAgentRegistryVerificationError("agentSkillInfo was not persisted")

    source_repository = getattr(skill_info, "sourceRepository", None)
    source_url = getattr(source_repository, "url", None)
    source_path = getattr(source_repository, "path", None)
    if source_url != registration.source_repository_url:
        raise DataHubAgentRegistryVerificationError("Agent Skill repository URL mismatch")
    if source_path != registration.source_skill_path:
        raise DataHubAgentRegistryVerificationError("Agent Skill source path mismatch")

    required_tools = tuple(sorted(getattr(skill_info, "requiredTools", None) or ()))
    if required_tools != tuple(sorted(registration.tool_urns)):
        raise DataHubAgentRegistryVerificationError("Agent Skill required-tools mismatch")

    agent_info = graph.get_aspect(
        entity_urn=registration.agent_urn,
        aspect_type=bindings.AIAgentInfoClass,
    )
    if agent_info is None:
        raise DataHubAgentRegistryVerificationError("aiAgentInfo was not persisted")

    dependencies = graph.get_aspect(
        entity_urn=registration.agent_urn,
        aspect_type=bindings.AIAgentDependenciesClass,
    )
    if dependencies is None:
        raise DataHubAgentRegistryVerificationError(
            "aiAgentDependencies were not persisted"
        )
    dependency_skills = tuple(sorted(getattr(dependencies, "skills", None) or ()))
    dependency_tools = tuple(sorted(getattr(dependencies, "tools", None) or ()))
    if dependency_skills != (registration.skill_urn,):
        raise DataHubAgentRegistryVerificationError("AI Agent skill dependency mismatch")
    if dependency_tools != tuple(sorted(registration.tool_urns)):
        raise DataHubAgentRegistryVerificationError("AI Agent tool dependencies mismatch")

    lineage = graph.get_aspect(
        entity_urn=registration.agent_urn,
        aspect_type=bindings.UpstreamLineageClass,
    )
    if lineage is None:
        raise DataHubAgentRegistryVerificationError(
            "AI Agent dataset dependencies were not persisted"
        )
    consumed_datasets = tuple(
        sorted(
            str(getattr(upstream, "dataset"))
            for upstream in (getattr(lineage, "upstreams", None) or ())
        )
    )
    if consumed_datasets != tuple(sorted(registration.consumed_dataset_urns)):
        raise DataHubAgentRegistryVerificationError(
            "AI Agent consumed-dataset lineage mismatch"
        )

    discovered_tool_urns: list[str] = []
    for tool_urn in registration.tool_urns:
        properties = graph.get_aspect(
            entity_urn=tool_urn,
            aspect_type=bindings.ApiPropertiesClass,
        )
        if properties is None or not getattr(properties, "name", None):
            raise DataHubAgentRegistryVerificationError(
                f"API tool properties were not persisted: {tool_urn}"
            )
        discovered_tool_urns.append(tool_urn)

    created_at = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "created_at": created_at,
        "status": "verified",
        "agent_urn": registration.agent_urn,
        "skill_urn": registration.skill_urn,
        "tool_urns": tuple(sorted(discovered_tool_urns)),
        "tool_count": len(discovered_tool_urns),
        "required_tool_count": len(required_tools),
        "dependency_tool_count": len(dependency_tools),
        "dependency_skill_count": len(dependency_skills),
        "consumed_dataset_count": len(consumed_datasets),
        "source_repository_url": source_url,
        "source_skill_path": source_path,
        "report_sha256": "0" * 64,
    }
    payload["report_sha256"] = _report_hash(payload)
    return DataHubAgentRegistryVerificationReport.model_validate(payload)


def _load_bindings() -> DataHubAgentRegistryVerificationBindings:
    try:
        from datahub.ingestion.graph.client import get_default_graph
        from datahub.metadata.schema_classes import (
            AIAgentDependenciesClass,
            AIAgentInfoClass,
            AgentSkillInfoClass,
            ApiPropertiesClass,
            UpstreamLineageClass,
        )
    except ImportError as exc:
        raise DataHubAgentRegistryVerificationDependencyError(
            "install the live integration with: pip install -e '.[datahub]'"
        ) from exc

    return DataHubAgentRegistryVerificationBindings(
        get_default_graph=get_default_graph,
        AgentSkillInfoClass=AgentSkillInfoClass,
        AIAgentInfoClass=AIAgentInfoClass,
        AIAgentDependenciesClass=AIAgentDependenciesClass,
        ApiPropertiesClass=ApiPropertiesClass,
        UpstreamLineageClass=UpstreamLineageClass,
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


def _write_report_atomic(
    path: Path,
    report: DataHubAgentRegistryVerificationReport,
) -> None:
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
        description="Verify persisted ToxicJoin DataHub Agent Registry relationships"
    )
    parser.add_argument(
        "--registry-report",
        default=".toxicjoin/datahub-agent-registry.json",
        help="Registration report created by toxicjoin-datahub-agent-registry",
    )
    parser.add_argument(
        "--output",
        default=".toxicjoin/datahub-agent-registry-verified.json",
        help="Sanitized independent read-back report",
    )
    args = parser.parse_args()

    try:
        report = verify_datahub_agent_registry(
            registry_report=args.registry_report,
            output=args.output,
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
