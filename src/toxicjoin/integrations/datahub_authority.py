"""Least-privilege DataHub MCP settings, transports, and role-bound clients.

Secure/live ToxicJoin paths must not use an ambiguous MCP process that can both acquire
policy context and mutate DataHub. Read-only and mutation roles use distinct credential
environment variables and application-level capabilities. The upstream DataHub MCP 0.6.x
server registers ``save_document`` inside its general mutation registration path, so the
isolated writer must start that path but ToxicJoin places a transport-level allowlist in
front of it and exposes only ``save_document`` to the writer client.
"""

from __future__ import annotations

import os
import shlex
from enum import StrEnum
from typing import Any

from pydantic import SecretStr

from toxicjoin.integrations.datahub_mcp import (
    DataHubMcpClient,
    DataHubMcpContractError,
    DataHubMcpError,
    DataHubMcpSettings,
    DataHubMcpTransport,
    McpToolDefinition,
)


class DataHubMcpRole(StrEnum):
    READ_ONLY = "read_only"
    MUTATION = "mutation"


_READ_TOKEN_ENV = "DATAHUB_GMS_READ_TOKEN"
_WRITE_TOKEN_ENV = "DATAHUB_GMS_WRITE_TOKEN"
_MUTATION_PREFIXES = (
    "add_",
    "remove_",
    "set_",
    "update_",
    "create_",
    "delete_",
    "upsert_",
    "patch_",
)
_MUTATION_TOOL_NAMES = {"save_document"}
_REQUIRED_SAVE_DOCUMENT_PROPERTIES = {
    "title",
    "content",
    "document_type",
    "related_assets",
}
_WRITER_ALLOWED_TOOLS = frozenset({"save_document"})


class RoleBoundDataHubMcpSettings(DataHubMcpSettings):
    """MCP settings that force upstream tool registration for one authority role."""

    role: DataHubMcpRole

    def child_environment(self) -> dict[str, str]:
        environment = super().child_environment()
        if self.role == DataHubMcpRole.READ_ONLY:
            environment["TOOLS_IS_MUTATION_ENABLED"] = "false"
            environment["DATAHUB_MCP_DOCUMENT_TOOLS_DISABLED"] = "false"
            environment["SAVE_DOCUMENT_TOOL_ENABLED"] = "false"
        else:
            # mcp-server-datahub 0.6.x only registers save_document from inside
            # register_mutation_tools(), so this switch must be true for the isolated
            # writer child. ToolAllowlistTransport is mandatory at the ToxicJoin
            # boundary and permits save_document only.
            environment["TOOLS_IS_MUTATION_ENABLED"] = "true"
            environment["DATAHUB_MCP_DOCUMENT_TOOLS_DISABLED"] = "false"
            environment["SAVE_DOCUMENT_TOOL_ENABLED"] = "true"
        return environment

    def redacted_summary(self) -> dict[str, Any]:
        summary = super().redacted_summary()
        summary["role"] = self.role.value
        summary["document_write_enabled"] = self.role == DataHubMcpRole.MUTATION
        summary["writer_transport_allowlist"] = (
            sorted(_WRITER_ALLOWED_TOOLS)
            if self.role == DataHubMcpRole.MUTATION
            else []
        )
        return summary


def read_only_settings_from_env() -> RoleBoundDataHubMcpSettings:
    """Build settings for a context/read-back process with all writes disabled."""

    return _settings_from_env(
        token_env=_READ_TOKEN_ENV,
        role=DataHubMcpRole.READ_ONLY,
    )


def mutation_settings_from_env() -> RoleBoundDataHubMcpSettings:
    """Build settings for the isolated Decision writer process."""

    return _settings_from_env(
        token_env=_WRITE_TOKEN_ENV,
        role=DataHubMcpRole.MUTATION,
    )


def _settings_from_env(
    *,
    token_env: str,
    role: DataHubMcpRole,
) -> RoleBoundDataHubMcpSettings:
    url = os.getenv("DATAHUB_GMS_URL")
    if not url:
        raise DataHubMcpError("DATAHUB_GMS_URL is required")
    if token_env not in os.environ:
        raise DataHubMcpError(f"{token_env} must be set for the DataHub MCP role")

    command = os.getenv("DATAHUB_MCP_COMMAND", "uvx").strip()
    args = tuple(shlex.split(os.getenv("DATAHUB_MCP_ARGS", "mcp-server-datahub")))
    if not command or not args:
        raise DataHubMcpError("DataHub MCP command and arguments must not be empty")
    try:
        timeout = float(os.getenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30"))
    except ValueError as exc:
        raise DataHubMcpError("DATAHUB_MCP_TIMEOUT_SECONDS must be numeric") from exc

    return RoleBoundDataHubMcpSettings(
        gms_url=url,
        gms_token=SecretStr(os.environ[token_env]),
        command=command,
        args=args,
        timeout_seconds=timeout,
        mutation_enabled=role == DataHubMcpRole.MUTATION,
        role=role,
    )


class ToolAllowlistTransport:
    """Filter MCP discovery and calls before a privileged child reaches ToxicJoin code.

    The raw server inventory is retained for evidence so an allowlist cannot make the
    upstream capability set appear narrower than it really is.
    """

    def __init__(
        self,
        delegate: DataHubMcpTransport,
        *,
        allowed_tools: frozenset[str],
    ) -> None:
        if not allowed_tools:
            raise ValueError("MCP tool allowlist must not be empty")
        self._delegate = delegate
        self.allowed_tools = allowed_tools
        self.raw_tool_names: tuple[str, ...] = ()

    async def list_tools(self) -> tuple[McpToolDefinition, ...]:
        definitions = await self._delegate.list_tools()
        self.raw_tool_names = tuple(sorted(definition.name for definition in definitions))
        return tuple(
            definition
            for definition in definitions
            if definition.name in self.allowed_tools
        )

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        if name not in self.allowed_tools:
            raise DataHubMcpContractError(
                f"DataHub MCP tool {name} is outside the writer transport allowlist"
            )
        return await self._delegate.call_tool(name, arguments)


def writer_allowlisted_transport(delegate: DataHubMcpTransport) -> ToolAllowlistTransport:
    """Return the mandatory save_document-only transport for the writer role."""

    return ToolAllowlistTransport(delegate, allowed_tools=_WRITER_ALLOWED_TOOLS)


class RoleBoundDataHubMcpClient(DataHubMcpClient):
    """DataHub client whose local API is constrained to one explicit authority role."""

    def __init__(self, transport: DataHubMcpTransport, *, role: DataHubMcpRole) -> None:
        super().__init__(transport)
        self.role = role

    async def discover_and_validate(
        self,
        *,
        require_mutations: bool,
    ) -> tuple[McpToolDefinition, ...]:
        expected_mutation = self.role == DataHubMcpRole.MUTATION
        if require_mutations != expected_mutation:
            raise DataHubMcpContractError(
                f"DataHub MCP role {self.role.value} cannot validate the requested authority"
            )

        if self.role == DataHubMcpRole.READ_ONLY:
            definitions = await super().discover_and_validate(require_mutations=False)
            exposed_mutations = sorted(
                definition.name
                for definition in definitions
                if _looks_mutating(definition.name)
            )
            if exposed_mutations:
                raise DataHubMcpContractError(
                    "read-only DataHub MCP process exposed mutation tools: "
                    + ", ".join(exposed_mutations)
                )
            return definitions

        definitions = await self.transport.list_tools()
        tools = {definition.name: definition for definition in definitions}
        unexpected = sorted(set(tools) - _WRITER_ALLOWED_TOOLS)
        if unexpected:
            raise DataHubMcpContractError(
                "writer transport exposed tools outside allowlist: "
                + ", ".join(unexpected)
            )
        save_document = tools.get("save_document")
        failures: list[str] = []
        if save_document is None:
            failures.append("missing tool save_document")
        else:
            missing = sorted(
                _REQUIRED_SAVE_DOCUMENT_PROPERTIES - set(save_document.properties)
            )
            if missing:
                failures.append(
                    "tool save_document missing input properties: " + ", ".join(missing)
                )
            type_schema = save_document.properties.get("document_type", {})
            enum = type_schema.get("enum") if isinstance(type_schema, dict) else None
            if isinstance(enum, list) and "Decision" not in enum:
                failures.append("save_document does not allow document_type=Decision")
        if failures:
            raise DataHubMcpContractError("; ".join(failures))
        self._tools = tools
        return definitions

    async def save_decision(
        self,
        *,
        title: str,
        content: str,
        related_assets: tuple[str, ...],
        external_url: str | None = None,
    ) -> str:
        self._require_mutation_role()
        return await super().save_decision(
            title=title,
            content=content,
            related_assets=related_assets,
            external_url=external_url,
        )

    async def get_entities(self, urns: tuple[str, ...]) -> tuple[dict[str, Any], ...]:
        self._require_read_role()
        return await super().get_entities(urns)

    async def list_schema_fields(
        self,
        urn: str,
        *,
        keywords: tuple[str, ...] = (),
        page_size: int = 100,
        max_pages: int = 20,
    ) -> tuple[dict[str, Any], ...]:
        self._require_read_role()
        return await super().list_schema_fields(
            urn,
            keywords=keywords,
            page_size=page_size,
            max_pages=max_pages,
        )

    async def get_lineage(
        self,
        urn: str,
        *,
        column: str | None = None,
        upstream: bool = True,
        max_hops: int = 2,
        max_results: int = 100,
    ) -> dict[str, Any]:
        self._require_read_role()
        return await super().get_lineage(
            urn,
            column=column,
            upstream=upstream,
            max_hops=max_hops,
            max_results=max_results,
        )

    async def read_entity(self, urn: str) -> dict[str, Any]:
        self._require_read_role()
        return await super().read_entity(urn)

    async def verify_document_marker(self, urn: str, marker: str) -> dict[str, Any]:
        self._require_read_role()
        return await super().verify_document_marker(urn, marker)

    def _require_read_role(self) -> None:
        if self.role != DataHubMcpRole.READ_ONLY:
            raise DataHubMcpContractError(
                "mutation-only DataHub MCP client cannot acquire governed read context"
            )

    def _require_mutation_role(self) -> None:
        if self.role != DataHubMcpRole.MUTATION:
            raise DataHubMcpContractError(
                "read-only DataHub MCP client cannot perform mutations"
            )


def _looks_mutating(tool_name: str) -> bool:
    return tool_name in _MUTATION_TOOL_NAMES or tool_name.startswith(_MUTATION_PREFIXES)
