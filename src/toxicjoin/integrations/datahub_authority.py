"""Least-privilege DataHub MCP settings, transports, and role-bound clients.

Secure/live ToxicJoin paths must not use an ambiguous MCP process that can both acquire
policy context and mutate DataHub. Read-only and mutation roles use distinct credential
environment variables, concrete credential types, and application-level capabilities. The
upstream DataHub MCP 0.6.x server registers ``save_document`` inside its general mutation
registration path, so the isolated writer must start that path but ToxicJoin places a
transport-level allowlist in front of it and exposes only ``save_document`` to the writer client.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import shlex
from enum import StrEnum
from typing import Any, Literal, Self

from pydantic import PrivateAttr, SecretStr

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
_READ_CREDENTIAL_SEAL = object()
_WRITE_CREDENTIAL_SEAL = object()
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
_PROTECTED_ROLE_FIELDS = frozenset(
    {"role", "mutation_enabled", "credential_source", "gms_token"}
)


class RoleBoundDataHubMcpSettings(DataHubMcpSettings):
    """Base settings whose concrete subclass identifies credential authority provenance."""

    role: DataHubMcpRole
    credential_source: str
    _factory_seal: object | None = PrivateAttr(default=None)
    _token_fingerprint: str | None = PrivateAttr(default=None)

    def child_environment(self) -> dict[str, str]:
        environment = super().child_environment()
        if self.role == DataHubMcpRole.READ_ONLY:
            environment["TOOLS_IS_MUTATION_ENABLED"] = "false"
            environment["DATAHUB_MCP_DOCUMENT_TOOLS_DISABLED"] = "false"
            environment["SAVE_DOCUMENT_TOOL_ENABLED"] = "false"
        else:
            environment["TOOLS_IS_MUTATION_ENABLED"] = "true"
            environment["DATAHUB_MCP_DOCUMENT_TOOLS_DISABLED"] = "false"
            environment["SAVE_DOCUMENT_TOOL_ENABLED"] = "true"
        return environment

    def redacted_summary(self) -> dict[str, Any]:
        summary = super().redacted_summary()
        summary["role"] = self.role.value
        summary["credential_source"] = self.credential_source
        summary["document_write_enabled"] = self.role == DataHubMcpRole.MUTATION
        summary["writer_transport_allowlist"] = (
            sorted(_WRITER_ALLOWED_TOOLS)
            if self.role == DataHubMcpRole.MUTATION
            else []
        )
        return summary

    def model_copy(
        self,
        *,
        update: dict[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        """Forbid changing credential authority or bearer-token material through model_copy."""

        if update and _PROTECTED_ROLE_FIELDS.intersection(update):
            raise ValueError(
                "DataHub credential authority/token fields cannot be changed by model_copy"
            )
        return super().model_copy(update=update, deep=deep)

    def _bind_factory_provenance(self, *, seal: object) -> None:
        self._factory_seal = seal
        self._token_fingerprint = _credential_fingerprint(self.gms_token)

    def _factory_provenance_matches(self, *, seal: object) -> bool:
        if self._factory_seal is not seal or self._token_fingerprint is None:
            return False
        return hmac.compare_digest(
            self._token_fingerprint,
            _credential_fingerprint(self.gms_token),
        )


class ReadOnlyDataHubMcpSettings(RoleBoundDataHubMcpSettings):
    """Credential type sourced only from the dedicated DataHub read-token channel."""

    role: Literal[DataHubMcpRole.READ_ONLY] = DataHubMcpRole.READ_ONLY
    mutation_enabled: Literal[False] = False
    credential_source: Literal["DATAHUB_GMS_READ_TOKEN"] = _READ_TOKEN_ENV


class MutationDataHubMcpSettings(RoleBoundDataHubMcpSettings):
    """Credential type sourced only from the dedicated DataHub writer-token channel."""

    role: Literal[DataHubMcpRole.MUTATION] = DataHubMcpRole.MUTATION
    mutation_enabled: Literal[True] = True
    credential_source: Literal["DATAHUB_GMS_WRITE_TOKEN"] = _WRITE_TOKEN_ENV


def read_only_credential_provenance_valid(settings: Any) -> bool:
    """Return whether settings were issued from the dedicated read-token factory unchanged."""

    return (
        type(settings) is ReadOnlyDataHubMcpSettings
        and settings.role == DataHubMcpRole.READ_ONLY
        and settings.mutation_enabled is False
        and settings.credential_source == _READ_TOKEN_ENV
        and settings._factory_provenance_matches(seal=_READ_CREDENTIAL_SEAL)
    )


def read_only_settings_from_env() -> ReadOnlyDataHubMcpSettings:
    """Build settings for a context/read-back process with all writes disabled."""

    settings = _settings_from_env(
        token_env=_READ_TOKEN_ENV,
        role=DataHubMcpRole.READ_ONLY,
    )
    assert isinstance(settings, ReadOnlyDataHubMcpSettings)
    return settings


def mutation_settings_from_env() -> MutationDataHubMcpSettings:
    """Build settings for the isolated Decision writer process."""

    settings = _settings_from_env(
        token_env=_WRITE_TOKEN_ENV,
        role=DataHubMcpRole.MUTATION,
    )
    assert isinstance(settings, MutationDataHubMcpSettings)
    return settings


def _settings_from_env(
    *,
    token_env: str,
    role: DataHubMcpRole,
) -> ReadOnlyDataHubMcpSettings | MutationDataHubMcpSettings:
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

    common = {
        "gms_url": url,
        "gms_token": SecretStr(os.environ[token_env]),
        "command": command,
        "args": args,
        "timeout_seconds": timeout,
    }
    if role == DataHubMcpRole.READ_ONLY:
        if token_env != _READ_TOKEN_ENV:
            raise DataHubMcpError("read-only DataHub role requires the dedicated read token")
        settings = ReadOnlyDataHubMcpSettings(**common)
        settings._bind_factory_provenance(seal=_READ_CREDENTIAL_SEAL)
        return settings
    if token_env != _WRITE_TOKEN_ENV:
        raise DataHubMcpError("mutation DataHub role requires the dedicated write token")
    settings = MutationDataHubMcpSettings(**common)
    settings._bind_factory_provenance(seal=_WRITE_CREDENTIAL_SEAL)
    return settings


def _credential_fingerprint(token: SecretStr) -> str:
    value = token.get_secret_value().encode("utf-8")
    return hashlib.sha256(b"toxicjoin:datahub-credential:v1\x00" + value).hexdigest()


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
