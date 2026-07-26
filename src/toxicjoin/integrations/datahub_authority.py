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
import weakref
from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Any, Literal, Self

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
_PROTECTED_ROLE_FIELDS = frozenset(
    {"role", "mutation_enabled", "credential_source", "gms_token"}
)
_PROVENANCE_LOCK = RLock()


@dataclass(frozen=True, slots=True)
class _CredentialSnapshot:
    role: DataHubMcpRole
    credential_source: str
    gms_url: str
    command: str
    args: tuple[str, ...]
    timeout_seconds: float
    mutation_enabled: bool
    token_fingerprint: str


@dataclass(frozen=True, slots=True)
class _CapturedCredential:
    snapshot: _CredentialSnapshot
    token_value: str


@dataclass(frozen=True, slots=True)
class _CredentialRegistration:
    reference: weakref.ReferenceType[Any]
    snapshot: _CredentialSnapshot


_PROVENANCE_REGISTRY: dict[int, _CredentialRegistration] = {}


class RoleBoundDataHubMcpSettings(DataHubMcpSettings):
    """Base settings whose concrete subclass identifies local DataHub authority role."""

    role: DataHubMcpRole
    credential_source: str

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
    """Return whether a read settings object is an unchanged authority-registry issuance."""

    if type(settings) is not ReadOnlyDataHubMcpSettings:
        return False
    try:
        captured = _capture_credential(settings)
    except Exception:
        return False
    return _read_snapshot_shape_valid(captured.snapshot) and _registration_matches(
        settings,
        captured.snapshot,
    )


def clone_read_only_settings_for_child(
    settings: Any,
) -> ReadOnlyDataHubMcpSettings | None:
    """Issue a detached registered read credential only from an unchanged registered reader.

    ``None`` means the supplied object is well-formed but not an eligible read-factory issuance.
    Malformed credential internals raise and are expected to be collapsed by the caller's
    redaction boundary.
    """

    if type(settings) is not ReadOnlyDataHubMcpSettings:
        return None
    captured = _capture_credential(settings)
    if not _read_snapshot_shape_valid(captured.snapshot):
        return None
    if not _registration_matches(settings, captured.snapshot):
        return None

    clone = ReadOnlyDataHubMcpSettings(
        gms_url=captured.snapshot.gms_url,
        gms_token=SecretStr(captured.token_value),
        command=captured.snapshot.command,
        args=captured.snapshot.args,
        timeout_seconds=captured.snapshot.timeout_seconds,
    )
    _register_factory_credential(clone)
    return clone


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
        _register_factory_credential(settings)
        return settings
    if token_env != _WRITE_TOKEN_ENV:
        raise DataHubMcpError("mutation DataHub role requires the dedicated write token")
    settings = MutationDataHubMcpSettings(**common)
    _register_factory_credential(settings)
    return settings


def _read_snapshot_shape_valid(snapshot: _CredentialSnapshot) -> bool:
    return (
        snapshot.role is DataHubMcpRole.READ_ONLY
        and snapshot.mutation_enabled is False
        and snapshot.credential_source == _READ_TOKEN_ENV
    )


def _register_factory_credential(settings: RoleBoundDataHubMcpSettings) -> None:
    captured = _capture_credential(settings)
    key = id(settings)

    def _cleanup(reference: weakref.ReferenceType[Any], *, registry_key: int = key) -> None:
        with _PROVENANCE_LOCK:
            current = _PROVENANCE_REGISTRY.get(registry_key)
            if current is not None and current.reference is reference:
                _PROVENANCE_REGISTRY.pop(registry_key, None)

    reference = weakref.ref(settings, _cleanup)
    registration = _CredentialRegistration(
        reference=reference,
        snapshot=captured.snapshot,
    )
    with _PROVENANCE_LOCK:
        _PROVENANCE_REGISTRY[key] = registration


def _registration_matches(
    settings: RoleBoundDataHubMcpSettings,
    snapshot: _CredentialSnapshot,
) -> bool:
    with _PROVENANCE_LOCK:
        registration = _PROVENANCE_REGISTRY.get(id(settings))
        if registration is None or registration.reference() is not settings:
            return False
        registered = registration.snapshot

    return (
        registered.role is snapshot.role
        and registered.credential_source == snapshot.credential_source
        and registered.gms_url == snapshot.gms_url
        and registered.command == snapshot.command
        and registered.args == snapshot.args
        and registered.timeout_seconds == snapshot.timeout_seconds
        and registered.mutation_enabled is snapshot.mutation_enabled
        and hmac.compare_digest(
            registered.token_fingerprint,
            snapshot.token_fingerprint,
        )
    )


def _capture_credential(settings: RoleBoundDataHubMcpSettings) -> _CapturedCredential:
    role = settings.role
    if type(role) is not DataHubMcpRole:
        raise TypeError("DataHub credential role is malformed")
    mutation_enabled = settings.mutation_enabled
    if type(mutation_enabled) is not bool:
        raise TypeError("DataHub mutation flag is malformed")
    timeout_seconds = settings.timeout_seconds
    if type(timeout_seconds) is not float:
        raise TypeError("DataHub timeout is malformed")
    args = settings.args
    if type(args) is not tuple:
        raise TypeError("DataHub command arguments are malformed")

    credential_source = _exact_text(settings.credential_source)
    gms_url = _exact_text(settings.gms_url)
    command = _exact_text(settings.command)
    exact_args = tuple(_exact_text(argument) for argument in args)
    token_value = _secret_text(settings.gms_token)
    token_fingerprint = _credential_fingerprint_value(token_value)
    return _CapturedCredential(
        snapshot=_CredentialSnapshot(
            role=role,
            credential_source=credential_source,
            gms_url=gms_url,
            command=command,
            args=exact_args,
            timeout_seconds=timeout_seconds,
            mutation_enabled=mutation_enabled,
            token_fingerprint=token_fingerprint,
        ),
        token_value=token_value,
    )


def _secret_text(token: SecretStr) -> str:
    if type(token) is not SecretStr:
        raise TypeError("DataHub bearer wrapper is malformed")
    return _exact_text(token.get_secret_value())


def _exact_text(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError("DataHub credential text is malformed")
    exact = str.__str__(value)
    if type(exact) is not str:
        raise TypeError("DataHub credential text normalization failed")
    return exact


def _credential_fingerprint_value(value: str) -> str:
    return hashlib.sha256(
        b"toxicjoin:datahub-credential:v2\x00" + value.encode("utf-8")
    ).hexdigest()


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
