"""Validated asynchronous client for the official DataHub MCP server.

The adapter discovers tools at runtime and checks their input schemas before any
operation. This prevents silent compatibility failures when the upstream MCP server
changes. The stable MCP Python SDK v1 is loaded lazily through the optional
``toxicjoin[datahub]`` extra so fixture mode remains lightweight.
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
from contextlib import AsyncExitStack
from typing import Any, Protocol, Self

from pydantic import Field, SecretStr

from toxicjoin.models import StrictModel


class DataHubMcpError(RuntimeError):
    """Base fail-closed DataHub MCP integration error."""


class DataHubMcpContractError(DataHubMcpError):
    """Raised when the live MCP server does not expose the expected contract."""


class DataHubMcpDependencyError(DataHubMcpError):
    """Raised when the optional official MCP SDK is not installed."""


class McpToolDefinition(StrictModel):
    name: str = Field(min_length=1)
    input_schema: dict[str, Any]

    @property
    def properties(self) -> dict[str, Any]:
        properties = self.input_schema.get("properties", {})
        return properties if isinstance(properties, dict) else {}


class DataHubMcpSettings(StrictModel):
    gms_url: str = Field(pattern=r"^https?://")
    gms_token: SecretStr
    command: str = Field(default="uvx", min_length=1)
    args: tuple[str, ...] = ("mcp-server-datahub",)
    timeout_seconds: float = Field(default=30.0, gt=0, le=300)
    mutation_enabled: bool = True

    @classmethod
    def from_env(cls) -> "DataHubMcpSettings":
        url = os.getenv("DATAHUB_GMS_URL")
        if not url:
            raise DataHubMcpError("DATAHUB_GMS_URL is required")
        if "DATAHUB_GMS_TOKEN" not in os.environ:
            raise DataHubMcpError(
                "DATAHUB_GMS_TOKEN must be set; use an explicit placeholder only "
                "for an auth-disabled local DataHub instance"
            )

        command = os.getenv("DATAHUB_MCP_COMMAND", "uvx").strip()
        raw_args = os.getenv("DATAHUB_MCP_ARGS", "mcp-server-datahub")
        args = tuple(shlex.split(raw_args))
        if not command or not args:
            raise DataHubMcpError("DataHub MCP command and arguments must not be empty")

        try:
            timeout = float(os.getenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30"))
        except ValueError as exc:
            raise DataHubMcpError(
                "DATAHUB_MCP_TIMEOUT_SECONDS must be numeric"
            ) from exc

        return cls(
            gms_url=url,
            gms_token=SecretStr(os.environ.get("DATAHUB_GMS_TOKEN", "")),
            command=command,
            args=args,
            timeout_seconds=timeout,
            mutation_enabled=True,
        )

    def child_environment(self) -> dict[str, str]:
        """Build a minimal environment for the MCP child process.

        Only operating-system and network variables needed to launch ``uvx`` are
        inherited. Unrelated application secrets are not forwarded.
        """

        inherited_keys = {
            "PATH",
            "HOME",
            "USERPROFILE",
            "APPDATA",
            "LOCALAPPDATA",
            "SYSTEMROOT",
            "WINDIR",
            "TEMP",
            "TMP",
            "TMPDIR",
            "UV_CACHE_DIR",
            "XDG_CACHE_HOME",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "NO_PROXY",
            "http_proxy",
            "https_proxy",
            "no_proxy",
        }
        environment = {
            key: value
            for key, value in os.environ.items()
            if key in inherited_keys
        }
        environment.update(
            {
                "DATAHUB_GMS_URL": self.gms_url,
                "DATAHUB_GMS_TOKEN": self.gms_token.get_secret_value(),
                "TOOLS_IS_MUTATION_ENABLED": (
                    "true" if self.mutation_enabled else "false"
                ),
                "DATAHUB_MCP_DOCUMENT_TOOLS_DISABLED": "false",
            }
        )
        return environment

    def redacted_summary(self) -> dict[str, Any]:
        return {
            "command": self.command,
            "args": list(self.args),
            "gms_scheme": self.gms_url.split(":", 1)[0],
            "token_present": bool(self.gms_token.get_secret_value()),
            "mutation_enabled": self.mutation_enabled,
            "timeout_seconds": self.timeout_seconds,
        }


class DataHubMcpTransport(Protocol):
    async def __aenter__(self) -> Self: ...

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None: ...

    async def list_tools(self) -> tuple[McpToolDefinition, ...]: ...

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any: ...


class StdioDataHubMcpTransport:
    """Official MCP SDK stdio transport for ``mcp-server-datahub``."""

    def __init__(self, settings: DataHubMcpSettings) -> None:
        self.settings = settings
        self._stack: AsyncExitStack | None = None
        self._session: Any = None

    async def __aenter__(self) -> Self:
        try:
            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client
        except ImportError as exc:
            raise DataHubMcpDependencyError(
                "install the optional integration with: pip install -e '.[datahub]'"
            ) from exc

        stack = AsyncExitStack()
        try:
            async with asyncio.timeout(self.settings.timeout_seconds):
                read_stream, write_stream = await stack.enter_async_context(
                    stdio_client(
                        StdioServerParameters(
                            command=self.settings.command,
                            args=list(self.settings.args),
                            env=self.settings.child_environment(),
                        )
                    )
                )
                session = await stack.enter_async_context(
                    ClientSession(read_stream, write_stream)
                )
                await session.initialize()
        except TimeoutError as exc:
            await stack.aclose()
            raise DataHubMcpError(
                "DataHub MCP session initialization timed out"
            ) from exc
        except Exception as exc:
            await stack.aclose()
            raise DataHubMcpError(
                "unable to initialize the DataHub MCP stdio session"
            ) from exc

        self._stack = stack
        self._session = session
        return self

    async def __aexit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        if self._stack is not None:
            await self._stack.aclose()
        self._stack = None
        self._session = None

    async def list_tools(self) -> tuple[McpToolDefinition, ...]:
        session = self._require_session()
        try:
            async with asyncio.timeout(self.settings.timeout_seconds):
                result = await session.list_tools()
        except TimeoutError as exc:
            raise DataHubMcpError("DataHub MCP list_tools timed out") from exc
        except Exception as exc:
            raise DataHubMcpError("DataHub MCP list_tools failed") from exc

        definitions: list[McpToolDefinition] = []
        for tool in getattr(result, "tools", ()):
            if hasattr(tool, "model_dump"):
                dumped = tool.model_dump(mode="json", by_alias=True)
            elif isinstance(tool, dict):
                dumped = tool
            else:
                dumped = {
                    "name": getattr(tool, "name", ""),
                    "inputSchema": getattr(
                        tool,
                        "inputSchema",
                        getattr(tool, "input_schema", {}),
                    ),
                }
            schema = dumped.get("inputSchema", dumped.get("input_schema", {}))
            definitions.append(
                McpToolDefinition(
                    name=str(dumped.get("name", "")),
                    input_schema=schema if isinstance(schema, dict) else {},
                )
            )
        return tuple(definitions)

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> Any:
        session = self._require_session()
        try:
            async with asyncio.timeout(self.settings.timeout_seconds):
                result = await session.call_tool(name, arguments=arguments)
        except TimeoutError as exc:
            raise DataHubMcpError(f"DataHub MCP tool timed out: {name}") from exc
        except Exception as exc:
            raise DataHubMcpError(f"DataHub MCP tool call failed: {name}") from exc

        is_error = bool(
            getattr(result, "isError", getattr(result, "is_error", False))
        )
        if is_error:
            raise DataHubMcpError(f"DataHub MCP tool returned an error: {name}")

        structured = getattr(
            result,
            "structuredContent",
            getattr(result, "structured_content", None),
        )
        if structured is not None:
            return _json_compatible(structured)

        content = getattr(result, "content", ())
        text_parts: list[str] = []
        for part in content:
            text = getattr(part, "text", None)
            if isinstance(part, dict):
                text = part.get("text", text)
            if isinstance(text, str):
                text_parts.append(text)
        if not text_parts:
            return None
        if len(text_parts) == 1:
            return _parse_json_or_text(text_parts[0])
        return tuple(_parse_json_or_text(part) for part in text_parts)

    def _require_session(self) -> Any:
        if self._session is None:
            raise DataHubMcpError("DataHub MCP transport is not connected")
        return self._session


_REQUIRED_READ_CONTRACTS: dict[str, set[str]] = {
    "get_entities": {"urns"},
    "list_schema_fields": {"urn", "keywords", "limit", "offset"},
    "get_lineage": {"urn", "column", "upstream", "max_hops"},
}
_REQUIRED_WRITE_CONTRACTS: dict[str, set[str]] = {
    "save_document": {
        "title",
        "content",
        "document_type",
        "related_assets",
    },
}


class DataHubMcpClient:
    """Validated high-level client for the official DataHub MCP tools."""

    def __init__(self, transport: DataHubMcpTransport) -> None:
        self.transport = transport
        self._tools: dict[str, McpToolDefinition] = {}

    async def discover_and_validate(
        self,
        *,
        require_mutations: bool,
    ) -> tuple[McpToolDefinition, ...]:
        definitions = await self.transport.list_tools()
        tools = {definition.name: definition for definition in definitions}
        expected = dict(_REQUIRED_READ_CONTRACTS)
        if require_mutations:
            expected.update(_REQUIRED_WRITE_CONTRACTS)

        failures: list[str] = []
        for tool_name, required_properties in expected.items():
            definition = tools.get(tool_name)
            if definition is None:
                failures.append(f"missing tool {tool_name}")
                continue
            missing = sorted(required_properties - set(definition.properties))
            if missing:
                failures.append(
                    f"tool {tool_name} missing input properties: {', '.join(missing)}"
                )

        save_document = tools.get("save_document")
        if require_mutations and save_document is not None:
            type_schema = save_document.properties.get("document_type", {})
            enum = type_schema.get("enum") if isinstance(type_schema, dict) else None
            if isinstance(enum, list) and "Decision" not in enum:
                failures.append("save_document does not allow document_type=Decision")

        if failures:
            raise DataHubMcpContractError("; ".join(failures))

        self._tools = tools
        return definitions

    async def get_entities(self, urns: tuple[str, ...]) -> tuple[dict[str, Any], ...]:
        if not urns:
            return ()
        payload = await self.transport.call_tool("get_entities", {"urns": list(urns)})
        payload = _unwrap_fastmcp_collection_result(payload)
        if not isinstance(payload, list) or not all(
            isinstance(item, dict) for item in payload
        ):
            raise DataHubMcpError("get_entities returned an unexpected payload")
        return tuple(payload)

    async def list_schema_fields(
        self,
        urn: str,
        *,
        keywords: tuple[str, ...] = (),
        page_size: int = 100,
        max_pages: int = 20,
    ) -> tuple[dict[str, Any], ...]:
        if not 1 <= page_size <= 1000:
            raise ValueError("page_size must be between 1 and 1000")
        if max_pages < 1:
            raise ValueError("max_pages must be positive")

        fields: list[dict[str, Any]] = []
        offset = 0
        for _ in range(max_pages):
            payload = await self.transport.call_tool(
                "list_schema_fields",
                {
                    "urn": urn,
                    "keywords": list(keywords),
                    "limit": page_size,
                    "offset": offset,
                },
            )
            if not isinstance(payload, dict):
                raise DataHubMcpError(
                    "list_schema_fields returned an unexpected payload"
                )
            page_fields = payload.get("fields")
            if not isinstance(page_fields, list) or not all(
                isinstance(item, dict) for item in page_fields
            ):
                raise DataHubMcpError("list_schema_fields payload has invalid fields")
            fields.extend(page_fields)

            remaining = payload.get("remainingCount", 0)
            if not isinstance(remaining, int):
                raise DataHubMcpError(
                    "list_schema_fields payload has invalid remainingCount"
                )
            if remaining <= 0:
                return tuple(fields)
            offset += len(page_fields)
            if not page_fields:
                raise DataHubMcpError(
                    "list_schema_fields reported remaining fields without progress"
                )

        raise DataHubMcpError("list_schema_fields exceeded the pagination safety limit")

    async def get_lineage(
        self,
        urn: str,
        *,
        column: str | None = None,
        upstream: bool = True,
        max_hops: int = 2,
        max_results: int = 100,
    ) -> dict[str, Any]:
        payload = await self.transport.call_tool(
            "get_lineage",
            {
                "urn": urn,
                "column": column,
                "upstream": upstream,
                "max_hops": max_hops,
                "max_results": max_results,
                "offset": 0,
            },
        )
        if not isinstance(payload, dict):
            raise DataHubMcpError(
                "get_lineage returned an unexpected payload"
            )

        relationships = payload.get("relationships")
        if relationships is not None:
            if not isinstance(relationships, list) or not all(
                isinstance(item, dict) for item in relationships
            ):
                raise DataHubMcpError(
                    "get_lineage payload has invalid relationships"
                )
        else:
            direction_key = "upstreams" if upstream else "downstreams"
            direction = payload.get(direction_key)
            if direction is None:
                relationships = []
            else:
                if not isinstance(direction, dict):
                    raise DataHubMcpError(
                        f"get_lineage payload has invalid {direction_key}"
                    )
                search_results = direction.get("searchResults", [])
                if not isinstance(search_results, list) or not all(
                    isinstance(item, dict) for item in search_results
                ):
                    raise DataHubMcpError(
                        "get_lineage payload has invalid searchResults"
                    )
                relationships = search_results

        normalized = dict(payload)
        normalized["relationships"] = relationships
        normalized["count"] = len(relationships)
        return normalized

    async def save_decision(
        self,
        *,
        title: str,
        content: str,
        related_assets: tuple[str, ...],
        external_url: str | None = None,
    ) -> str:
        arguments: dict[str, Any] = {
            "title": title,
            "content": content,
            "document_type": "Decision",
            "related_assets": list(related_assets),
        }
        if external_url is not None:
            arguments["external_url"] = external_url

        payload = await self.transport.call_tool("save_document", arguments)
        urn = _find_document_urn(payload)
        if urn is None:
            raise DataHubMcpError("save_document did not return a document URN")
        return urn

    async def read_entity(self, urn: str) -> dict[str, Any]:
        entities = await self.get_entities((urn,))
        if len(entities) != 1:
            raise DataHubMcpError(
                f"expected one entity for read-back, received {len(entities)}"
            )
        return entities[0]

    async def verify_document_marker(self, urn: str, marker: str) -> dict[str, Any]:
        definition = self._tools.get("grep_documents")
        if definition is None:
            raise DataHubMcpContractError(
                "missing tool grep_documents for independent document verification"
            )
        required = {
            "urns",
            "pattern",
            "context_chars",
            "max_matches_per_doc",
            "start_offset",
        }
        missing = sorted(required - set(definition.properties))
        if missing:
            raise DataHubMcpContractError(
                "tool grep_documents missing input properties: "
                + ", ".join(missing)
            )

        payload = await self.transport.call_tool(
            "grep_documents",
            {
                "urns": [urn],
                "pattern": marker,
                "context_chars": 160,
                "max_matches_per_doc": 3,
                "start_offset": 0,
            },
        )
        if not isinstance(payload, dict):
            raise DataHubMcpError(
                "grep_documents returned an unexpected payload"
            )
        results = payload.get("results")
        total_matches = payload.get("total_matches")
        if not isinstance(results, list) or not all(
            isinstance(item, dict) for item in results
        ):
            raise DataHubMcpError(
                "grep_documents payload has invalid results"
            )
        if not isinstance(total_matches, int):
            raise DataHubMcpError(
                "grep_documents payload has invalid total_matches"
            )

        for result in results:
            if result.get("urn") != urn:
                continue
            matches = result.get("matches")
            if not isinstance(matches, list):
                continue
            for match in matches:
                if (
                    isinstance(match, dict)
                    and marker in str(match.get("excerpt", ""))
                ):
                    return result

        if total_matches <= 0:
            raise DataHubMcpError(
                "independent document read-back did not contain the verification marker"
            )
        raise DataHubMcpError(
            "grep_documents reported matches without verifiable marker evidence"
        )


def _unwrap_fastmcp_collection_result(value: Any) -> Any:
    """Unwrap FastMCP's standard envelope for non-object output.

    FastMCP exposes list and primitive return values as ``{"result": value}``
    because MCP structured content must be an object. Only that exact one-key
    envelope is accepted; additional keys remain a contract failure.
    """

    if isinstance(value, dict) and set(value) == {"result"}:
        return value["result"]
    return value


def _parse_json_or_text(value: str) -> Any:
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value


def _json_compatible(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", by_alias=True)
    if isinstance(value, dict):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_compatible(item) for item in value]
    return value


def _find_document_urn(value: Any) -> str | None:
    if isinstance(value, str):
        if value.startswith("urn:li:document:"):
            return value
        return None
    if isinstance(value, dict):
        prioritized_keys = ("urn", "documentUrn", "document_urn")
        for key in prioritized_keys:
            candidate = value.get(key)
            found = _find_document_urn(candidate)
            if found is not None:
                return found
        for candidate in value.values():
            found = _find_document_urn(candidate)
            if found is not None:
                return found
    if isinstance(value, (list, tuple)):
        for candidate in value:
            found = _find_document_urn(candidate)
            if found is not None:
                return found
    return None
