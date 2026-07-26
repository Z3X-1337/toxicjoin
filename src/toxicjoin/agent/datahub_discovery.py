"""Security-owned read-only DataHub discovery for the planning-only agent boundary."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable
from urllib.parse import quote, unquote_to_bytes

from pydantic import BaseModel, SecretStr

from toxicjoin.agent.models import (
    AgentDataContext,
    AgentDatasetView,
    AgentFieldView,
    AgentLineageView,
    build_agent_data_context,
)
from toxicjoin.context.datahub import (
    DataHubAssetMap,
    DataHubSnapshot,
    DataHubSnapshotLoader,
)
from toxicjoin.integrations.datahub_authority import (
    DataHubMcpRole,
    ReadOnlyDataHubMcpSettings,
    RoleBoundDataHubMcpClient,
    read_only_credential_provenance_valid,
)
from toxicjoin.integrations.datahub_mcp import (
    DataHubMcpTransport,
    StdioDataHubMcpTransport,
)

_DATASET_URN_PATTERN = re.compile(
    r"^urn:li:dataset:\("
    r"urn:li:dataPlatform:(?P<platform>[^,()]+),"
    r"(?P<dataset>[^,()]+),"
    r"(?P<environment>[^,()]+)"
    r"\)$"
)
_PLATFORM_SAFE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
_DATASET_SAFE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._:/+~-"
_ENVIRONMENT_SAFE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"


class AgentDataHubDiscoveryError(RuntimeError):
    """Stable fail-closed error for agent-facing DataHub discovery."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


TransportFactory = Callable[[ReadOnlyDataHubMcpSettings], DataHubMcpTransport]


class DataHubAgentDiscoverer:
    """Acquire one trusted DataHub snapshot and expose only a sanitized planning view.

    Discovery requires a factory-issued dedicated READ_ONLY credential whose concrete type,
    private factory seal, and bearer-token fingerprint all remain intact. A settings object whose
    token or authority labels were copied/replaced is rejected before any transport is created.
    """

    def __init__(
        self,
        *,
        settings: ReadOnlyDataHubMcpSettings,
        asset_map: DataHubAssetMap,
        transport_factory: TransportFactory = StdioDataHubMcpTransport,
    ) -> None:
        self._settings = _read_only_settings(settings)
        self._asset_map = DataHubAssetMap.model_validate(asset_map.model_dump(mode="json"))
        self._transport_factory = transport_factory

    async def discover(self) -> AgentDataContext:
        """Return one immutable, explicitly non-authoritative planning context."""

        try:
            transport = self._transport_factory(self._settings)
            async with transport:
                client = RoleBoundDataHubMcpClient(
                    transport,
                    role=DataHubMcpRole.READ_ONLY,
                )
                snapshot = await DataHubSnapshotLoader(
                    client,
                    self._asset_map,
                ).load(require_mutations=False)
        except Exception:
            raise AgentDataHubDiscoveryError("AGENT_DATAHUB_DISCOVERY_FAILED") from None

        return build_agent_data_context_from_snapshot(snapshot)


def build_agent_data_context_from_snapshot(snapshot: DataHubSnapshot) -> AgentDataContext:
    """Project a validated DataHub snapshot into the planning-only agent schema.

    Snapshot serialization and validation are one redacted boundary because unconstrained
    MCP-derived payload fragments can contain non-JSON values or attacker-controlled details.
    Fixed identity failures remain stable codes; every other projection failure is collapsed.
    """

    try:
        serialized = snapshot.model_dump(mode="json")
        trusted = DataHubSnapshot.model_validate(serialized)
    except Exception:
        raise AgentDataHubDiscoveryError("AGENT_DATAHUB_SNAPSHOT_INVALID") from None

    try:
        return _project_trusted_snapshot(trusted)
    except AgentDataHubDiscoveryError:
        raise
    except Exception:
        raise AgentDataHubDiscoveryError("AGENT_DATAHUB_PROJECTION_FAILED") from None


def _project_trusted_snapshot(snapshot: DataHubSnapshot) -> AgentDataContext:
    dataset_views: list[AgentDatasetView] = []
    for logical_name, dataset in sorted(snapshot.catalog.datasets.items()):
        if not _is_canonical_dataset_urn(dataset.urn):
            raise AgentDataHubDiscoveryError("AGENT_DATAHUB_DATASET_IDENTITY_INVALID")

        field_views: list[AgentFieldView] = []
        for field_path, field in sorted(dataset.fields.items()):
            lineage_views: list[AgentLineageView] = []
            for source in field.lineage_sources:
                source_urn = source.datahub_urn
                if source_urn is None:
                    raise AgentDataHubDiscoveryError(
                        "AGENT_DATAHUB_LINEAGE_IDENTITY_UNRESOLVED"
                    )
                if not _is_canonical_dataset_urn(source_urn):
                    raise AgentDataHubDiscoveryError(
                        "AGENT_DATAHUB_LINEAGE_IDENTITY_INVALID"
                    )
                lineage_views.append(
                    AgentLineageView(
                        source_dataset_urn=source_urn,
                        source_field_path=source.ref.field_path,
                        category=source.category,
                        security_authoritative=False,
                    )
                )

            ordered_lineage = tuple(
                sorted(
                    lineage_views,
                    key=lambda item: (item.source_dataset_urn, item.source_field_path),
                )
            )
            if len({item.key for item in ordered_lineage}) != len(ordered_lineage):
                raise AgentDataHubDiscoveryError("AGENT_DATAHUB_LINEAGE_DUPLICATE")

            field_views.append(
                AgentFieldView(
                    field_path=field_path,
                    category=field.category,
                    tags=tuple(sorted(set(field.tags))),
                    glossary_terms=tuple(sorted(set(field.glossary_terms))),
                    lineage=ordered_lineage,
                    security_authoritative=False,
                )
            )

        dataset_views.append(
            AgentDatasetView(
                logical_name=logical_name,
                dataset_urn=dataset.urn,
                owner=dataset.owner,
                domain=dataset.domain,
                fields=tuple(field_views),
                security_authoritative=False,
            )
        )

    return build_agent_data_context(
        source_snapshot_sha256=snapshot.snapshot_sha256,
        catalog_version=snapshot.catalog.version,
        datasets=tuple(dataset_views),
    )


def _require_read_only_provenance(settings: object) -> None:
    """Validate read credential provenance without exposing malformed bearer internals."""

    try:
        valid = read_only_credential_provenance_valid(settings)
    except Exception:
        raise AgentDataHubDiscoveryError("AGENT_DATAHUB_SETTINGS_INVALID") from None
    if not valid:
        raise AgentDataHubDiscoveryError("AGENT_DATAHUB_READ_ROLE_REQUIRED")


def _read_only_settings(settings: ReadOnlyDataHubMcpSettings) -> ReadOnlyDataHubMcpSettings:
    """Return a detached private copy only when factory-issued read provenance is intact."""

    _require_read_only_provenance(settings)

    try:
        token_value = settings.gms_token.get_secret_value()
        copied = BaseModel.model_copy(
            settings,
            update={"gms_token": SecretStr(token_value)},
            deep=False,
        )
    except Exception:
        raise AgentDataHubDiscoveryError("AGENT_DATAHUB_SETTINGS_INVALID") from None

    _require_read_only_provenance(copied)
    try:
        shared_bearer = copied.gms_token is settings.gms_token
    except Exception:
        raise AgentDataHubDiscoveryError("AGENT_DATAHUB_SETTINGS_INVALID") from None
    if shared_bearer:
        raise AgentDataHubDiscoveryError("AGENT_DATAHUB_SETTINGS_INVALID")
    return copied


def _is_canonical_dataset_urn(value: str) -> bool:
    if not isinstance(value, str) or len(value) > 2048:
        return False
    match = _DATASET_URN_PATTERN.fullmatch(value)
    if match is None:
        return False

    platform = match.group("platform")
    dataset = match.group("dataset")
    environment = match.group("environment")
    if not _is_canonical_urn_component(platform, safe=_PLATFORM_SAFE):
        return False
    if not _is_canonical_urn_component(dataset, safe=_DATASET_SAFE):
        return False
    if not _is_canonical_urn_component(environment, safe=_ENVIRONMENT_SAFE):
        return False

    canonical = (
        "urn:li:dataset:(urn:li:dataPlatform:"
        f"{platform},{dataset},{environment})"
    )
    return canonical == value


def _is_canonical_urn_component(value: str, *, safe: str) -> bool:
    if not value:
        return False
    try:
        decoded = unquote_to_bytes(value).decode("utf-8", errors="strict")
    except (UnicodeDecodeError, ValueError):
        return False
    if not decoded:
        return False
    if any(
        character.isspace() or unicodedata.category(character).startswith("C")
        for character in decoded
    ):
        return False
    if any(character in ",()" for character in decoded):
        return False
    try:
        encoded = quote(decoded, safe=safe, encoding="utf-8", errors="strict")
    except (UnicodeEncodeError, ValueError):
        return False
    return encoded == value
