"""Security-owned read-only DataHub discovery for the planning-only agent boundary."""

from __future__ import annotations

import re
from collections.abc import Callable

from pydantic import ValidationError

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
    RoleBoundDataHubMcpClient,
    RoleBoundDataHubMcpSettings,
)
from toxicjoin.integrations.datahub_mcp import (
    DataHubMcpTransport,
    StdioDataHubMcpTransport,
)

# P0 accepts the canonical three-part DataHub dataset URN shape used by ToxicJoin's governed
# asset manifest. Deliberately fail closed on exotic/ambiguous forms rather than treating a
# mere ``urn:li:dataset:`` prefix as resolved identity.
_DATASET_URN_PATTERN = re.compile(
    r"^urn:li:dataset:\("
    r"urn:li:dataPlatform:[A-Za-z0-9._-]+,"
    r"[A-Za-z0-9._:/%+~-]+,"
    r"[A-Za-z0-9._-]+"
    r"\)$"
)


class AgentDataHubDiscoveryError(RuntimeError):
    """Stable fail-closed error for agent-facing DataHub discovery."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


TransportFactory = Callable[[RoleBoundDataHubMcpSettings], DataHubMcpTransport]


class DataHubAgentDiscoverer:
    """Acquire one trusted DataHub snapshot and expose only a sanitized planning view.

    Discovery requires a dedicated role-bound READ_ONLY credential. Generic/legacy DataHub
    settings are not attenuated into a read credential because disabling MCP mutation tools does
    not reduce the authority of the underlying DataHub token.
    """

    def __init__(
        self,
        *,
        settings: RoleBoundDataHubMcpSettings,
        asset_map: DataHubAssetMap,
        transport_factory: TransportFactory = StdioDataHubMcpTransport,
    ) -> None:
        self._settings = _read_only_settings(settings)
        self._asset_map = DataHubAssetMap.model_validate(asset_map.model_dump(mode="json"))
        self._transport_factory = transport_factory

    async def discover(self) -> AgentDataContext:
        """Return one immutable, explicitly non-authoritative planning context."""

        # Everything inside this block is an external/pluggable I/O boundary. Never trust an
        # exception type raised from it, including AgentDataHubDiscoveryError itself: a malicious
        # transport could forge that exported type and attach credentials or endpoint material.
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

    Fixed identity failures are safe to expose as stable codes. All other projection failures are
    collapsed to ``AGENT_DATAHUB_PROJECTION_FAILED`` with exception chaining suppressed because
    Pydantic and other validators may include raw MCP-derived input in their error messages.
    """

    try:
        trusted = DataHubSnapshot.model_validate(snapshot.model_dump(mode="json"))
    except (AttributeError, ValidationError):
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


def _read_only_settings(
    settings: RoleBoundDataHubMcpSettings,
) -> RoleBoundDataHubMcpSettings:
    """Return a private copy of a dedicated role-bound READ_ONLY credential."""

    if not isinstance(settings, RoleBoundDataHubMcpSettings):
        raise AgentDataHubDiscoveryError("AGENT_DATAHUB_READ_ROLE_REQUIRED")
    if settings.role != DataHubMcpRole.READ_ONLY or settings.mutation_enabled:
        raise AgentDataHubDiscoveryError("AGENT_DATAHUB_READ_ROLE_REQUIRED")

    try:
        return RoleBoundDataHubMcpSettings(
            gms_url=settings.gms_url,
            gms_token=settings.gms_token,
            command=settings.command,
            args=tuple(settings.args),
            timeout_seconds=settings.timeout_seconds,
            mutation_enabled=False,
            role=DataHubMcpRole.READ_ONLY,
        )
    except (AttributeError, ValidationError, ValueError):
        raise AgentDataHubDiscoveryError("AGENT_DATAHUB_SETTINGS_INVALID") from None


def _is_canonical_dataset_urn(value: str) -> bool:
    if not isinstance(value, str) or len(value) > 2048:
        return False
    return _DATASET_URN_PATTERN.fullmatch(value) is not None
