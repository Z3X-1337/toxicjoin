"""Security-owned read-only DataHub discovery for the planning-only agent boundary."""

from __future__ import annotations

from collections.abc import Callable

from pydantic import SecretStr, ValidationError

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
from toxicjoin.integrations.datahub_mcp import (
    DataHubMcpClient,
    DataHubMcpError,
    DataHubMcpSettings,
    DataHubMcpTransport,
    StdioDataHubMcpTransport,
)

_DATASET_URN_PREFIX = "urn:li:dataset:"


class AgentDataHubDiscoveryError(RuntimeError):
    """Stable fail-closed error for agent-facing DataHub discovery."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


TransportFactory = Callable[[DataHubMcpSettings], DataHubMcpTransport]


class DataHubAgentDiscoverer:
    """Acquire one trusted DataHub snapshot and expose only a sanitized planning view.

    The planner never receives this object, the MCP settings, credentials, transport, client,
    tool definitions, or mutation handles. The discoverer always creates a private settings
    copy with mutations disabled before opening the MCP transport.
    """

    def __init__(
        self,
        *,
        settings: DataHubMcpSettings,
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
                client = DataHubMcpClient(transport)
                snapshot = await DataHubSnapshotLoader(
                    client,
                    self._asset_map,
                ).load(require_mutations=False)
            return build_agent_data_context_from_snapshot(snapshot)
        except AgentDataHubDiscoveryError:
            raise
        except (DataHubMcpError, ValidationError, ValueError, TypeError):
            raise AgentDataHubDiscoveryError("AGENT_DATAHUB_DISCOVERY_FAILED") from None
        except Exception:
            # External transport implementations are untrusted I/O boundaries. Suppress the
            # exception chain because it may contain endpoint, credential, or payload data.
            raise AgentDataHubDiscoveryError("AGENT_DATAHUB_DISCOVERY_FAILED") from None


def build_agent_data_context_from_snapshot(snapshot: DataHubSnapshot) -> AgentDataContext:
    """Project a validated DataHub snapshot into the planning-only agent schema.

    This conversion deliberately fails closed if an upstream lineage edge lacks a DataHub
    dataset identity. Hiding that edge would give the planner a falsely complete picture.
    The returned categories and lineage remain planning hints only; they never become evidence
    or authorization facts through this function.
    """

    try:
        trusted = DataHubSnapshot.model_validate(snapshot.model_dump(mode="json"))
    except (AttributeError, ValidationError):
        raise AgentDataHubDiscoveryError("AGENT_DATAHUB_SNAPSHOT_INVALID") from None

    dataset_views: list[AgentDatasetView] = []
    for logical_name, dataset in sorted(trusted.catalog.datasets.items()):
        if not dataset.urn.startswith(_DATASET_URN_PREFIX):
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
                if not source_urn.startswith(_DATASET_URN_PREFIX):
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
        source_snapshot_sha256=trusted.snapshot_sha256,
        catalog_version=trusted.catalog.version,
        datasets=tuple(dataset_views),
    )


def _read_only_settings(settings: DataHubMcpSettings) -> DataHubMcpSettings:
    """Revalidate settings while forcing a private mutation-disabled credential surface."""

    try:
        return DataHubMcpSettings(
            gms_url=settings.gms_url,
            gms_token=SecretStr(settings.gms_token.get_secret_value()),
            command=settings.command,
            args=tuple(settings.args),
            timeout_seconds=settings.timeout_seconds,
            mutation_enabled=False,
        )
    except (AttributeError, ValidationError, ValueError):
        raise AgentDataHubDiscoveryError("AGENT_DATAHUB_SETTINGS_INVALID") from None
