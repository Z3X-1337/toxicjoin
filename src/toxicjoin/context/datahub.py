"""Live DataHub metadata snapshot and normalized context resolution.

The live adapter never asks the policy engine to understand DataHub-specific response
shapes. It validates an explicit logical-name-to-URN manifest, reads entities and
schema fields through the official MCP server, classifies direct field metadata, then
binds complete column-level upstream lineage into the same governed catalog consumed by
the deterministic policy engine.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator, model_validator

from toxicjoin.context.fixture import (
    FixtureCatalog,
    FixtureContextResolver,
    FixtureDataset,
    FixtureField,
)
from toxicjoin.context.governance import GovernanceContextBinding
from toxicjoin.context.models import ContextResolution
from toxicjoin.integrations.datahub_mcp import DataHubMcpClient, DataHubMcpError
from toxicjoin.models import (
    ColumnRef,
    LineageSource,
    QueryPlan,
    SensitivityCategory,
    StrictModel,
)


class DataHubMetadataError(DataHubMcpError):
    """Raised when live DataHub metadata cannot be normalized safely."""


_DEFAULT_MAX_SNAPSHOT_AGE_SECONDS = 300.0
_MAX_SNAPSHOT_AGE_SECONDS = 3600.0
_LINEAGE_MAX_RESULTS = 100
_LINEAGE_UNLIMITED_HOPS = 3


class DataHubAssetMap(StrictModel):
    version: str = Field(min_length=1)
    datasets: dict[str, str]
    flagship_dataset: str = Field(min_length=1)
    flagship_column: str | None = None

    @model_validator(mode="after")
    def validate_manifest(self) -> "DataHubAssetMap":
        if not self.datasets:
            raise ValueError("DataHub asset manifest must contain at least one dataset")
        if self.flagship_dataset not in self.datasets:
            raise ValueError("flagship_dataset must exist in datasets")
        invalid_names = [name for name in self.datasets if not name.strip()]
        if invalid_names:
            raise ValueError("dataset logical names must not be empty")
        invalid_urns = [
            urn
            for urn in self.datasets.values()
            if not urn.startswith("urn:li:dataset:")
        ]
        if invalid_urns:
            raise ValueError("all DataHub assets must be dataset URNs")
        if len(set(self.datasets.values())) != len(self.datasets):
            raise ValueError("DataHub asset URNs must be unique")
        return self

    @classmethod
    def from_path(cls, path: str | Path) -> "DataHubAssetMap":
        manifest_path = Path(path)
        try:
            raw = json.loads(manifest_path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise ValueError(f"unable to read DataHub asset manifest: {manifest_path}") from exc
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid DataHub asset manifest JSON: {manifest_path}") from exc
        return cls.model_validate(raw)

    @property
    def flagship_urn(self) -> str:
        return self.datasets[self.flagship_dataset]


class DataHubSnapshot(StrictModel):
    catalog: FixtureCatalog
    verified_entities: tuple[str, ...]
    field_counts: dict[str, int]
    lineage_sample: dict[str, Any]
    discovered_tools: tuple[str, ...]
    observed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("observed_at")
    @classmethod
    def normalize_observed_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("DataHub snapshot observed_at must be timezone-aware")
        return value.astimezone(timezone.utc)

    @property
    def snapshot_sha256(self) -> str:
        """Hash governed snapshot content without making wall-clock time part of identity."""

        canonical = json.dumps(
            {
                "catalog": self.catalog.model_dump(mode="json"),
                "verified_entities": sorted(self.verified_entities),
                "field_counts": self.field_counts,
                "lineage_sample": self.lineage_sample,
                "discovered_tools": sorted(self.discovered_tools),
            },
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()


class DataHubSnapshotLoader:
    """Fetch and normalize a fail-closed metadata snapshot from DataHub MCP."""

    def __init__(
        self,
        client: DataHubMcpClient,
        asset_map: DataHubAssetMap,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self.client = client
        self.asset_map = asset_map
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    async def load(self, *, require_mutations: bool) -> DataHubSnapshot:
        definitions = await self.client.discover_and_validate(
            require_mutations=require_mutations
        )
        expected_urns = tuple(self.asset_map.datasets.values())
        entities = await self.client.get_entities(expected_urns)
        verified_entities = _verify_entity_set(entities, expected_urns)

        datasets: dict[str, FixtureDataset] = {}
        field_counts: dict[str, int] = {}
        entities_by_urn = {
            urn: entity
            for entity in entities
            if (urn := _extract_entity_urn(entity)) is not None
        }

        for logical_name, urn in self.asset_map.datasets.items():
            fields = await self.client.list_schema_fields(urn)
            if not fields:
                raise DataHubMetadataError(
                    f"DataHub dataset has no schema fields: {logical_name}"
                )
            normalized_fields: dict[str, FixtureField] = {}
            for field in fields:
                field_path = _field_path(field)
                if field_path in normalized_fields:
                    raise DataHubMetadataError(
                        f"duplicate field path in DataHub schema: {logical_name}.{field_path}"
                    )
                normalized_fields[field_path] = _normalize_field(field)

            entity = entities_by_urn.get(urn, {})
            datasets[logical_name] = FixtureDataset(
                urn=urn,
                owner=_first_urn_with_prefix(entity, "urn:li:corpuser:"),
                domain=_first_urn_with_prefix(entity, "urn:li:domain:"),
                fields=normalized_fields,
            )
            field_counts[logical_name] = len(normalized_fields)

        urn_to_logical = {urn: logical for logical, urn in self.asset_map.datasets.items()}
        flagship_lineage: dict[str, Any] | None = None

        for logical_name, dataset in tuple(datasets.items()):
            updated_fields: dict[str, FixtureField] = {}
            for field_path, field in dataset.fields.items():
                lineage = await self.client.get_lineage(
                    dataset.urn,
                    column=field_path,
                    upstream=True,
                    max_hops=_LINEAGE_UNLIMITED_HOPS,
                    max_results=_LINEAGE_MAX_RESULTS,
                )
                lineage_sources = _normalize_lineage_sources(
                    lineage,
                    target=ColumnRef(dataset=logical_name, field_path=field_path),
                    datasets=datasets,
                    urn_to_logical=urn_to_logical,
                )
                updated_fields[field_path] = field.model_copy(
                    update={"lineage_sources": lineage_sources}
                )
                if (
                    logical_name == self.asset_map.flagship_dataset
                    and field_path == self.asset_map.flagship_column
                ):
                    flagship_lineage = lineage

            datasets[logical_name] = dataset.model_copy(update={"fields": updated_fields})

        if self.asset_map.flagship_column is None:
            flagship_lineage = await self.client.get_lineage(
                self.asset_map.flagship_urn,
                column=None,
                upstream=True,
                max_hops=_LINEAGE_UNLIMITED_HOPS,
                max_results=_LINEAGE_MAX_RESULTS,
            )
        elif flagship_lineage is None:
            raise DataHubMetadataError(
                "configured flagship column does not exist in the DataHub schema"
            )

        assert flagship_lineage is not None
        relationships = _lineage_relationships(flagship_lineage)
        if not relationships:
            raise DataHubMetadataError(
                "DataHub returned no upstream lineage for the configured flagship column"
            )
        if _lineage_payload_incomplete(flagship_lineage):
            raise DataHubMetadataError(
                "DataHub flagship lineage is incomplete or truncated"
            )

        observed_at = _utc_datetime(self._clock())
        return DataHubSnapshot(
            catalog=FixtureCatalog(
                version=f"datahub-mcp:{self.asset_map.version}",
                datasets=datasets,
            ),
            verified_entities=verified_entities,
            field_counts=field_counts,
            lineage_sample=flagship_lineage,
            discovered_tools=tuple(sorted(definition.name for definition in definitions)),
            observed_at=observed_at,
        )


class DataHubSnapshotContextResolver(FixtureContextResolver):
    """Refreshable policy resolver backed by one freshness-bounded DataHub snapshot."""

    def __init__(
        self,
        snapshot: DataHubSnapshot,
        *,
        max_age_seconds: float = _DEFAULT_MAX_SNAPSHOT_AGE_SECONDS,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if max_age_seconds <= 0 or max_age_seconds > _MAX_SNAPSHOT_AGE_SECONDS:
            raise ValueError(
                f"DataHub snapshot max age must be in (0, {_MAX_SNAPSHOT_AGE_SECONDS:g}] seconds"
            )
        self._snapshot_lock = threading.RLock()
        self._snapshot = snapshot
        self._max_age_seconds = float(max_age_seconds)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        super().__init__(snapshot.catalog)

    @property
    def snapshot(self) -> DataHubSnapshot:
        with self._snapshot_lock:
            return self._snapshot

    @property
    def max_age_seconds(self) -> float:
        return self._max_age_seconds

    def replace_snapshot(self, snapshot: DataHubSnapshot) -> None:
        """Atomically install a newly acquired DataHub snapshot for future requests."""

        with self._snapshot_lock:
            self._snapshot = snapshot
            self.catalog = snapshot.catalog

    def current_governance_binding(self) -> GovernanceContextBinding:
        with self._snapshot_lock:
            return self._binding_for(self._snapshot)

    def is_fresh(self) -> bool:
        try:
            self.current_governance_binding()
        except Exception:
            return False
        return True

    def resolve_with_governance_binding(
        self,
        query_plan: QueryPlan,
    ) -> tuple[ContextResolution, GovernanceContextBinding]:
        """Resolve governed context and provenance from the same snapshot atomically."""

        with self._snapshot_lock:
            snapshot = self._snapshot
            binding = self._binding_for(snapshot)
            resolution = FixtureContextResolver(snapshot.catalog).resolve(query_plan)
            return resolution, binding

    def resolve(self, query_plan: QueryPlan) -> ContextResolution:
        resolution, _ = self.resolve_with_governance_binding(query_plan)
        return resolution

    def _binding_for(self, snapshot: DataHubSnapshot) -> GovernanceContextBinding:
        binding = GovernanceContextBinding(
            source="datahub-mcp",
            snapshot_sha256=snapshot.snapshot_sha256,
            catalog_version=snapshot.catalog.version,
            observed_at=snapshot.observed_at,
            expires_at=snapshot.observed_at
            + timedelta(seconds=self._max_age_seconds),
        )
        binding.assert_fresh(_utc_datetime(self._clock()))
        return binding


_CATEGORY_LABELS: dict[SensitivityCategory, set[str]] = {
    SensitivityCategory.DIRECT_IDENTIFIER: {
        "toxicjoindirectidentifier",
        "directidentifier",
    },
    SensitivityCategory.STABLE_PSEUDONYM: {
        "toxicjoinstablepseudonym",
        "stablepseudonym",
        "stablecustomeridentifier",
    },
    SensitivityCategory.QUASI_IDENTIFIER: {
        "toxicjoinquasiidentifier",
        "quasiidentifier",
    },
    SensitivityCategory.SENSITIVE_ATTRIBUTE: {
        "toxicjoinsensitiveattribute",
        "sensitiveattribute",
        "toxicjoinfinancial",
        "toxicjoinsensitivesupport",
        "toxicjoinsensitivitylevel",
        "toxicjoinmodeloutput",
    },
    SensitivityCategory.PUBLIC_OR_LOW_RISK: {
        "toxicjoinpublicorlowrisk",
        "publicorlowrisk",
    },
}


def _normalize_field(field: dict[str, Any]) -> FixtureField:
    tags = _extract_tag_names(field)
    glossary_terms = _extract_glossary_names(field)
    labels = {_normalize_label(value) for value in tags + glossary_terms}
    categories = {
        category
        for category, accepted in _CATEGORY_LABELS.items()
        if labels.intersection(accepted)
    }

    if not categories:
        category = SensitivityCategory.UNCLASSIFIED
    elif len(categories) == 1:
        category = next(iter(categories))
    else:
        rendered = ", ".join(sorted(value.value for value in categories))
        raise DataHubMetadataError(
            f"conflicting sensitivity categories on field {_field_path(field)}: {rendered}"
        )

    return FixtureField(
        category=category,
        tags=tuple(sorted(tags)),
        glossary_terms=tuple(sorted(glossary_terms)),
    )


def _normalize_lineage_sources(
    payload: dict[str, Any],
    *,
    target: ColumnRef,
    datasets: dict[str, FixtureDataset],
    urn_to_logical: dict[str, str],
) -> tuple[LineageSource, ...]:
    relationships = _lineage_relationships(payload)
    sources: dict[str, LineageSource] = {}
    incomplete = _lineage_payload_incomplete(payload)

    for index, relationship in enumerate(relationships):
        entity = relationship.get("entity")
        urn = _extract_entity_urn(entity) if isinstance(entity, dict) else None
        columns = relationship.get("lineageColumns")
        if (
            urn is None
            or not isinstance(columns, list)
            or not columns
            or not all(isinstance(column, str) and column.strip() for column in columns)
        ):
            incomplete = True
            unresolved = _unresolved_lineage_source(
                target=target,
                discriminator=f"relationship-{index}",
                datahub_urn=urn,
            )
            sources[unresolved.ref.key] = unresolved
            continue

        logical_name = urn_to_logical.get(urn)
        upstream_dataset = datasets.get(logical_name) if logical_name is not None else None
        for column in columns:
            assert isinstance(column, str)
            if upstream_dataset is None or column not in upstream_dataset.fields:
                unresolved = LineageSource(
                    ref=ColumnRef(
                        dataset=f"@datahub:{urn}",
                        field_path=column,
                    ),
                    category=SensitivityCategory.UNCLASSIFIED,
                    datahub_urn=urn,
                )
                sources[unresolved.ref.key] = unresolved
                continue

            ref = ColumnRef(dataset=logical_name, field_path=column)
            if ref.key == target.key:
                continue
            upstream_field = upstream_dataset.fields[column]
            sources[ref.key] = LineageSource(
                ref=ref,
                category=upstream_field.category,
                datahub_urn=urn,
            )

    if incomplete:
        unresolved = _unresolved_lineage_source(
            target=target,
            discriminator="incomplete",
            datahub_urn=None,
        )
        sources[unresolved.ref.key] = unresolved

    return tuple(sources[key] for key in sorted(sources))


def _lineage_relationships(payload: dict[str, Any]) -> list[dict[str, Any]]:
    relationships = payload.get("relationships")
    if not isinstance(relationships, list) or not all(
        isinstance(item, dict) for item in relationships
    ):
        raise DataHubMetadataError("DataHub lineage payload has invalid relationships")
    return relationships


def _lineage_payload_incomplete(payload: dict[str, Any]) -> bool:
    upstreams = payload.get("upstreams")
    if isinstance(upstreams, dict):
        if upstreams.get("hasMore") is True:
            return True
        if upstreams.get("truncatedDueToTokenBudget") is True:
            return True

    for relationship in _lineage_relationships(payload):
        if relationship.get("truncatedChildren"):
            return True
    return False


def _unresolved_lineage_source(
    *,
    target: ColumnRef,
    discriminator: str,
    datahub_urn: str | None,
) -> LineageSource:
    digest = hashlib.sha256(
        f"{target.key}:{discriminator}:{datahub_urn or ''}".encode("utf-8")
    ).hexdigest()[:16]
    return LineageSource(
        ref=ColumnRef(
            dataset="@datahub-lineage",
            field_path=f"{target.key}:{digest}",
        ),
        category=SensitivityCategory.UNCLASSIFIED,
        datahub_urn=datahub_urn,
    )


def _verify_entity_set(
    entities: tuple[dict[str, Any], ...],
    expected_urns: tuple[str, ...],
) -> tuple[str, ...]:
    found = {
        urn
        for entity in entities
        if (urn := _extract_entity_urn(entity)) is not None
    }
    missing = sorted(set(expected_urns) - found)
    unexpected = sorted(found - set(expected_urns))
    if missing:
        raise DataHubMetadataError(
            "DataHub get_entities did not return configured assets: "
            + ", ".join(missing)
        )
    if unexpected:
        raise DataHubMetadataError(
            "DataHub get_entities returned unexpected assets: "
            + ", ".join(unexpected)
        )
    return tuple(sorted(found))


def _extract_entity_urn(entity: dict[str, Any]) -> str | None:
    direct = entity.get("urn")
    if isinstance(direct, str):
        return direct
    return _first_urn_with_prefix(entity, "urn:li:dataset:")


def _field_path(field: dict[str, Any]) -> str:
    value = field.get("fieldPath", field.get("field_path"))
    if not isinstance(value, str) or not value.strip():
        raise DataHubMetadataError("DataHub schema field is missing fieldPath")
    return value


def _extract_tag_names(field: dict[str, Any]) -> tuple[str, ...]:
    names: set[str] = set()
    for source_key in ("tags", "editedTags", "edited_tags"):
        for item in _association_items(
            field,
            source_key=source_key,
            collection_key="tags",
        ):
            if isinstance(item, str):
                name = item
            elif isinstance(item, dict):
                tag = item.get("tag", item)
                name = _name_or_urn(tag)
            else:
                raise DataHubMetadataError(
                    f"DataHub field {_field_path(field)} has an invalid tag entry"
                )
            if not isinstance(name, str) or not name.strip():
                raise DataHubMetadataError(
                    f"DataHub field {_field_path(field)} has an unresolvable tag entry"
                )
            names.add(name)
    return tuple(sorted(names))


def _extract_glossary_names(field: dict[str, Any]) -> tuple[str, ...]:
    names: set[str] = set()
    for source_key in (
        "glossaryTerms",
        "glossary_terms",
        "editedGlossaryTerms",
        "edited_glossary_terms",
    ):
        for item in _association_items(
            field,
            source_key=source_key,
            collection_key="terms",
        ):
            if isinstance(item, str):
                name = item
            elif isinstance(item, dict):
                term = item.get("term", item)
                name = _name_or_urn(term)
            else:
                raise DataHubMetadataError(
                    f"DataHub field {_field_path(field)} has an invalid glossary entry"
                )
            if not isinstance(name, str) or not name.strip():
                raise DataHubMetadataError(
                    f"DataHub field {_field_path(field)} has an unresolvable glossary entry"
                )
            names.add(name)
    return tuple(sorted(names))


def _association_items(
    field: dict[str, Any],
    *,
    source_key: str,
    collection_key: str,
) -> tuple[Any, ...]:
    if source_key not in field or field[source_key] is None:
        return ()

    container = field[source_key]
    if isinstance(container, dict):
        items = container.get(collection_key, [])
    elif isinstance(container, list):
        items = container
    else:
        raise DataHubMetadataError(
            f"DataHub field {_field_path(field)} has invalid {source_key} metadata"
        )

    if not isinstance(items, list):
        raise DataHubMetadataError(
            f"DataHub field {_field_path(field)} has invalid {source_key}.{collection_key} metadata"
        )
    return tuple(items)


def _name_or_urn(value: Any) -> str | None:
    if isinstance(value, str):
        return value
    if not isinstance(value, dict):
        return None
    properties = value.get("properties")
    if isinstance(properties, dict):
        name = properties.get("name")
        if isinstance(name, str) and name.strip():
            return name
    for key in ("name", "urn"):
        candidate = value.get(key)
        if isinstance(candidate, str) and candidate.strip():
            return candidate
    return None


def _normalize_label(value: str) -> str:
    if value.startswith("urn:li:tag:"):
        value = value.removeprefix("urn:li:tag:")
    if value.startswith("urn:li:glossaryTerm:"):
        value = value.removeprefix("urn:li:glossaryTerm:")
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _first_urn_with_prefix(value: Any, prefix: str) -> str | None:
    if isinstance(value, str):
        return value if value.startswith(prefix) else None
    if isinstance(value, dict):
        for item in value.values():
            found = _first_urn_with_prefix(item, prefix)
            if found is not None:
                return found
    if isinstance(value, (list, tuple)):
        for item in value:
            found = _first_urn_with_prefix(item, prefix)
            if found is not None:
                return found
    return None


def _utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise DataHubMetadataError("DataHub snapshot clock must be timezone-aware")
    return value.astimezone(timezone.utc)
