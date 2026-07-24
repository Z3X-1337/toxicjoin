"""Live DataHub metadata snapshot and normalized context resolution.

The live adapter never asks the policy engine to understand DataHub-specific response
shapes. It validates an explicit logical-name-to-URN manifest, reads entities and
schema fields through the official MCP server, classifies fields from controlled tags
or glossary terms, and materializes the same ``FixtureCatalog`` model used by the
deterministic offline path.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from pydantic import Field, model_validator

from toxicjoin.context.fixture import (
    FixtureCatalog,
    FixtureContextResolver,
    FixtureDataset,
    FixtureField,
)
from toxicjoin.integrations.datahub_mcp import DataHubMcpClient, DataHubMcpError
from toxicjoin.models import SensitivityCategory, StrictModel


class DataHubMetadataError(DataHubMcpError):
    """Raised when live DataHub metadata cannot be normalized safely."""


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


class DataHubSnapshotLoader:
    """Fetch and normalize a fail-closed metadata snapshot from DataHub MCP."""

    def __init__(
        self,
        client: DataHubMcpClient,
        asset_map: DataHubAssetMap,
    ) -> None:
        self.client = client
        self.asset_map = asset_map

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

        lineage = await self.client.get_lineage(
            self.asset_map.flagship_urn,
            column=self.asset_map.flagship_column,
            upstream=True,
            max_hops=2,
            max_results=100,
        )
        relationships = lineage.get("relationships")
        if not isinstance(relationships, list) or not all(
            isinstance(item, dict) for item in relationships
        ):
            raise DataHubMetadataError(
                "DataHub lineage payload has invalid relationships"
            )
        if not relationships:
            raise DataHubMetadataError(
                "DataHub returned no upstream lineage for the configured flagship column"
            )

        return DataHubSnapshot(
            catalog=FixtureCatalog(
                version=f"datahub-mcp:{self.asset_map.version}",
                datasets=datasets,
            ),
            verified_entities=verified_entities,
            field_counts=field_counts,
            lineage_sample=lineage,
            discovered_tools=tuple(sorted(definition.name for definition in definitions)),
        )


class DataHubSnapshotContextResolver(FixtureContextResolver):
    """Synchronous policy resolver backed by an already verified live snapshot."""

    def __init__(self, snapshot: DataHubSnapshot) -> None:
        super().__init__(snapshot.catalog)
        self.snapshot = snapshot


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
    return _extract_association_names(
        field,
        keys=("tags", "editedTags", "edited_tags"),
        list_key="tags",
        association_key="tag",
    )


def _extract_glossary_names(field: dict[str, Any]) -> tuple[str, ...]:
    return _extract_association_names(
        field,
        keys=(
            "glossaryTerms",
            "glossary_terms",
            "editedGlossaryTerms",
            "edited_glossary_terms",
        ),
        list_key="terms",
        association_key="term",
    )


def _extract_association_names(
    field: dict[str, Any],
    *,
    keys: tuple[str, ...],
    list_key: str,
    association_key: str,
) -> tuple[str, ...]:
    """Merge raw GraphQL and cleaned MCP association representations.

    DataHub MCP can surface system metadata as ``tags`` / ``glossaryTerms`` and
    user-curated editable schema metadata as ``editedTags`` /
    ``editedGlossaryTerms``. Both forms are governance input and therefore must be
    considered together. Conflicting sensitivity labels are deliberately left for
    ``_normalize_field`` to reject fail-closed.
    """

    names: set[str] = set()
    for key in keys:
        container = field.get(key)
        if isinstance(container, dict):
            items: Any = container.get(list_key, [])
        elif isinstance(container, (list, tuple)):
            items = container
        elif isinstance(container, str):
            items = (container,)
        else:
            items = ()

        if not isinstance(items, (list, tuple)):
            continue
        for item in items:
            name: str | None = None
            if isinstance(item, str):
                name = item
            elif isinstance(item, dict):
                association = item.get(association_key, item)
                name = _name_or_urn(association)
            if isinstance(name, str) and name.strip():
                names.add(name)

    return tuple(sorted(names))


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
