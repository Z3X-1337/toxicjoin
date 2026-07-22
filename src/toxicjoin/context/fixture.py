"""DataHub-shaped fixture metadata resolver.

Fixture mode exists to make policy and execution tests deterministic. It mirrors
only the governed fields ToxicJoin consumes and is never presented as a live
DataHub integration.
"""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import Field

from toxicjoin.models import (
    ColumnContext,
    ColumnRef,
    PolicyInput,
    QueryPlan,
    ReasonCode,
    SensitivityCategory,
    StrictModel,
)


class FixtureField(StrictModel):
    category: SensitivityCategory
    tags: tuple[str, ...] = ()
    glossary_terms: tuple[str, ...] = ()


class FixtureDataset(StrictModel):
    urn: str = Field(min_length=1)
    owner: str | None = None
    domain: str | None = None
    fields: dict[str, FixtureField]


class FixtureCatalog(StrictModel):
    version: str = Field(min_length=1)
    datasets: dict[str, FixtureDataset]


class ContextResolution(StrictModel):
    projected_context: tuple[ColumnContext, ...]
    all_referenced_context: tuple[ColumnContext, ...]
    failures: tuple[ReasonCode, ...] = ()

    def to_policy_input(
        self,
        *,
        task_purpose: str,
        query_plan: QueryPlan,
        subject_key: ColumnRef | None = None,
        minimum_group_size_present: int | None = None,
    ) -> PolicyInput:
        effective_threshold = (
            minimum_group_size_present
            if minimum_group_size_present is not None
            else query_plan.minimum_group_size_present
        )
        return PolicyInput(
            task_purpose=task_purpose,
            query_plan=query_plan,
            projected_context=self.projected_context,
            all_referenced_context=self.all_referenced_context,
            subject_key=subject_key,
            minimum_group_size_present=effective_threshold,
            upstream_failures=self.failures,
        )


def load_fixture_catalog(path: str | Path) -> FixtureCatalog:
    catalog_path = Path(path)
    try:
        raw = json.loads(catalog_path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ValueError(f"unable to read fixture catalog: {catalog_path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid fixture catalog JSON: {catalog_path}") from exc

    return FixtureCatalog.model_validate(raw)


class FixtureContextResolver:
    """Resolve QueryPlan fields against deterministic DataHub-shaped metadata."""

    def __init__(self, catalog: FixtureCatalog) -> None:
        self.catalog = catalog

    @classmethod
    def from_path(cls, path: str | Path) -> "FixtureContextResolver":
        return cls(load_fixture_catalog(path))

    def resolve(self, query_plan: QueryPlan) -> ContextResolution:
        failures: list[ReasonCode] = []
        cache: dict[str, ColumnContext] = {}

        if query_plan.contains_wildcard:
            # Star expansion requires a trusted schema-aware expansion phase. Until that
            # phase is implemented, fixture and live modes both fail closed.
            failures.append(ReasonCode.UNRESOLVED_COLUMN)

        projected_context = self._resolve_many(
            query_plan.projected_columns,
            failures=failures,
            cache=cache,
        )

        referenced_refs = query_plan.referenced_columns or _merge_refs(
            query_plan.projected_columns,
            query_plan.join_columns,
            query_plan.group_by_columns,
        )
        all_referenced_context = self._resolve_many(
            referenced_refs,
            failures=failures,
            cache=cache,
        )

        return ContextResolution(
            projected_context=projected_context,
            all_referenced_context=all_referenced_context,
            failures=_deduplicate_failures(failures),
        )

    def _resolve_many(
        self,
        refs: tuple[ColumnRef, ...],
        *,
        failures: list[ReasonCode],
        cache: dict[str, ColumnContext],
    ) -> tuple[ColumnContext, ...]:
        resolved: dict[str, ColumnContext] = {}
        for ref in refs:
            context = cache.get(ref.key)
            if context is None:
                context, failure = self._resolve_one(ref)
                cache[ref.key] = context
                if failure is not None:
                    failures.append(failure)
            resolved[ref.key] = context

        return tuple(resolved[key] for key in sorted(resolved))

    def _resolve_one(
        self,
        ref: ColumnRef,
    ) -> tuple[ColumnContext, ReasonCode | None]:
        if ref.dataset.startswith("@"):
            return _unresolved_context(ref), ReasonCode.UNRESOLVED_DATASET

        dataset = self.catalog.datasets.get(ref.dataset)
        if dataset is None:
            return _unresolved_context(ref), ReasonCode.UNRESOLVED_DATASET

        field = dataset.fields.get(ref.field_path)
        if field is None:
            return _unresolved_context(ref), ReasonCode.UNRESOLVED_COLUMN

        context = ColumnContext(
            ref=ref,
            category=field.category,
            datahub_urn=dataset.urn,
            tags=field.tags,
            glossary_terms=field.glossary_terms,
            resolved=True,
        )
        if field.category == SensitivityCategory.UNCLASSIFIED:
            return context, ReasonCode.UNCLASSIFIED_COLUMN
        return context, None


def _unresolved_context(ref: ColumnRef) -> ColumnContext:
    return ColumnContext(
        ref=ref,
        category=SensitivityCategory.UNCLASSIFIED,
        resolved=False,
    )


def _merge_refs(*collections: tuple[ColumnRef, ...]) -> tuple[ColumnRef, ...]:
    merged: dict[str, ColumnRef] = {}
    for collection in collections:
        for ref in collection:
            merged[ref.key] = ref
    return tuple(merged[key] for key in sorted(merged))


def _deduplicate_failures(values: list[ReasonCode]) -> tuple[ReasonCode, ...]:
    return tuple(dict.fromkeys(values))
