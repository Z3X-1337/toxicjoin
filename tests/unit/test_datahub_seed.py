from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from toxicjoin.integrations.datahub_seed import (
    DataHubSdkBindings,
    build_seed_plan,
    seed_live_datahub,
)


class FakeTag:
    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs


class FakeGlossaryTerm:
    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs


class FakeTagUrn:
    def __init__(self, name: str) -> None:
        self.name = name

    def __str__(self) -> str:
        return f"urn:li:tag:{self.name}"


class FakeGlossaryTermUrn:
    def __init__(self, term_id: str) -> None:
        self.term_id = term_id

    def __str__(self) -> str:
        return f"urn:li:glossaryTerm:{self.term_id}"


class FakeDatasetUrn:
    def __init__(self, *, platform: str, name: str, env: str) -> None:
        self.platform = platform
        self.name = name
        self.env = env

    def __str__(self) -> str:
        return (
            "urn:li:dataset:(urn:li:dataPlatform:"
            f"{self.platform},{self.name},{self.env})"
        )


class FakeSchemaField:
    def __init__(self) -> None:
        self.tags: list[FakeTagUrn] = []
        self.terms: list[FakeGlossaryTermUrn] = []

    def add_tag(self, tag: FakeTagUrn) -> None:
        self.tags.append(tag)

    def add_term(self, term: FakeGlossaryTermUrn) -> None:
        self.terms.append(term)


class FakeDataset:
    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.fields = {
            field_path: FakeSchemaField()
            for field_path, _native_type, _description in kwargs["schema"]
        }

    def __getitem__(self, field_path: str) -> FakeSchemaField:
        return self.fields[field_path]


class FakeEntities:
    def __init__(self) -> None:
        self.upserts: list[Any] = []

    def upsert(self, entity: Any) -> None:
        self.upserts.append(entity)


class FakeLineage:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def add_lineage(self, **kwargs: Any) -> None:
        self.calls.append(kwargs)


class FakeClient:
    def __init__(self) -> None:
        self.entities = FakeEntities()
        self.lineage = FakeLineage()


class UnusedDataHubClient:
    @classmethod
    def from_env(cls):
        raise AssertionError("explicit fake client should be used")


def _bindings() -> DataHubSdkBindings:
    return DataHubSdkBindings(
        DataHubClient=UnusedDataHubClient,
        Dataset=FakeDataset,
        Tag=FakeTag,
        GlossaryTerm=FakeGlossaryTerm,
        DatasetUrn=FakeDatasetUrn,
        TagUrn=FakeTagUrn,
        GlossaryTermUrn=FakeGlossaryTermUrn,
    )


def test_seed_plan_covers_all_governed_assets_and_fields() -> None:
    plan = build_seed_plan()

    assert [dataset.logical_name for dataset in plan.datasets] == [
        "customers",
        "location_activity",
        "orders",
        "retention_scores",
        "support_cases",
    ]
    assert sum(len(dataset.fields) for dataset in plan.datasets) == 19
    assert "toxicjoin:demo" in plan.tags
    assert "toxicjoin:stable-pseudonym" in plan.tags
    assert "toxicjoin:model-output" in plan.tags
    assert {term.term_id for term in plan.terms} == {
        "AgeBand",
        "ChurnScore",
        "CoarseRegion",
        "PreciseArea",
        "PurchaseAmount",
        "StableCustomerIdentifier",
        "SupportCaseCategory",
    }
    assert len(plan.lineages) == 4
    assert all(lineage.downstream == "retention_scores" for lineage in plan.lineages)


def test_seed_applies_entities_fields_lineage_and_sanitized_report(tmp_path: Path) -> None:
    client = FakeClient()
    output = tmp_path / "datahub-seed.json"

    report = seed_live_datahub(
        output=output,
        client=client,
        bindings=_bindings(),
    )

    plan = build_seed_plan()
    assert report.status == "seeded"
    assert report.tag_count == len(plan.tags)
    assert report.term_count == len(plan.terms)
    assert report.dataset_count == 5
    assert report.field_count == 19
    assert report.lineage_count == 4
    assert len(report.dataset_urns) == 5
    assert all(urn.startswith("urn:li:dataset:") for urn in report.dataset_urns)

    tags = [entity for entity in client.entities.upserts if isinstance(entity, FakeTag)]
    terms = [
        entity
        for entity in client.entities.upserts
        if isinstance(entity, FakeGlossaryTerm)
    ]
    datasets = [
        entity
        for entity in client.entities.upserts
        if isinstance(entity, FakeDataset)
    ]
    assert len(tags) == len(plan.tags)
    assert len(terms) == len(plan.terms)
    assert len(datasets) == 5

    customers = next(
        dataset
        for dataset in datasets
        if dataset.kwargs["name"] == "toxicjoin.customers"
    )
    assert customers.kwargs["owners"] == ["urn:li:corpuser:data-platform"]
    assert customers.kwargs["custom_properties"]["toxicjoin.synthetic"] == "true"
    customer_id = customers.fields["customer_id"]
    assert [tag.name for tag in customer_id.tags] == [
        "toxicjoin:stable-pseudonym"
    ]
    assert [term.term_id for term in customer_id.terms] == [
        "StableCustomerIdentifier"
    ]

    assert len(client.lineage.calls) == 4
    support_lineage = next(
        call
        for call in client.lineage.calls
        if str(call["upstream"]).endswith("toxicjoin.support_cases,PROD)")
    )
    assert support_lineage["column_lineage"] == {
        "churn_score": ["case_category", "sensitivity_level"]
    }

    encoded = output.read_text(encoding="utf-8")
    payload = json.loads(encoded)
    assert payload["status"] == "seeded"
    assert payload["report_sha256"] == report.report_sha256
    assert "token" not in encoded.lower()
    assert "password" not in encoded.lower()
    assert "warehouse rows" not in encoded.lower()
