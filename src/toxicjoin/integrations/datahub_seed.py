"""Seed the governed ToxicJoin demo graph into a live DataHub instance.

The implementation uses the current public DataHub Python SDK, but loads it lazily so
fixture mode and the default test suite do not require the optional heavy dependency.
All generated datasets use synthetic metadata only; no warehouse rows are emitted.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pydantic import Field, field_validator

from toxicjoin.demo import default_fixture_catalog
from toxicjoin.models import StrictModel


class DataHubSeedError(RuntimeError):
    """Fail-closed live DataHub seed error."""


class DataHubSeedDependencyError(DataHubSeedError):
    """Raised when the optional DataHub SDK is unavailable."""


class SeedFieldSpec(StrictModel):
    field_path: str = Field(min_length=1)
    native_type: str = Field(min_length=1)
    description: str = Field(min_length=1)
    tags: tuple[str, ...] = ()
    glossary_terms: tuple[str, ...] = ()


class SeedDatasetSpec(StrictModel):
    logical_name: str = Field(min_length=1)
    platform: str = "duckdb"
    datahub_name: str = Field(min_length=1)
    env: str = "PROD"
    description: str = Field(min_length=1)
    owner: str | None = None
    fields: tuple[SeedFieldSpec, ...]


class SeedTermSpec(StrictModel):
    term_id: str = Field(min_length=1)
    display_name: str = Field(min_length=1)
    definition: str = Field(min_length=1)


class SeedLineageSpec(StrictModel):
    upstream: str = Field(min_length=1)
    downstream: str = Field(min_length=1)
    column_lineage: dict[str, tuple[str, ...]]


class DataHubSeedPlan(StrictModel):
    version: str = "1.0"
    tags: tuple[str, ...]
    terms: tuple[SeedTermSpec, ...]
    datasets: tuple[SeedDatasetSpec, ...]
    lineages: tuple[SeedLineageSpec, ...]


class DataHubSeedReport(StrictModel):
    schema_version: str = "1.0"
    created_at: datetime
    status: str = Field(pattern=r"^seeded$")
    tag_count: int = Field(ge=0)
    term_count: int = Field(ge=0)
    dataset_count: int = Field(ge=0)
    field_count: int = Field(ge=0)
    lineage_count: int = Field(ge=0)
    dataset_urns: tuple[str, ...]
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @field_validator("created_at")
    @classmethod
    def normalize_created_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("created_at must be timezone-aware")
        return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class DataHubSdkBindings:
    DataHubClient: Any
    Dataset: Any
    Tag: Any
    GlossaryTerm: Any
    DatasetUrn: Any
    TagUrn: Any
    GlossaryTermUrn: Any


_FIELD_TYPES: dict[str, str] = {
    "customers.customer_id": "VARCHAR",
    "customers.age_band": "VARCHAR",
    "customers.precise_area": "VARCHAR",
    "customers.coarse_region": "VARCHAR",
    "orders.order_id": "VARCHAR",
    "orders.customer_id": "VARCHAR",
    "orders.purchase_amount": "DECIMAL(12,2)",
    "orders.category": "VARCHAR",
    "orders.ordered_at": "TIMESTAMP",
    "support_cases.case_id": "VARCHAR",
    "support_cases.customer_id": "VARCHAR",
    "support_cases.case_category": "VARCHAR",
    "support_cases.sensitivity_level": "VARCHAR",
    "location_activity.customer_id": "VARCHAR",
    "location_activity.precise_area": "VARCHAR",
    "location_activity.activity_count": "INTEGER",
    "retention_scores.customer_id": "VARCHAR",
    "retention_scores.churn_score": "DOUBLE",
    "retention_scores.model_timestamp": "TIMESTAMP",
}

_FIELD_DESCRIPTIONS: dict[str, str] = {
    "customers.customer_id": "Stable synthetic customer pseudonym used for governed joins.",
    "customers.age_band": "Synthetic customer age range used as a quasi-identifier.",
    "customers.precise_area": "Synthetic fine-grained area with intentionally small groups.",
    "customers.coarse_region": "Coarsened region designed for safe aggregate analysis.",
    "orders.order_id": "Synthetic order identifier.",
    "orders.customer_id": "Stable synthetic customer pseudonym.",
    "orders.purchase_amount": "Synthetic purchase amount treated as financial data.",
    "orders.category": "Public synthetic product category.",
    "orders.ordered_at": "Synthetic order timestamp.",
    "support_cases.case_id": "Synthetic support-case identifier.",
    "support_cases.customer_id": "Stable synthetic customer pseudonym.",
    "support_cases.case_category": "Synthetic support topic that may reveal sensitive context.",
    "support_cases.sensitivity_level": "Synthetic support sensitivity classification.",
    "location_activity.customer_id": "Stable synthetic customer pseudonym.",
    "location_activity.precise_area": "Synthetic fine-grained activity location.",
    "location_activity.activity_count": "Synthetic activity frequency.",
    "retention_scores.customer_id": "Stable synthetic customer pseudonym.",
    "retention_scores.churn_score": "Synthetic model output representing churn likelihood.",
    "retention_scores.model_timestamp": "Synthetic model scoring timestamp.",
}

_DATASET_DESCRIPTIONS: dict[str, str] = {
    "customers": "Synthetic customer segmentation data for ToxicJoin privacy evaluation.",
    "orders": "Synthetic commerce activity used in compositional-risk scenarios.",
    "support_cases": "Synthetic support metadata containing planted sensitive categories.",
    "location_activity": "Synthetic fine-grained location activity for re-identification tests.",
    "retention_scores": "Synthetic churn-model outputs used by the flagship safe rewrite.",
}

_TERM_DEFINITIONS: dict[str, str] = {
    "StableCustomerIdentifier": "A stable pseudonymous subject key that can enable linkage.",
    "AgeBand": "A binned age attribute treated as a quasi-identifier.",
    "PreciseArea": "A fine-grained location attribute that can create small groups.",
    "CoarseRegion": "A coarsened location attribute suitable for safer aggregation.",
    "PurchaseAmount": "A financial transaction amount treated as sensitive.",
    "SupportCaseCategory": "A support category that may reveal sensitive circumstances.",
    "ChurnScore": "A predictive model output treated as a sensitive behavioral attribute.",
}


def build_seed_plan() -> DataHubSeedPlan:
    """Build a deterministic seed plan from the package-owned governed catalog."""

    catalog = default_fixture_catalog()
    tags = {"toxicjoin:demo"}
    term_ids: set[str] = set()
    datasets: list[SeedDatasetSpec] = []

    for logical_name, dataset in sorted(catalog.datasets.items()):
        fields: list[SeedFieldSpec] = []
        for field_path, field in sorted(dataset.fields.items()):
            key = f"{logical_name}.{field_path}"
            if key not in _FIELD_TYPES or key not in _FIELD_DESCRIPTIONS:
                raise DataHubSeedError(f"missing seed definition for governed field: {key}")
            tags.update(field.tags)
            normalized_terms = tuple(
                sorted(_glossary_term_id(value) for value in field.glossary_terms)
            )
            term_ids.update(normalized_terms)
            fields.append(
                SeedFieldSpec(
                    field_path=field_path,
                    native_type=_FIELD_TYPES[key],
                    description=_FIELD_DESCRIPTIONS[key],
                    tags=tuple(sorted(field.tags)),
                    glossary_terms=normalized_terms,
                )
            )

        datasets.append(
            SeedDatasetSpec(
                logical_name=logical_name,
                datahub_name=f"toxicjoin.{logical_name}",
                description=_DATASET_DESCRIPTIONS[logical_name],
                owner=dataset.owner,
                fields=tuple(fields),
            )
        )

    terms = tuple(
        SeedTermSpec(
            term_id=term_id,
            display_name=_humanize_identifier(term_id),
            definition=_TERM_DEFINITIONS.get(
                term_id,
                f"Governed ToxicJoin glossary term for {term_id}.",
            ),
        )
        for term_id in sorted(term_ids)
    )

    lineages = (
        SeedLineageSpec(
            upstream="customers",
            downstream="retention_scores",
            column_lineage={"customer_id": ("customer_id",)},
        ),
        SeedLineageSpec(
            upstream="orders",
            downstream="retention_scores",
            column_lineage={"churn_score": ("purchase_amount",)},
        ),
        SeedLineageSpec(
            upstream="support_cases",
            downstream="retention_scores",
            column_lineage={
                "churn_score": ("case_category", "sensitivity_level"),
            },
        ),
        SeedLineageSpec(
            upstream="location_activity",
            downstream="retention_scores",
            column_lineage={
                "churn_score": ("activity_count", "precise_area"),
            },
        ),
    )

    return DataHubSeedPlan(
        tags=tuple(sorted(tags)),
        terms=terms,
        datasets=tuple(datasets),
        lineages=lineages,
    )


def seed_live_datahub(
    *,
    output: str | Path,
    client: Any | None = None,
    bindings: DataHubSdkBindings | None = None,
) -> DataHubSeedReport:
    """Apply the deterministic seed plan and persist a sanitized evidence report."""

    resolved_bindings = bindings or _load_sdk_bindings()
    resolved_client = client or resolved_bindings.DataHubClient.from_env()
    plan = build_seed_plan()

    for tag_name in plan.tags:
        resolved_client.entities.upsert(
            resolved_bindings.Tag(
                name=tag_name,
                display_name=tag_name,
                description=f"ToxicJoin governed metadata tag: {tag_name}",
            )
        )

    for term in plan.terms:
        resolved_client.entities.upsert(
            resolved_bindings.GlossaryTerm(
                id=term.term_id,
                display_name=term.display_name,
                definition=term.definition,
            )
        )

    dataset_urns: dict[str, Any] = {}
    for dataset_spec in plan.datasets:
        dataset = resolved_bindings.Dataset(
            platform=dataset_spec.platform,
            name=dataset_spec.datahub_name,
            env=dataset_spec.env,
            display_name=f"ToxicJoin {dataset_spec.logical_name}",
            description=dataset_spec.description,
            owners=[dataset_spec.owner] if dataset_spec.owner else None,
            tags=[resolved_bindings.TagUrn("toxicjoin:demo")],
            custom_properties={
                "toxicjoin.synthetic": "true",
                "toxicjoin.seed_version": plan.version,
            },
            schema=[
                (
                    field.field_path,
                    field.native_type,
                    field.description,
                )
                for field in dataset_spec.fields
            ],
        )
        for field in dataset_spec.fields:
            for tag_name in field.tags:
                dataset[field.field_path].add_tag(resolved_bindings.TagUrn(tag_name))
            for term_id in field.glossary_terms:
                dataset[field.field_path].add_term(
                    resolved_bindings.GlossaryTermUrn(term_id)
                )
        resolved_client.entities.upsert(dataset)
        dataset_urns[dataset_spec.logical_name] = resolved_bindings.DatasetUrn(
            platform=dataset_spec.platform,
            name=dataset_spec.datahub_name,
            env=dataset_spec.env,
        )

    for lineage in plan.lineages:
        resolved_client.lineage.add_lineage(
            upstream=dataset_urns[lineage.upstream],
            downstream=dataset_urns[lineage.downstream],
            column_lineage={
                downstream: list(upstream_columns)
                for downstream, upstream_columns in lineage.column_lineage.items()
            },
        )

    created_at = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "created_at": created_at,
        "status": "seeded",
        "tag_count": len(plan.tags),
        "term_count": len(plan.terms),
        "dataset_count": len(plan.datasets),
        "field_count": sum(len(dataset.fields) for dataset in plan.datasets),
        "lineage_count": len(plan.lineages),
        "dataset_urns": tuple(
            sorted(str(urn) for urn in dataset_urns.values())
        ),
        "report_sha256": "0" * 64,
    }
    payload["report_sha256"] = _report_hash(payload)
    report = DataHubSeedReport.model_validate(payload)
    _write_report_atomic(Path(output), report)
    return report


def _load_sdk_bindings() -> DataHubSdkBindings:
    try:
        from datahub.metadata.urns import DatasetUrn, GlossaryTermUrn, TagUrn
        from datahub.sdk import DataHubClient, Dataset
        from datahub.sdk.glossary_term import GlossaryTerm
        from datahub.sdk.tag import Tag
    except ImportError as exc:
        raise DataHubSeedDependencyError(
            "install the live integration with: pip install -e '.[datahub]'"
        ) from exc

    return DataHubSdkBindings(
        DataHubClient=DataHubClient,
        Dataset=Dataset,
        Tag=Tag,
        GlossaryTerm=GlossaryTerm,
        DatasetUrn=DatasetUrn,
        TagUrn=TagUrn,
        GlossaryTermUrn=GlossaryTermUrn,
    )


def _glossary_term_id(value: str) -> str:
    prefix = "urn:li:glossaryTerm:"
    term_id = value.removeprefix(prefix)
    if not term_id or term_id == value:
        raise DataHubSeedError(f"invalid glossary term URN: {value}")
    return term_id


def _humanize_identifier(value: str) -> str:
    words = re.sub(r"(?<!^)(?=[A-Z])", " ", value).replace("_", " ")
    return " ".join(words.split())


def _report_hash(payload: dict[str, Any]) -> str:
    canonical_payload = {
        key: _json_compatible(value)
        for key, value in payload.items()
        if key != "report_sha256"
    }
    canonical = json.dumps(
        canonical_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _write_report_atomic(path: Path, report: DataHubSeedReport) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (
        json.dumps(
            report.model_dump(mode="json"),
            indent=2,
            sort_keys=True,
            ensure_ascii=True,
        )
        + "\n"
    ).encode("utf-8")

    temp_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_path = Path(handle.name)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_path, path)
        temp_path = None
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


def _json_compatible(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, dict):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_compatible(item) for item in value]
    return value


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Seed ToxicJoin governed demo metadata into a live DataHub instance"
    )
    parser.add_argument(
        "--output",
        default=".toxicjoin/datahub-seed.json",
        help="Sanitized JSON seed report",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Required explicit acknowledgement that live DataHub will be mutated",
    )
    args = parser.parse_args()

    if not args.yes:
        parser.error("--yes is required because this command mutates live DataHub metadata")

    try:
        report = seed_live_datahub(output=args.output)
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "error_type": type(exc).__name__,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        raise SystemExit(1) from exc

    print(report.model_dump_json(indent=2))


if __name__ == "__main__":
    main()
