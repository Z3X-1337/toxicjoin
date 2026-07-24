"""Build governed, caller-name-insensitive disclosure semantics from analyzed SQL."""

from __future__ import annotations

from toxicjoin.auth import RequestIdentity
from toxicjoin.context.fixture import FixtureCatalog
from toxicjoin.disclosure.models import (
    DisclosureAuditIdentity,
    DisclosureEvent,
    DisclosureScope,
    DisclosureSemanticRelease,
    GovernedColumn,
    GovernedSubjectDomain,
    SemanticOutput,
    compute_scope_sha256,
    compute_semantic_sha256,
    compute_subject_namespace_sha256,
)
from toxicjoin.models import (
    ColumnRef,
    ProjectionExposure,
    QueryPlan,
    SensitivityCategory,
)


_SUBJECT_CATEGORIES = {
    SensitivityCategory.DIRECT_IDENTIFIER,
    SensitivityCategory.STABLE_PSEUDONYM,
}


class DisclosureSemanticError(ValueError):
    """Raised when governed disclosure semantics cannot be derived safely."""


def resolve_governed_subject_domain(
    catalog: FixtureCatalog,
    *,
    subject_key: ColumnRef,
    source_datasets: tuple[str, ...],
) -> GovernedSubjectDomain:
    """Resolve a stable identifier namespace across all participating datasets.

    The caller-selected dataset and alias are not allowed to partition privacy history.
    The field path and governed identifier category define the namespace, while all
    matching dataset/domain URNs are retained as audit evidence.
    """

    sources = tuple(sorted(set(source_datasets)))
    if not sources:
        raise DisclosureSemanticError("subject domain requires at least one source dataset")
    if subject_key.dataset not in sources:
        raise DisclosureSemanticError("subject key dataset must participate in the query")

    requested_dataset = catalog.datasets.get(subject_key.dataset)
    if requested_dataset is None:
        raise DisclosureSemanticError("subject key dataset is not governed")
    requested_field = requested_dataset.fields.get(subject_key.field_path)
    if requested_field is None:
        raise DisclosureSemanticError("subject key field is not governed")
    if requested_field.category not in _SUBJECT_CATEGORIES:
        raise DisclosureSemanticError(
            "subject key must be a direct identifier or stable pseudonym"
        )

    dataset_urns: list[str] = []
    governance_domains: list[str] = []
    observed_categories: set[SensitivityCategory] = set()
    for logical_name in sources:
        dataset = catalog.datasets.get(logical_name)
        if dataset is None:
            raise DisclosureSemanticError(f"source dataset is not governed: {logical_name}")
        field = dataset.fields.get(subject_key.field_path)
        if field is None or field.category not in _SUBJECT_CATEGORIES:
            continue
        dataset_urns.append(dataset.urn)
        observed_categories.add(field.category)
        if dataset.domain is not None:
            governance_domains.append(dataset.domain)

    if not dataset_urns:
        raise DisclosureSemanticError("no governed subject identifier exists in query sources")
    if observed_categories != {requested_field.category}:
        raise DisclosureSemanticError(
            "conflicting governed subject categories across query source datasets"
        )

    namespace_sha256 = compute_subject_namespace_sha256(
        subject_key.field_path,
        requested_field.category,
    )
    return GovernedSubjectDomain(
        field_path=subject_key.field_path,
        category=requested_field.category,
        dataset_urns=tuple(sorted(set(dataset_urns))),
        governance_domains=tuple(sorted(set(governance_domains))),
        namespace_sha256=namespace_sha256,
    )


def build_disclosure_scope(
    identity: RequestIdentity,
    subject: GovernedSubjectDomain,
) -> DisclosureScope:
    scope_sha256 = compute_scope_sha256(
        principal_id=identity.principal_id,
        agent_id=identity.agent_id,
        subject_namespace_sha256=subject.namespace_sha256,
    )
    return DisclosureScope(
        principal_id=identity.principal_id,
        agent_id=identity.agent_id,
        subject=subject,
        scope_sha256=scope_sha256,
    )


def build_semantic_release(
    catalog: FixtureCatalog,
    query_plan: QueryPlan,
) -> DisclosureSemanticRelease:
    """Build governed release metadata without SQL text, hashes, literals, or aliases."""

    source_dataset_urns = tuple(
        sorted(_dataset_urn(catalog, name) for name in set(query_plan.source_datasets))
    )
    outputs = tuple(
        _semantic_output(catalog, exposure) for exposure in query_plan.projected_exposures
    )
    referenced = _governed_columns(catalog, query_plan.referenced_columns)
    joins = _governed_columns(catalog, query_plan.join_columns)
    groups = _governed_columns(catalog, query_plan.group_by_columns)
    aggregates = tuple(
        sorted(set(function.strip().upper() for function in query_plan.aggregate_functions))
    )

    provisional = DisclosureSemanticRelease.model_construct(
        source_dataset_urns=source_dataset_urns,
        outputs=outputs,
        referenced_columns=referenced,
        join_columns=joins,
        group_keys=groups,
        aggregate_functions=aggregates,
        minimum_group_size_present=query_plan.minimum_group_size_present,
        semantic_sha256="0" * 64,
    )
    semantic_sha256 = compute_semantic_sha256(provisional)
    return DisclosureSemanticRelease(
        source_dataset_urns=source_dataset_urns,
        outputs=outputs,
        referenced_columns=referenced,
        join_columns=joins,
        group_keys=groups,
        aggregate_functions=aggregates,
        minimum_group_size_present=query_plan.minimum_group_size_present,
        semantic_sha256=semantic_sha256,
    )


def build_disclosure_event(
    *,
    identity: RequestIdentity,
    catalog: FixtureCatalog,
    query_plan: QueryPlan,
    subject_key: ColumnRef,
    receipt_id: str,
    policy_version: str,
) -> DisclosureEvent:
    subject = resolve_governed_subject_domain(
        catalog,
        subject_key=subject_key,
        source_datasets=query_plan.source_datasets,
    )
    return DisclosureEvent(
        scope=build_disclosure_scope(identity, subject),
        audit_identity=DisclosureAuditIdentity(
            credential_id=identity.credential_id,
        ),
        receipt_id=receipt_id,
        policy_version=policy_version,
        semantic=build_semantic_release(catalog, query_plan),
    )


def _semantic_output(
    catalog: FixtureCatalog,
    exposure: ProjectionExposure,
) -> SemanticOutput:
    return SemanticOutput(
        kind=exposure.kind,
        sources=_governed_columns(catalog, exposure.source_columns),
    )


def _governed_columns(
    catalog: FixtureCatalog,
    refs: tuple[ColumnRef, ...],
) -> tuple[GovernedColumn, ...]:
    columns: dict[str, GovernedColumn] = {}
    for ref in refs:
        column = _governed_column(catalog, ref)
        columns[column.key] = column
    return tuple(columns[key] for key in sorted(columns))


def _governed_column(catalog: FixtureCatalog, ref: ColumnRef) -> GovernedColumn:
    dataset = catalog.datasets.get(ref.dataset)
    if dataset is None:
        raise DisclosureSemanticError(f"source dataset is not governed: {ref.dataset}")
    field = dataset.fields.get(ref.field_path)
    if field is None:
        raise DisclosureSemanticError(f"source column is not governed: {ref.key}")
    if field.category == SensitivityCategory.UNCLASSIFIED:
        raise DisclosureSemanticError(f"source column is unclassified: {ref.key}")
    return GovernedColumn(
        dataset_urn=dataset.urn,
        field_path=ref.field_path,
        category=field.category,
    )


def _dataset_urn(catalog: FixtureCatalog, logical_name: str) -> str:
    dataset = catalog.datasets.get(logical_name)
    if dataset is None:
        raise DisclosureSemanticError(f"source dataset is not governed: {logical_name}")
    return dataset.urn
