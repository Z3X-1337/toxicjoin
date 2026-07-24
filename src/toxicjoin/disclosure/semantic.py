"""Build governed, caller-name-insensitive disclosure semantics from analyzed SQL."""

from __future__ import annotations

from typing import Protocol

from toxicjoin.auth import RequestIdentity
from toxicjoin.context.fixture import FixtureCatalog
from toxicjoin.context.models import ContextResolution
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
    ColumnContext,
    ColumnRef,
    ProjectionExposure,
    QueryPlan,
    SensitivityCategory,
)


_SUBJECT_CATEGORIES = {
    SensitivityCategory.DIRECT_IDENTIFIER,
    SensitivityCategory.STABLE_PSEUDONYM,
}


class ContextResolver(Protocol):
    def resolve(self, query_plan: QueryPlan) -> ContextResolution: ...


class DisclosureSemanticError(ValueError):
    """Raised when governed disclosure semantics cannot be derived safely."""


def resolve_governed_subject_domain(
    catalog: FixtureCatalog,
    *,
    subject_key: ColumnRef,
    source_datasets: tuple[str, ...],
) -> GovernedSubjectDomain:
    """Resolve a stable identifier namespace from fixture/catalog governance."""

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
        if field is None:
            continue
        if field.category not in _SUBJECT_CATEGORIES:
            raise DisclosureSemanticError(
                "conflicting governed subject categories across query source datasets"
            )
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


def resolve_governed_subject_domain_from_resolver(
    resolver: ContextResolver,
    *,
    query_plan: QueryPlan,
    subject_key: ColumnRef,
) -> tuple[GovernedSubjectDomain, tuple[ColumnContext, ...]]:
    """Resolve the subject namespace through the same provider used for authorization.

    A synthetic metadata-only probe asks the resolver for the subject field on every
    query source. Missing fields on secondary sources are ignored, while a same-named
    field that exists with conflicting/non-identifier governance fails closed.
    """

    sources = tuple(sorted(set(query_plan.source_datasets)))
    if not sources:
        raise DisclosureSemanticError("subject domain requires at least one source dataset")
    if subject_key.dataset not in sources:
        raise DisclosureSemanticError("subject key dataset must participate in the query")

    refs = tuple(
        ColumnRef(dataset=dataset, field_path=subject_key.field_path)
        for dataset in sources
    )
    probe = QueryPlan(
        statement_type="SELECT",
        source_datasets=sources,
        projected_columns=(),
        referenced_columns=refs,
    )
    try:
        resolution = resolver.resolve(probe)
    except Exception as exc:
        raise DisclosureSemanticError("subject governance probe failed") from exc

    contexts = _context_map(resolution.all_referenced_context)
    requested = contexts.get(f"{subject_key.dataset}.{subject_key.field_path}")
    if requested is None or not requested.resolved:
        raise DisclosureSemanticError("subject key field is not governed")
    if requested.category not in _SUBJECT_CATEGORIES:
        raise DisclosureSemanticError(
            "subject key must be a direct identifier or stable pseudonym"
        )

    resolved_subjects: list[ColumnContext] = []
    observed_categories: set[SensitivityCategory] = set()
    dataset_urns: list[str] = []
    for dataset in sources:
        context = contexts.get(f"{dataset}.{subject_key.field_path}")
        if context is None or not context.resolved:
            if dataset == subject_key.dataset:
                raise DisclosureSemanticError("subject key field is not governed")
            continue
        if context.category not in _SUBJECT_CATEGORIES:
            raise DisclosureSemanticError(
                "conflicting governed subject categories across query source datasets"
            )
        if context.datahub_urn is None:
            raise DisclosureSemanticError("subject governance is missing dataset URN")
        resolved_subjects.append(context)
        observed_categories.add(context.category)
        dataset_urns.append(context.datahub_urn)

    if not resolved_subjects:
        raise DisclosureSemanticError("no governed subject identifier exists in query sources")
    if observed_categories != {requested.category}:
        raise DisclosureSemanticError(
            "conflicting governed subject categories across query source datasets"
        )

    namespace_sha256 = compute_subject_namespace_sha256(
        subject_key.field_path,
        requested.category,
    )
    subject = GovernedSubjectDomain(
        field_path=subject_key.field_path,
        category=requested.category,
        dataset_urns=tuple(sorted(set(dataset_urns))),
        governance_domains=(),
        namespace_sha256=namespace_sha256,
    )
    return subject, tuple(sorted(resolved_subjects, key=lambda item: item.ref.key))


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
    """Build governed release metadata from an explicit fixture/catalog snapshot."""

    source_dataset_urns = tuple(
        sorted(_dataset_urn(catalog, name) for name in set(query_plan.source_datasets))
    )
    outputs = tuple(
        _semantic_output(catalog, exposure) for exposure in query_plan.projected_exposures
    )
    referenced = _governed_columns(catalog, query_plan.referenced_columns)
    joins = _governed_columns(catalog, query_plan.join_columns)
    groups = _governed_columns(catalog, query_plan.group_by_columns)
    return _build_release(
        source_dataset_urns=source_dataset_urns,
        outputs=outputs,
        referenced=referenced,
        joins=joins,
        groups=groups,
        query_plan=query_plan,
    )


def build_semantic_release_from_resolution(
    query_plan: QueryPlan,
    resolution: ContextResolution,
    *,
    additional_context: tuple[ColumnContext, ...] = (),
) -> DisclosureSemanticRelease:
    """Build release semantics from the exact normalized governance used by policy."""

    contexts = _context_map(
        resolution.all_referenced_context
        + resolution.projected_context
        + additional_context
    )
    source_dataset_urns: list[str] = []
    for dataset in sorted(set(query_plan.source_datasets)):
        urns = {
            context.datahub_urn
            for context in contexts.values()
            if context.ref.dataset == dataset
            and context.resolved
            and context.datahub_urn is not None
        }
        if len(urns) != 1:
            raise DisclosureSemanticError(
                f"source dataset governance is unresolved or ambiguous: {dataset}"
            )
        source_dataset_urns.append(next(iter(urns)))

    outputs = tuple(
        SemanticOutput(
            kind=exposure.kind,
            sources=_governed_columns_from_context(exposure.source_columns, contexts),
        )
        for exposure in query_plan.projected_exposures
    )
    referenced = _governed_columns_from_context(query_plan.referenced_columns, contexts)
    joins = _governed_columns_from_context(query_plan.join_columns, contexts)
    groups = _governed_columns_from_context(query_plan.group_by_columns, contexts)
    return _build_release(
        source_dataset_urns=tuple(source_dataset_urns),
        outputs=outputs,
        referenced=referenced,
        joins=joins,
        groups=groups,
        query_plan=query_plan,
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
        audit_identity=DisclosureAuditIdentity(credential_id=identity.credential_id),
        receipt_id=receipt_id,
        policy_version=policy_version,
        semantic=build_semantic_release(catalog, query_plan),
    )


def build_disclosure_event_from_resolver(
    *,
    identity: RequestIdentity,
    resolver: ContextResolver,
    resolution: ContextResolution,
    query_plan: QueryPlan,
    subject_key: ColumnRef,
    receipt_id: str,
    policy_version: str,
) -> DisclosureEvent:
    """Build one provider-neutral event from the exact verifier governance snapshot."""

    subject, subject_context = resolve_governed_subject_domain_from_resolver(
        resolver,
        query_plan=query_plan,
        subject_key=subject_key,
    )
    semantic = build_semantic_release_from_resolution(
        query_plan,
        resolution,
        additional_context=subject_context,
    )
    return DisclosureEvent(
        scope=build_disclosure_scope(identity, subject),
        audit_identity=DisclosureAuditIdentity(credential_id=identity.credential_id),
        receipt_id=receipt_id,
        policy_version=policy_version,
        semantic=semantic,
    )


def _build_release(
    *,
    source_dataset_urns: tuple[str, ...],
    outputs: tuple[SemanticOutput, ...],
    referenced: tuple[GovernedColumn, ...],
    joins: tuple[GovernedColumn, ...],
    groups: tuple[GovernedColumn, ...],
    query_plan: QueryPlan,
) -> DisclosureSemanticRelease:
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
    return DisclosureSemanticRelease(
        source_dataset_urns=source_dataset_urns,
        outputs=outputs,
        referenced_columns=referenced,
        join_columns=joins,
        group_keys=groups,
        aggregate_functions=aggregates,
        minimum_group_size_present=query_plan.minimum_group_size_present,
        semantic_sha256=compute_semantic_sha256(provisional),
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


def _governed_columns_from_context(
    refs: tuple[ColumnRef, ...],
    contexts: dict[str, ColumnContext],
) -> tuple[GovernedColumn, ...]:
    columns: dict[str, GovernedColumn] = {}
    for ref in refs:
        context = contexts.get(ref.key)
        if context is None or not context.resolved:
            raise DisclosureSemanticError(f"source column is not governed: {ref.key}")
        if context.category == SensitivityCategory.UNCLASSIFIED:
            raise DisclosureSemanticError(f"source column is unclassified: {ref.key}")
        if context.datahub_urn is None:
            raise DisclosureSemanticError(f"source column is missing dataset URN: {ref.key}")
        column = GovernedColumn(
            dataset_urn=context.datahub_urn,
            field_path=ref.field_path,
            category=context.category,
        )
        columns[column.key] = column
    return tuple(columns[key] for key in sorted(columns))


def _context_map(values: tuple[ColumnContext, ...]) -> dict[str, ColumnContext]:
    contexts: dict[str, ColumnContext] = {}
    for context in values:
        existing = contexts.get(context.ref.key)
        if existing is not None and not _same_governance_context(existing, context):
            raise DisclosureSemanticError(
                f"conflicting governance context for column: {context.ref.key}"
            )
        if existing is None:
            contexts[context.ref.key] = context
    return contexts


def _same_governance_context(left: ColumnContext, right: ColumnContext) -> bool:
    """Compare governed identity while intentionally ignoring SQL alias metadata."""

    return (
        left.ref.dataset == right.ref.dataset
        and left.ref.field_path == right.ref.field_path
        and left.category == right.category
        and left.datahub_urn == right.datahub_urn
        and tuple(sorted(left.tags)) == tuple(sorted(right.tags))
        and tuple(sorted(left.glossary_terms)) == tuple(sorted(right.glossary_terms))
        and left.resolved == right.resolved
    )


def _dataset_urn(catalog: FixtureCatalog, logical_name: str) -> str:
    dataset = catalog.datasets.get(logical_name)
    if dataset is None:
        raise DisclosureSemanticError(f"source dataset is not governed: {logical_name}")
    return dataset.urn
