"""Public SQL analyzer with root-output lineage correction.

The low-level parser walks every scope so it can capture all governed references.
That is correct for risk evidence, but intermediate CTE projections are not final
output columns. This layer recomputes only the root SELECT projections while
preserving the complete referenced-column graph from the parser.
"""

from __future__ import annotations

import sqlglot
from sqlglot import exp
from sqlglot.optimizer.scope import Scope, traverse_scope

from toxicjoin.models import (
    ColumnRef,
    ProjectionExposure,
    ProjectionExposureKind,
    QueryPlan,
    ReasonCode,
)
from toxicjoin.sql.parser import (
    SqlAnalysisError,
    _columns_belonging_to,
    _resolve_columns,
    _selected_source,
    _sorted_refs,
    analyze_sql as _analyze_all_scopes,
)


def analyze_sql(sql: str, *, dialect: str = "duckdb") -> QueryPlan:
    """Return a QueryPlan whose projected columns describe root output only."""

    plan = _analyze_all_scopes(sql, dialect=dialect)
    root = sqlglot.parse_one(sql, read=dialect)
    if not isinstance(root, exp.Select):
        raise SqlAnalysisError(
            ReasonCode.UNSUPPORTED_STATEMENT,
            f"only SELECT is supported, received {root.key.upper()}",
        )
    root_scope = _find_root_scope(root)
    warnings = set(plan.analysis_warnings)
    warnings.discard("SELECT_STAR_REQUIRES_SCHEMA_EXPANSION")
    root_projected: set[ColumnRef] = set()
    projected_exposures: list[ProjectionExposure] = []
    contains_output_wildcard = False

    for projection in root.expressions:
        if _is_output_wildcard(projection):
            contains_output_wildcard = True
            warnings.add("SELECT_STAR_REQUIRES_SCHEMA_EXPANSION")

        resolved = _resolve_columns(
            _columns_belonging_to(projection, root),
            scope=root_scope,
            warnings=warnings,
        )
        root_projected.update(resolved)

        exposure = _projection_exposure(
            projection,
            root=root,
            root_scope=root_scope,
            warnings=warnings,
            resolved=resolved,
        )
        if exposure is not None:
            projected_exposures.append(exposure)

    return plan.model_copy(
        update={
            "projected_columns": _sorted_refs(root_projected),
            "projected_exposures": tuple(projected_exposures),
            "contains_wildcard": contains_output_wildcard,
            "analysis_warnings": tuple(sorted(warnings)),
        }
    )


def _projection_exposure(
    projection: exp.Expression,
    *,
    root: exp.Select,
    root_scope: Scope,
    warnings: set[str],
    resolved: set[ColumnRef],
) -> ProjectionExposure | None:
    expression = projection.this if isinstance(projection, exp.Alias) else projection
    output_name = projection.alias_or_name or expression.sql(comments=False)

    if not resolved:
        if any(
            isinstance(node, exp.Select) and node is not root
            for node in expression.walk()
        ):
            warnings.add("NESTED_OUTPUT_SCOPE_REQUIRES_LINEAGE")
            return ProjectionExposure(
                output_name=output_name,
                kind=ProjectionExposureKind.NESTED_SCOPE,
            )
        return None

    kind = _classify_projection_expression(
        expression,
        select=root,
        scope=root_scope,
        warnings=warnings,
    )
    return ProjectionExposure(
        output_name=output_name,
        kind=kind,
        source_columns=_sorted_refs(resolved),
    )


def _classify_projection_expression(
    expression: exp.Expression,
    *,
    select: exp.Select,
    scope: Scope,
    warnings: set[str],
    visited: frozenset[tuple[int, str]] = frozenset(),
) -> ProjectionExposureKind:
    if isinstance(expression, exp.Alias):
        expression = expression.this

    if _contains_filtered_or_countif_aggregate(expression):
        return ProjectionExposureKind.CONDITIONAL_AGGREGATE

    if isinstance(expression, exp.Column):
        kind = _source_column_kind(
            expression,
            scope=scope,
            warnings=warnings,
            visited=visited,
        )
        if kind == ProjectionExposureKind.RAW_VALUE and _is_group_key(
            expression,
            select=select,
            scope=scope,
            warnings=warnings,
        ):
            return ProjectionExposureKind.GROUP_KEY
        return kind

    columns = _columns_belonging_to(expression, select)
    if not columns:
        return ProjectionExposureKind.NESTED_SCOPE

    count_backed = False
    for column in columns:
        aggregate_kind = _aggregate_operand_kind(column, select)
        if aggregate_kind == ProjectionExposureKind.CONDITIONAL_AGGREGATE:
            return ProjectionExposureKind.CONDITIONAL_AGGREGATE
        if aggregate_kind == ProjectionExposureKind.AGGREGATE_VALUE:
            count_backed = True
            continue
        if aggregate_kind == ProjectionExposureKind.AGGREGATE_OPERAND:
            return ProjectionExposureKind.AGGREGATE_OPERAND

        source_kind = _source_column_kind(
            column,
            scope=scope,
            warnings=warnings,
            visited=visited,
        )
        if source_kind == ProjectionExposureKind.CONDITIONAL_AGGREGATE:
            return ProjectionExposureKind.CONDITIONAL_AGGREGATE
        if source_kind == ProjectionExposureKind.AGGREGATE_VALUE:
            count_backed = True
            continue
        if source_kind == ProjectionExposureKind.AGGREGATE_OPERAND:
            return ProjectionExposureKind.AGGREGATE_OPERAND
        if source_kind == ProjectionExposureKind.NESTED_SCOPE:
            return ProjectionExposureKind.NESTED_SCOPE
        return ProjectionExposureKind.TRANSFORMED_RAW_VALUE

    return (
        ProjectionExposureKind.AGGREGATE_VALUE
        if count_backed
        else ProjectionExposureKind.TRANSFORMED_RAW_VALUE
    )


def _source_column_kind(
    column: exp.Column,
    *,
    scope: Scope,
    warnings: set[str],
    visited: frozenset[tuple[int, str]],
) -> ProjectionExposureKind:
    _, source = _selected_source(scope, column.table, column.name)
    if isinstance(source, exp.Table):
        return ProjectionExposureKind.RAW_VALUE
    if not isinstance(source, Scope):
        return ProjectionExposureKind.NESTED_SCOPE

    visit_key = (id(source), column.name)
    if visit_key in visited:
        warnings.add(f"CYCLIC_EXPOSURE_LINEAGE:{column.name}")
        return ProjectionExposureKind.NESTED_SCOPE

    expression = source.expression
    if not isinstance(expression, exp.Select):
        return ProjectionExposureKind.NESTED_SCOPE

    matches = [
        projection
        for projection in expression.expressions
        if projection.alias_or_name == column.name
    ]
    if len(matches) != 1:
        warnings.add(f"UNRESOLVED_EXPOSURE_LINEAGE:{column.name}")
        return ProjectionExposureKind.NESTED_SCOPE

    projection = matches[0]
    inner = projection.this if isinstance(projection, exp.Alias) else projection
    return _classify_projection_expression(
        inner,
        select=expression,
        scope=source,
        warnings=warnings,
        visited=visited | {visit_key},
    )


def _is_group_key(
    column: exp.Column,
    *,
    select: exp.Select,
    scope: Scope,
    warnings: set[str],
) -> bool:
    group = select.args.get("group")
    if group is None:
        return False

    current = _resolve_columns((column,), scope=scope, warnings=warnings)
    grouped = _resolve_columns(
        _columns_belonging_to(group, select),
        scope=scope,
        warnings=warnings,
    )
    current_keys = {ref.key for ref in current}
    grouped_keys = {ref.key for ref in grouped}
    return bool(current_keys.intersection(grouped_keys))


def _aggregate_operand_kind(
    column: exp.Column,
    select: exp.Select,
) -> ProjectionExposureKind | None:
    """Classify aggregate operands conservatively.

    Only direct ``COUNT(column)`` / ``COUNT(DISTINCT column)`` cardinality is treated
    as an aggregate value. COUNT expressions that transform, filter, branch on, or
    otherwise predicate governed values are conditional disclosures: the outer group
    size does not prove that the predicate-defined subpopulation satisfies k-anonymity.
    Other aggregates may preserve or reconstruct source values and therefore remain
    semantically exposed operands.
    """

    current = column.parent
    while current is not None and current is not select:
        if isinstance(current, exp.AggFunc):
            if isinstance(current, exp.Count):
                return (
                    ProjectionExposureKind.AGGREGATE_VALUE
                    if _count_is_pure_cardinality(current)
                    else ProjectionExposureKind.CONDITIONAL_AGGREGATE
                )
            if current.key.upper() in {"COUNT_IF", "COUNTIF"}:
                return ProjectionExposureKind.CONDITIONAL_AGGREGATE
            return ProjectionExposureKind.AGGREGATE_OPERAND
        current = current.parent
    return None


def _count_is_pure_cardinality(count: exp.Count) -> bool:
    """Return true only when COUNT cannot encode an output predicate.

    COUNT(*) has no governed operand. Direct COUNT(column) and
    COUNT(DISTINCT column) reveal cardinality/missingness only. Any expression around
    the operand (CASE, IF, arithmetic, comparison, function call, etc.) is considered
    conditional and must be handled by policy as a protected disclosure.
    """

    argument = count.this
    if argument is None or isinstance(argument, exp.Star):
        return True
    if isinstance(argument, exp.Column):
        return True
    if isinstance(argument, exp.Distinct):
        expressions = tuple(argument.expressions)
        return len(expressions) == 1 and isinstance(expressions[0], exp.Column)
    return False


def _contains_filtered_or_countif_aggregate(expression: exp.Expression) -> bool:
    """Detect predicate-bearing aggregate syntax outside an aggregate's direct operand.

    SQLGlot represents ``COUNT(x) FILTER (WHERE predicate)`` as a Filter node whose
    aggregate and predicate are siblings, so walking only from predicate columns toward
    an AggFunc can miss the conditional semantics. COUNT_IF/COUNTIF are conditional by
    definition and are treated the same way when the dialect parser exposes them.
    """

    for node in expression.walk():
        if isinstance(node, exp.Filter) and isinstance(node.this, exp.AggFunc):
            return True
        if isinstance(node, exp.AggFunc) and node.key.upper() in {"COUNT_IF", "COUNTIF"}:
            return True
    return False


def _is_output_wildcard(projection: exp.Expression) -> bool:
    expression = projection.this if isinstance(projection, exp.Alias) else projection
    return isinstance(expression, exp.Star) or (
        isinstance(expression, exp.Column) and isinstance(expression.this, exp.Star)
    )


def _find_root_scope(root: exp.Select) -> Scope:
    for scope in traverse_scope(root):
        if scope.expression is root:
            return scope
    raise SqlAnalysisError(
        ReasonCode.UNSUPPORTED_STATEMENT,
        "SQLGlot did not expose a root query scope",
    )
