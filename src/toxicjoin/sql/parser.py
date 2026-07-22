"""Fail-closed SQL parsing and query-plan extraction.

This module is deliberately conservative. It accepts one read-only SELECT query,
extracts the governed inputs needed by the policy engine, and rejects constructs
that cannot be resolved safely.
"""

from __future__ import annotations

from collections.abc import Iterable

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError, TokenError
from sqlglot.optimizer.scope import Scope, traverse_scope

from toxicjoin.models import ColumnRef, QueryPlan, ReasonCode


class SqlAnalysisError(ValueError):
    """Deterministic analysis failure with a machine-readable reason code."""

    def __init__(self, reason_code: ReasonCode, detail: str) -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{reason_code.value}: {detail}")


def analyze_sql(sql: str, *, dialect: str = "duckdb") -> QueryPlan:
    """Parse one read-only SELECT statement into a normalized query plan.

    The analyzer performs no schema guessing. Qualified references are mapped to
    their physical source when possible, including simple CTE and derived-table
    projections. Unqualified references are accepted only when the current SQL
    scope has exactly one source; otherwise analysis fails closed.
    """

    if not sql or not sql.strip():
        raise SqlAnalysisError(ReasonCode.UNSUPPORTED_STATEMENT, "SQL input is empty")

    try:
        statements = [statement for statement in sqlglot.parse(sql, read=dialect) if statement]
    except (ParseError, TokenError, ValueError) as exc:
        raise SqlAnalysisError(
            ReasonCode.UNSUPPORTED_STATEMENT,
            f"SQL could not be parsed for dialect {dialect!r}: {exc}",
        ) from exc

    if len(statements) != 1:
        raise SqlAnalysisError(
            ReasonCode.MULTIPLE_STATEMENTS,
            f"expected exactly one statement, received {len(statements)}",
        )

    root = statements[0]
    if not isinstance(root, exp.Select):
        raise SqlAnalysisError(
            ReasonCode.UNSUPPORTED_STATEMENT,
            f"only SELECT is supported, received {root.key.upper()}",
        )

    _reject_forbidden_nodes(root)

    scopes = list(traverse_scope(root))
    if not scopes:
        raise SqlAnalysisError(
            ReasonCode.UNSUPPORTED_STATEMENT,
            "SQLGlot could not build a query scope",
        )

    source_datasets: set[str] = set()
    projected_columns: set[ColumnRef] = set()
    referenced_columns: set[ColumnRef] = set()
    join_columns: set[ColumnRef] = set()
    group_by_columns: set[ColumnRef] = set()
    aggregate_functions: set[str] = set()
    warnings: set[str] = set()

    root_scope: Scope | None = None

    for scope in scopes:
        physical_sources = _physical_sources(scope)
        source_datasets.update(physical_sources)
        select = scope.expression

        if not isinstance(select, exp.Select):
            raise SqlAnalysisError(
                ReasonCode.UNSUPPORTED_STATEMENT,
                f"unsupported query scope: {select.key.upper()}",
            )

        if select is root:
            root_scope = scope

        _validate_joins(select)

        referenced_columns.update(
            _resolve_columns(
                _columns_belonging_to(select, select),
                scope=scope,
                warnings=warnings,
            )
        )

        for projection in select.expressions:
            if projection.find(exp.Star):
                warnings.add("SELECT_STAR_REQUIRES_SCHEMA_EXPANSION")
            projected_columns.update(
                _resolve_columns(
                    _columns_belonging_to(projection, select),
                    scope=scope,
                    warnings=warnings,
                )
            )

        for join in select.args.get("joins") or ():
            if join.args.get("using"):
                raise SqlAnalysisError(
                    ReasonCode.UNSUPPORTED_STATEMENT,
                    "JOIN ... USING is outside the supported MVP profile; use an explicit ON clause",
                )
            on_expression = join.args.get("on")
            if on_expression is not None:
                join_columns.update(
                    _resolve_columns(
                        _columns_belonging_to(on_expression, select),
                        scope=scope,
                        warnings=warnings,
                    )
                )

        group = select.args.get("group")
        if group is not None:
            group_by_columns.update(
                _resolve_columns(
                    _columns_belonging_to(group, select),
                    scope=scope,
                    warnings=warnings,
                )
            )

        for aggregate in _nodes_belonging_to(select, select, exp.AggFunc):
            aggregate_functions.add(aggregate.key.upper())

    if root_scope is None:
        raise SqlAnalysisError(
            ReasonCode.UNSUPPORTED_STATEMENT,
            "SQLGlot did not expose a root query scope",
        )

    minimum_group_size, minimum_group_subject = _extract_minimum_group_threshold(
        root,
        root_scope,
        warnings,
    )

    contains_wildcard = any(isinstance(node, exp.Star) for node in root.walk())
    is_grouped = bool(group_by_columns or aggregate_functions)

    return QueryPlan(
        statement_type="SELECT",
        source_datasets=tuple(sorted(source_datasets)),
        projected_columns=_sorted_refs(projected_columns),
        referenced_columns=_sorted_refs(referenced_columns),
        join_columns=_sorted_refs(join_columns),
        group_by_columns=_sorted_refs(group_by_columns),
        aggregate_functions=tuple(sorted(aggregate_functions)),
        minimum_group_size_present=minimum_group_size,
        minimum_group_size_subject=minimum_group_subject,
        is_grouped=is_grouped,
        contains_wildcard=contains_wildcard,
        analysis_warnings=tuple(sorted(warnings)),
    )


def _reject_forbidden_nodes(root: exp.Select) -> None:
    forbidden_names = (
        "Insert",
        "Update",
        "Delete",
        "Merge",
        "Create",
        "Drop",
        "Alter",
        "Command",
        "Transaction",
        "Commit",
        "Rollback",
        "Grant",
        "Revoke",
        "Use",
        "Set",
        "Copy",
        "Attach",
        "Detach",
        "Install",
        "LoadData",
    )
    forbidden_types = tuple(
        node_type
        for name in forbidden_names
        if (node_type := getattr(exp, name, None)) is not None
    )
    if forbidden_types and any(isinstance(node, forbidden_types) for node in root.walk()):
        raise SqlAnalysisError(
            ReasonCode.UNSUPPORTED_STATEMENT,
            "query contains a mutation, DDL, transaction, command, or external-access node",
        )


def _physical_sources(scope: Scope) -> set[str]:
    physical_sources: set[str] = set()
    for _, source in scope.sources.items():
        if isinstance(source, exp.Table):
            physical_sources.add(_qualified_table_name(source))
    return physical_sources


def _qualified_table_name(table: exp.Table) -> str:
    parts = [table.catalog, table.db, table.name]
    normalized = [part for part in parts if part]
    if not normalized:
        raise SqlAnalysisError(ReasonCode.UNRESOLVED_DATASET, "table has no resolvable name")
    return ".".join(normalized)


def _validate_joins(select: exp.Select) -> None:
    for join in select.args.get("joins") or ():
        side = str(join.args.get("side") or "").upper()
        kind = str(join.args.get("kind") or "").upper()
        method = str(join.args.get("method") or "").upper()

        if side not in {"", "LEFT"} or kind not in {"", "INNER"} or method:
            rendered = join.sql(comments=False)
            raise SqlAnalysisError(
                ReasonCode.UNSUPPORTED_STATEMENT,
                f"unsupported join profile: {rendered}",
            )

        if side == "" and kind == "" and join.args.get("on") is None and not join.args.get("using"):
            raise SqlAnalysisError(
                ReasonCode.UNSUPPORTED_STATEMENT,
                "implicit or cross joins are outside the supported MVP profile",
            )


def _extract_minimum_group_threshold(
    select: exp.Select,
    scope: Scope,
    warnings: set[str],
) -> tuple[int | None, ColumnRef | None]:
    having = select.args.get("having")
    if having is None:
        return None, None

    body = having.this if isinstance(having, exp.Having) else having
    if any(isinstance(node, exp.Or) for node in body.walk()):
        warnings.add("UNTRUSTED_GROUP_THRESHOLD_OR_EXPRESSION")
        return None, None

    candidates: list[tuple[int, ColumnRef]] = []
    for node in body.walk():
        candidate: tuple[exp.Expression, exp.Expression] | None = None
        if isinstance(node, exp.GTE):
            candidate = (node.this, node.expression)
        elif isinstance(node, exp.LTE):
            candidate = (node.expression, node.this)

        if candidate is None:
            continue

        count_expression, literal_expression = candidate
        literal = _integer_literal(literal_expression)
        distinct_column = _count_distinct_column(count_expression, select)
        if literal is None or distinct_column is None:
            continue

        resolved = _resolve_columns(
            (distinct_column,),
            scope=scope,
            warnings=warnings,
        )
        if len(resolved) != 1:
            warnings.add("UNTRUSTED_GROUP_THRESHOLD_AMBIGUOUS_SUBJECT")
            continue
        candidates.append((literal, next(iter(resolved))))

    if not candidates:
        return None, None

    subjects = {column.key for _, column in candidates}
    if len(subjects) != 1:
        warnings.add("UNTRUSTED_GROUP_THRESHOLD_MULTIPLE_SUBJECTS")
        return None, None

    threshold, subject = max(candidates, key=lambda item: item[0])
    return threshold, subject


def _integer_literal(expression: exp.Expression) -> int | None:
    if not isinstance(expression, exp.Literal) or expression.is_string:
        return None
    try:
        value = int(str(expression.this))
    except (TypeError, ValueError):
        return None
    return value if value >= 1 else None


def _count_distinct_column(
    expression: exp.Expression,
    select: exp.Select,
) -> exp.Column | None:
    if not isinstance(expression, exp.Count):
        return None

    target = expression.this
    is_distinct = isinstance(target, exp.Distinct) or bool(expression.args.get("distinct"))
    if not is_distinct:
        return None

    columns = _columns_belonging_to(expression, select)
    if len(columns) != 1:
        return None
    return columns[0]


def _resolve_columns(
    columns: Iterable[exp.Column],
    *,
    scope: Scope,
    warnings: set[str],
    visited: frozenset[tuple[int, str]] = frozenset(),
) -> set[ColumnRef]:
    resolved: set[ColumnRef] = set()
    for column in columns:
        resolved.update(
            _resolve_column(
                column,
                scope=scope,
                warnings=warnings,
                visited=visited,
            )
        )
    return resolved


def _resolve_column(
    column: exp.Column,
    *,
    scope: Scope,
    warnings: set[str],
    visited: frozenset[tuple[int, str]],
) -> set[ColumnRef]:
    qualifier = column.table
    source_name, source = _selected_source(scope, qualifier, column.name)

    if isinstance(source, exp.Table):
        return {
            ColumnRef(
                dataset=_qualified_table_name(source),
                field_path=column.name,
                alias=qualifier or source_name or None,
            )
        }

    if isinstance(source, Scope):
        return _resolve_derived_output(
            output_name=column.name,
            source_scope=source,
            source_name=source_name or qualifier or "derived",
            warnings=warnings,
            visited=visited,
        )

    unresolved_name = qualifier or source_name or "unknown"
    warnings.add(f"UNRESOLVED_SOURCE_ALIAS:{unresolved_name}")
    return {
        ColumnRef(
            dataset=f"@unresolved:{unresolved_name}",
            field_path=column.name,
            alias=qualifier or source_name or None,
        )
    }


def _selected_source(
    scope: Scope,
    qualifier: str,
    column_name: str,
) -> tuple[str | None, exp.Expression | Scope | None]:
    if qualifier:
        selected = scope.selected_sources.get(qualifier)
        if selected is not None:
            return qualifier, selected[1]
        return qualifier, scope.sources.get(qualifier)

    candidates = list(scope.selected_sources.items())
    if len(candidates) != 1:
        raise SqlAnalysisError(
            ReasonCode.AMBIGUOUS_COLUMN,
            f"unqualified column {column_name!r} has {len(candidates)} possible sources",
        )
    source_name, (_, source) = candidates[0]
    return source_name, source


def _resolve_derived_output(
    *,
    output_name: str,
    source_scope: Scope,
    source_name: str,
    warnings: set[str],
    visited: frozenset[tuple[int, str]],
) -> set[ColumnRef]:
    visit_key = (id(source_scope), output_name)
    if visit_key in visited:
        warnings.add(f"CYCLIC_DERIVED_REFERENCE:{source_name}.{output_name}")
        return {
            ColumnRef(
                dataset=f"@unresolved:{source_name}",
                field_path=output_name,
                alias=source_name,
            )
        }

    expression = source_scope.expression
    if not isinstance(expression, exp.Select):
        warnings.add(f"UNSUPPORTED_DERIVED_SCOPE:{source_name}")
        return {
            ColumnRef(
                dataset=f"@unresolved:{source_name}",
                field_path=output_name,
                alias=source_name,
            )
        }

    matches = [
        projection
        for projection in expression.expressions
        if projection.alias_or_name == output_name
    ]
    if len(matches) != 1:
        if any(projection.find(exp.Star) for projection in expression.expressions):
            warnings.add(f"DERIVED_STAR_REQUIRES_SCHEMA_EXPANSION:{source_name}")
        else:
            warnings.add(f"UNRESOLVED_DERIVED_COLUMN:{source_name}.{output_name}")
        return {
            ColumnRef(
                dataset=f"@unresolved:{source_name}",
                field_path=output_name,
                alias=source_name,
            )
        }

    projection = matches[0]
    source_columns = _columns_belonging_to(projection, expression)
    if not source_columns:
        # A literal or COUNT(*) has no governed source field. It is safe to omit from
        # metadata resolution, while aggregate presence remains in QueryPlan.
        return set()

    return _resolve_columns(
        source_columns,
        scope=source_scope,
        warnings=warnings,
        visited=visited | {visit_key},
    )


def _columns_belonging_to(expression: exp.Expression, select: exp.Select) -> tuple[exp.Column, ...]:
    return tuple(
        column
        for column in expression.find_all(exp.Column)
        if _nearest_select(column) is select
    )


def _nodes_belonging_to(
    expression: exp.Expression,
    select: exp.Select,
    node_type: type[exp.Expression],
) -> tuple[exp.Expression, ...]:
    return tuple(
        node
        for node in expression.find_all(node_type)
        if _nearest_select(node) is select
    )


def _nearest_select(node: exp.Expression) -> exp.Select | None:
    current = node.parent
    while current is not None:
        if isinstance(current, exp.Select):
            return current
        current = current.parent
    return None


def _sorted_refs(values: set[ColumnRef]) -> tuple[ColumnRef, ...]:
    return tuple(
        sorted(
            values,
            key=lambda value: (value.dataset, value.field_path, value.alias or ""),
        )
    )
