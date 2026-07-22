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
    their physical source when possible. Unqualified references are accepted only
    when the current SQL scope has exactly one source; otherwise analysis fails
    closed with ``AMBIGUOUS_COLUMN``.
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
    join_columns: set[ColumnRef] = set()
    group_by_columns: set[ColumnRef] = set()
    aggregate_functions: set[str] = set()
    warnings: set[str] = set()

    for scope in scopes:
        alias_map, physical_sources = _source_map(scope)
        source_datasets.update(physical_sources)
        select = scope.expression

        if not isinstance(select, exp.Select):
            raise SqlAnalysisError(
                ReasonCode.UNSUPPORTED_STATEMENT,
                f"unsupported query scope: {select.key.upper()}",
            )

        _validate_joins(select)

        for projection in select.expressions:
            if projection.find(exp.Star):
                warnings.add("SELECT_STAR_REQUIRES_SCHEMA_EXPANSION")
            projected_columns.update(
                _resolve_columns(
                    _columns_belonging_to(projection, select),
                    alias_map=alias_map,
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
                        alias_map=alias_map,
                        scope=scope,
                        warnings=warnings,
                    )
                )

        group = select.args.get("group")
        if group is not None:
            group_by_columns.update(
                _resolve_columns(
                    _columns_belonging_to(group, select),
                    alias_map=alias_map,
                    scope=scope,
                    warnings=warnings,
                )
            )

        for aggregate in _nodes_belonging_to(select, select, exp.AggFunc):
            aggregate_functions.add(aggregate.key.upper())

    contains_wildcard = any(isinstance(node, exp.Star) for node in root.walk())
    is_grouped = bool(group_by_columns or aggregate_functions)

    return QueryPlan(
        statement_type="SELECT",
        source_datasets=tuple(sorted(source_datasets)),
        projected_columns=_sorted_refs(projected_columns),
        join_columns=_sorted_refs(join_columns),
        group_by_columns=_sorted_refs(group_by_columns),
        aggregate_functions=tuple(sorted(aggregate_functions)),
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
    )
    forbidden_types = tuple(
        node_type
        for name in forbidden_names
        if (node_type := getattr(exp, name, None)) is not None
    )
    if forbidden_types and any(isinstance(node, forbidden_types) for node in root.walk()):
        raise SqlAnalysisError(
            ReasonCode.UNSUPPORTED_STATEMENT,
            "query contains a mutation, DDL, transaction, or command node",
        )


def _source_map(scope: Scope) -> tuple[dict[str, str], set[str]]:
    alias_map: dict[str, str] = {}
    physical_sources: set[str] = set()

    for alias, (_, source) in scope.selected_sources.items():
        if isinstance(source, exp.Table):
            dataset = _qualified_table_name(source)
            alias_map[alias] = dataset
            physical_sources.add(dataset)
        elif isinstance(source, Scope):
            alias_map[alias] = f"@derived:{alias}"
        else:
            alias_map[alias] = f"@unresolved:{alias}"

    return alias_map, physical_sources


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


def _resolve_columns(
    columns: Iterable[exp.Column],
    *,
    alias_map: dict[str, str],
    scope: Scope,
    warnings: set[str],
) -> set[ColumnRef]:
    resolved: set[ColumnRef] = set()

    for column in columns:
        qualifier = column.table
        if qualifier:
            dataset = alias_map.get(qualifier)
            if dataset is None:
                dataset = f"@unresolved:{qualifier}"
                warnings.add(f"UNRESOLVED_SOURCE_ALIAS:{qualifier}")
        else:
            candidates = tuple(dict.fromkeys(alias_map.values()))
            if len(candidates) != 1:
                raise SqlAnalysisError(
                    ReasonCode.AMBIGUOUS_COLUMN,
                    f"unqualified column {column.name!r} has {len(candidates)} possible sources",
                )
            dataset = candidates[0]

        resolved.add(
            ColumnRef(
                dataset=dataset,
                field_path=column.name,
                alias=qualifier or None,
            )
        )

    return resolved


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
    return tuple(sorted(values, key=lambda value: (value.dataset, value.field_path, value.alias or "")))
