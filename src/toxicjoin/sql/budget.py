"""Deterministic preflight budgets for SQL text and parsed AST complexity."""

from __future__ import annotations

import sqlglot
from sqlglot import exp
from sqlglot.errors import ParseError, TokenError

from toxicjoin.models import ReasonCode
from toxicjoin.sql.parser import SqlAnalysisError


MAX_SQL_TEXT_BYTES = 100_000
MAX_SQL_AST_NODES = 2_000
MAX_SQL_AST_DEPTH = 64


def enforce_sql_resource_budget(sql: str, *, dialect: str = "duckdb") -> None:
    """Reject oversized or structurally expensive SQL before semantic analysis.

    Invalid SQL is left to the normal analyzer so existing parse-error semantics remain
    stable. Valid parse trees are bounded across all supplied statements before the
    normal single-statement/read-only checks run.
    """

    encoded_size = len(sql.encode("utf-8"))
    if encoded_size > MAX_SQL_TEXT_BYTES:
        raise SqlAnalysisError(
            ReasonCode.QUERY_COMPLEXITY_LIMIT,
            f"SQL text exceeds {MAX_SQL_TEXT_BYTES} byte budget",
        )

    try:
        statements = [statement for statement in sqlglot.parse(sql, read=dialect) if statement]
    except RecursionError as exc:
        raise SqlAnalysisError(
            ReasonCode.QUERY_COMPLEXITY_LIMIT,
            "SQL parser recursion budget exceeded",
        ) from exc
    except (ParseError, TokenError, ValueError):
        return

    total_nodes = 0
    for root in statements:
        total_nodes = _count_bounded(root, initial_count=total_nodes)


def _count_bounded(root: exp.Expression, *, initial_count: int) -> int:
    total_nodes = initial_count
    stack: list[tuple[exp.Expression, int]] = [(root, 1)]
    while stack:
        node, depth = stack.pop()
        total_nodes += 1
        if total_nodes > MAX_SQL_AST_NODES:
            raise SqlAnalysisError(
                ReasonCode.QUERY_COMPLEXITY_LIMIT,
                f"SQL AST exceeds {MAX_SQL_AST_NODES} node budget",
            )
        if depth > MAX_SQL_AST_DEPTH:
            raise SqlAnalysisError(
                ReasonCode.QUERY_COMPLEXITY_LIMIT,
                f"SQL AST exceeds {MAX_SQL_AST_DEPTH} level depth budget",
            )
        stack.extend((child, depth + 1) for child in node.iter_expressions())
    return total_nodes
