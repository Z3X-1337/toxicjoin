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

from toxicjoin.models import ColumnRef, QueryPlan, ReasonCode
from toxicjoin.sql.parser import (
    SqlAnalysisError,
    _columns_belonging_to,
    _resolve_columns,
    _sorted_refs,
    analyze_sql as _analyze_all_scopes,
)


def analyze_sql(sql: str, *, dialect: str = "duckdb") -> QueryPlan:
    """Return a QueryPlan whose projected columns describe root output only."""

    plan = _analyze_all_scopes(sql, dialect=dialect)
    root = sqlglot.parse_one(sql, read=dialect)
    if not isinstance(root, exp.Select):
        # The low-level analyzer already rejects this, but keep this boundary explicit.
        raise SqlAnalysisError(
            ReasonCode.UNSUPPORTED_STATEMENT,
            f"only SELECT is supported, received {root.key.upper()}",
        )

    root_scope = _find_root_scope(root)
    warnings = set(plan.analysis_warnings)
    root_projected: set[ColumnRef] = set()

    for projection in root.expressions:
        if projection.find(exp.Star):
            warnings.add("SELECT_STAR_REQUIRES_SCHEMA_EXPANSION")
        root_projected.update(
            _resolve_columns(
                _columns_belonging_to(projection, root),
                scope=root_scope,
                warnings=warnings,
            )
        )

    return plan.model_copy(
        update={
            "projected_columns": _sorted_refs(root_projected),
            "analysis_warnings": tuple(sorted(warnings)),
        }
    )


def _find_root_scope(root: exp.Select) -> Scope:
    for scope in traverse_scope(root):
        if scope.expression is root:
            return scope
    raise SqlAnalysisError(
        ReasonCode.UNSUPPORTED_STATEMENT,
        "SQLGlot did not expose a root query scope",
    )
