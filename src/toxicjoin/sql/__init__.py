"""Read-only SQL analysis for ToxicJoin."""

from toxicjoin.sql.analyzer import analyze_sql as _analyze_sql
from toxicjoin.sql.budget import enforce_sql_resource_budget
from toxicjoin.sql.parser import SqlAnalysisError


def analyze_sql(sql: str, *, dialect: str = "duckdb"):
    """Apply deterministic resource budgets before semantic SQL analysis."""

    enforce_sql_resource_budget(sql, dialect=dialect)
    return _analyze_sql(sql, dialect=dialect)


__all__ = ["SqlAnalysisError", "analyze_sql"]
