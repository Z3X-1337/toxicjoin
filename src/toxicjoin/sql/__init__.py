"""Read-only SQL analysis for ToxicJoin."""

from toxicjoin.sql.analyzer import analyze_sql
from toxicjoin.sql.parser import SqlAnalysisError

__all__ = ["SqlAnalysisError", "analyze_sql"]
