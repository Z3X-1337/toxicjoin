"""Read-only SQL analysis for ToxicJoin."""

from toxicjoin.sql.parser import SqlAnalysisError, analyze_sql

__all__ = ["SqlAnalysisError", "analyze_sql"]
