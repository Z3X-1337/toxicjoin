"""Read-only, policy-gated query execution."""

from toxicjoin.execute.duckdb_executor import (
    DuckDBExecutor,
    ExecutionError,
    ExecutionResult,
)

__all__ = ["DuckDBExecutor", "ExecutionError", "ExecutionResult"]
