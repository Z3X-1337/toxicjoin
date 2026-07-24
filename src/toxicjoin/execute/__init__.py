"""Read-only, authorization-bound query execution."""

from toxicjoin.execute.authorization import (
    ExecutionAuthorization,
    ExecutionAuthorizationError,
    ExecutionAuthorizer,
)
from toxicjoin.execute.duckdb_executor import (
    DuckDBExecutor,
    ExecutionError,
    ExecutionResult,
)

__all__ = [
    "DuckDBExecutor",
    "ExecutionAuthorization",
    "ExecutionAuthorizationError",
    "ExecutionAuthorizer",
    "ExecutionError",
    "ExecutionResult",
]
