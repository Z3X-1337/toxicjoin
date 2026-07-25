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
from toxicjoin.execute.limits import ExecutionOutputLimits
from toxicjoin.execute.proof_bound_authorization import ProofBoundExecutionAuthorization
from toxicjoin.execute.proof_bound_strict import ProofBoundExecutionAuthorizer

__all__ = [
    "DuckDBExecutor",
    "ExecutionAuthorization",
    "ExecutionAuthorizationError",
    "ExecutionAuthorizer",
    "ExecutionError",
    "ExecutionOutputLimits",
    "ExecutionResult",
    "ProofBoundExecutionAuthorization",
    "ProofBoundExecutionAuthorizer",
]
