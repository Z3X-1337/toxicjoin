"""Policy-gated, read-only DuckDB execution with bounded previews."""

from __future__ import annotations

import hashlib
import threading
import time
from datetime import date, datetime, time as time_value
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import UUID

import duckdb
from pydantic import Field

from toxicjoin.models import Decision, PolicyDecision, QueryPlan, ReasonCode, StrictModel
from toxicjoin.sql import SqlAnalysisError, analyze_sql


class ExecutionError(ValueError):
    """Execution failure with a stable reason code and no sensitive row payload."""

    def __init__(self, reason_code: ReasonCode, detail: str) -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{reason_code.value}: {detail}")


class ExecutionResult(StrictModel):
    query_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    query_plan: QueryPlan
    columns: tuple[str, ...]
    rows: tuple[tuple[Any, ...], ...]
    preview_row_count: int = Field(ge=0)
    truncated: bool
    elapsed_ms: float = Field(ge=0)


class DuckDBExecutor:
    """Execute only policy-approved SELECT statements against a database file.

    The connection is opened read-only. External access, extension auto-loading,
    and community extensions are disabled before the configuration is locked.
    """

    def __init__(
        self,
        database: str | Path,
        *,
        max_preview_rows: int = 50,
        timeout_seconds: float = 5.0,
    ) -> None:
        self.database = Path(database)
        if max_preview_rows < 1:
            raise ValueError("max_preview_rows must be at least 1")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.max_preview_rows = max_preview_rows
        self.timeout_seconds = timeout_seconds

    def execute_allowed(
        self,
        sql: str,
        *,
        policy_decision: PolicyDecision,
        dialect: str = "duckdb",
    ) -> ExecutionResult:
        """Execute SQL only when the supplied deterministic decision is ALLOW."""

        if policy_decision.decision != Decision.ALLOW:
            raise ExecutionError(
                ReasonCode.VERIFICATION_FAILED,
                f"execution requires ALLOW, received {policy_decision.decision.value}",
            )
        if policy_decision.rewrite_required:
            raise ExecutionError(
                ReasonCode.VERIFICATION_FAILED,
                "execution cannot proceed while a rewrite remains required",
            )
        if not self.database.is_file():
            raise ExecutionError(
                ReasonCode.VERIFICATION_FAILED,
                f"database file does not exist: {self.database}",
            )

        try:
            query_plan = analyze_sql(sql, dialect=dialect)
        except SqlAnalysisError as exc:
            raise ExecutionError(exc.reason_code, exc.detail) from exc

        if query_plan.contains_wildcard:
            raise ExecutionError(
                ReasonCode.UNRESOLVED_COLUMN,
                "wildcard output must be expanded and governed before execution",
            )

        connection = self._connect()
        timed_out = threading.Event()

        def interrupt_query() -> None:
            timed_out.set()
            try:
                connection.interrupt()
            except Exception:
                # The main thread reports the original execution error. The timer must
                # never mask it with a secondary interrupt failure.
                pass

        timer = threading.Timer(self.timeout_seconds, interrupt_query)
        timer.daemon = True
        started = time.perf_counter()
        timer.start()
        try:
            cursor = connection.execute(sql)
            description = cursor.description or ()
            columns = tuple(str(item[0]) for item in description)
            fetched = cursor.fetchmany(self.max_preview_rows + 1)
        except duckdb.Error as exc:
            if timed_out.is_set():
                raise ExecutionError(
                    ReasonCode.VERIFICATION_FAILED,
                    f"query exceeded {self.timeout_seconds:.3f} seconds",
                ) from exc
            raise ExecutionError(
                ReasonCode.VERIFICATION_FAILED,
                f"DuckDB rejected the approved query: {exc}",
            ) from exc
        finally:
            timer.cancel()
            connection.close()

        elapsed_ms = (time.perf_counter() - started) * 1000
        truncated = len(fetched) > self.max_preview_rows
        preview = fetched[: self.max_preview_rows]
        normalized_rows = tuple(
            tuple(_json_safe(value) for value in row)
            for row in preview
        )

        return ExecutionResult(
            query_sha256=hashlib.sha256(sql.encode("utf-8")).hexdigest(),
            query_plan=query_plan,
            columns=columns,
            rows=normalized_rows,
            preview_row_count=len(normalized_rows),
            truncated=truncated,
            elapsed_ms=elapsed_ms,
        )

    def _connect(self) -> duckdb.DuckDBPyConnection:
        try:
            connection = duckdb.connect(
                str(self.database),
                read_only=True,
                config={
                    "enable_external_access": "false",
                    "allow_community_extensions": "false",
                    "autoload_known_extensions": "false",
                    "autoinstall_known_extensions": "false",
                    "threads": "1",
                },
            )
            connection.execute("SET lock_configuration = true")
            return connection
        except duckdb.Error as exc:
            raise ExecutionError(
                ReasonCode.VERIFICATION_FAILED,
                f"unable to establish hardened read-only DuckDB connection: {exc}",
            ) from exc


def _json_safe(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, (datetime, date, time_value)):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    return str(value)
