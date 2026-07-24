"""Authorization-bound, read-only DuckDB execution with bounded previews."""

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

from toxicjoin.execute.authorization import (
    ExecutionAuthorization,
    ExecutionAuthorizationError,
    ExecutionAuthorizer,
)
from toxicjoin.models import ColumnRef, QueryPlan, ReasonCode, StrictModel


class ExecutionError(ValueError):
    """Execution failure with a stable reason code and no sensitive row payload."""

    def __init__(self, reason_code: ReasonCode, detail: str) -> None:
        self.reason_code = reason_code
        self.detail = detail
        super().__init__(f"{reason_code.value}: {detail}")


class ExecutionResult(StrictModel):
    authorization_id: str = Field(pattern=r"^tj_auth_[0-9a-f]{32}$")
    query_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    query_plan: QueryPlan
    columns: tuple[str, ...]
    rows: tuple[tuple[Any, ...], ...]
    preview_row_count: int = Field(ge=0)
    truncated: bool
    elapsed_ms: float = Field(ge=0)


class DuckDBExecutor:
    """Execute only short-lived, independently revalidated capabilities.

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
        self._authorizer: ExecutionAuthorizer | None = None

    @property
    def authorization_bound(self) -> bool:
        return self._authorizer is not None

    def bind_authorizer(self, authorizer: ExecutionAuthorizer) -> None:
        """Bind one execution authority; rebinding to a different authority is forbidden."""

        if self._authorizer is not None and self._authorizer is not authorizer:
            raise ValueError("executor is already bound to a different execution authorizer")
        self._authorizer = authorizer

    def bind_authority(self, *, context_resolver: Any, policy_engine: Any) -> None:
        """Bind verifier authority once and reject later authority substitution."""

        if self._authorizer is None:
            self._authorizer = ExecutionAuthorizer(
                context_resolver=context_resolver,
                policy_engine=policy_engine,
            )
            return
        if (
            self._authorizer.context_resolver is not context_resolver
            or self._authorizer.policy_engine is not policy_engine
        ):
            raise ValueError("executor authority does not match verifier authority")

    def issue_authorization(
        self,
        sql: str,
        *,
        task_purpose: str,
        subject_key: ColumnRef,
        dialect: str = "duckdb",
        rewrite_parent_sql: str | None = None,
    ) -> ExecutionAuthorization:
        """Issue from the same authority that the execution boundary will verify."""

        if self._authorizer is None:
            raise ExecutionError(
                ReasonCode.VERIFICATION_FAILED,
                "executor has no execution authorizer bound",
            )
        try:
            return self._authorizer.issue(
                sql,
                task_purpose=task_purpose,
                subject_key=subject_key,
                dialect=dialect,
                rewrite_parent_sql=rewrite_parent_sql,
            )
        except ExecutionAuthorizationError as exc:
            raise ExecutionError(
                ReasonCode.VERIFICATION_FAILED,
                f"execution authorization issuance rejected: {exc.code}",
            ) from exc

    def execute_authorized(
        self,
        sql: str,
        *,
        authorization: ExecutionAuthorization,
        task_purpose: str,
        subject_key: ColumnRef,
        dialect: str = "duckdb",
        rewrite_parent_sql: str | None = None,
    ) -> ExecutionResult:
        """Consume a matching capability and execute its exact SQL once."""

        if not self.database.is_file():
            raise ExecutionError(
                ReasonCode.VERIFICATION_FAILED,
                f"database file does not exist: {self.database}",
            )
        if self._authorizer is None:
            raise ExecutionError(
                ReasonCode.VERIFICATION_FAILED,
                "executor has no execution authorizer bound",
            )

        try:
            query_plan = self._authorizer.verify_and_consume(
                authorization,
                sql,
                task_purpose=task_purpose,
                subject_key=subject_key,
                dialect=dialect,
                rewrite_parent_sql=rewrite_parent_sql,
            )
        except ExecutionAuthorizationError as exc:
            raise ExecutionError(
                ReasonCode.VERIFICATION_FAILED,
                f"execution authorization rejected: {exc.code}",
            ) from exc

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
                f"DuckDB rejected the authorized query: {exc}",
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
            authorization_id=authorization.authorization_id,
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
