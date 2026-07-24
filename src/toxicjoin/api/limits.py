"""HTTP resource budgets and per-principal traffic controls."""

from __future__ import annotations

import math
import os
import threading
import time
from collections import deque
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable

from pydantic import Field
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from toxicjoin.models import StrictModel


MAX_REQUEST_BYTES_ENV = "TOXICJOIN_MAX_REQUEST_BYTES"
RATE_LIMIT_REQUESTS_ENV = "TOXICJOIN_RATE_LIMIT_REQUESTS"
RATE_LIMIT_WINDOW_SECONDS_ENV = "TOXICJOIN_RATE_LIMIT_WINDOW_SECONDS"
MAX_CONCURRENT_PER_PRINCIPAL_ENV = "TOXICJOIN_MAX_CONCURRENT_PER_PRINCIPAL"


class ApiResourceLimits(StrictModel):
    """Bound API memory/traffic consumption with conservative defaults."""

    max_request_bytes: int = Field(default=128 * 1024, ge=1024, le=1024 * 1024)
    rate_limit_requests: int = Field(default=60, ge=1, le=100_000)
    rate_limit_window_seconds: float = Field(default=60.0, ge=1.0, le=3600.0)
    max_concurrent_per_principal: int = Field(default=2, ge=1, le=64)

    @classmethod
    def from_environment(
        cls,
        environ: Mapping[str, str] | None = None,
    ) -> "ApiResourceLimits":
        source: Mapping[str, str] = os.environ if environ is None else environ
        values: dict[str, Any] = {}
        mapping = {
            MAX_REQUEST_BYTES_ENV: ("max_request_bytes", int),
            RATE_LIMIT_REQUESTS_ENV: ("rate_limit_requests", int),
            RATE_LIMIT_WINDOW_SECONDS_ENV: ("rate_limit_window_seconds", float),
            MAX_CONCURRENT_PER_PRINCIPAL_ENV: ("max_concurrent_per_principal", int),
        }
        for env_name, (field_name, converter) in mapping.items():
            raw = source.get(env_name)
            if raw is None:
                continue
            try:
                values[field_name] = converter(raw)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"{env_name} must be numeric") from exc
        try:
            return cls.model_validate(values)
        except Exception as exc:
            raise ValueError("API resource limit configuration is invalid") from exc


class RequestBodyLimitMiddleware:
    """Buffer at most the configured API request body before framework parsing."""

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope.get("type") != "http"
            or not str(scope.get("path", "")).startswith("/api/")
            or str(scope.get("method", "")).upper() not in {"POST", "PUT", "PATCH"}
        ):
            await self.app(scope, receive, send)
            return

        declared = _content_length(scope)
        if declared is not None and declared > self.max_bytes:
            await _send_request_too_large(scope, receive, send, self.max_bytes)
            return

        buffered: list[Message] = []
        total = 0
        while True:
            message = await receive()
            buffered.append(message)
            if message.get("type") == "http.disconnect":
                break
            if message.get("type") != "http.request":
                continue
            total += len(message.get("body", b""))
            if total > self.max_bytes:
                await _send_request_too_large(scope, receive, send, self.max_bytes)
                return
            if not message.get("more_body", False):
                break

        index = 0

        async def replay_receive() -> Message:
            nonlocal index
            if index < len(buffered):
                message = buffered[index]
                index += 1
                return message
            return {"type": "http.request", "body": b"", "more_body": False}

        await self.app(scope, replay_receive, send)


def _content_length(scope: Scope) -> int | None:
    for key, value in scope.get("headers", ()):  # type: ignore[union-attr]
        if key.lower() != b"content-length":
            continue
        try:
            parsed = int(value.decode("ascii"))
        except (UnicodeDecodeError, ValueError):
            return None
        return parsed if parsed >= 0 else None
    return None


async def _send_request_too_large(
    scope: Scope,
    receive: Receive,
    send: Send,
    max_bytes: int,
) -> None:
    response = JSONResponse(
        status_code=413,
        content={
            "detail": {
                "code": "REQUEST_BODY_TOO_LARGE",
                "max_bytes": max_bytes,
            }
        },
    )
    await response(scope, receive, send)


class TrafficLimitError(RuntimeError):
    def __init__(self, code: str, *, retry_after_seconds: int) -> None:
        self.code = code
        self.retry_after_seconds = max(1, retry_after_seconds)
        super().__init__(code)


@dataclass
class _PrincipalState:
    timestamps: deque[float] = field(default_factory=deque)
    active: int = 0


class PrincipalTrafficLimiter:
    """In-process sliding-window rate and concurrency limiter keyed by principal."""

    def __init__(
        self,
        limits: ApiResourceLimits,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.limits = limits
        self._clock = clock
        self._lock = threading.Lock()
        self._states: dict[str, _PrincipalState] = {}

    @contextmanager
    def acquire(self, principal_id: str) -> Iterator[None]:
        now = float(self._clock())
        with self._lock:
            state = self._states.setdefault(principal_id, _PrincipalState())
            self._prune(state, now)
            if len(state.timestamps) >= self.limits.rate_limit_requests:
                retry_after = math.ceil(
                    self.limits.rate_limit_window_seconds
                    - (now - state.timestamps[0])
                )
                raise TrafficLimitError(
                    "RATE_LIMIT_EXCEEDED",
                    retry_after_seconds=retry_after,
                )

            # Count every authenticated protected-operation attempt, including one
            # rejected for concurrency, so concurrency pressure cannot bypass rate limits.
            state.timestamps.append(now)
            if state.active >= self.limits.max_concurrent_per_principal:
                raise TrafficLimitError(
                    "CONCURRENCY_LIMIT_EXCEEDED",
                    retry_after_seconds=1,
                )
            state.active += 1

        try:
            yield
        finally:
            finished = float(self._clock())
            with self._lock:
                state = self._states.get(principal_id)
                if state is not None:
                    state.active = max(0, state.active - 1)
                    self._prune(state, finished)
                    if state.active == 0 and not state.timestamps:
                        self._states.pop(principal_id, None)

    def _prune(self, state: _PrincipalState, now: float) -> None:
        threshold = now - self.limits.rate_limit_window_seconds
        while state.timestamps and state.timestamps[0] <= threshold:
            state.timestamps.popleft()
