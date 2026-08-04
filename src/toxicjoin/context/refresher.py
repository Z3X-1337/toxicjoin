"""Keep a live DataHub snapshot fresh for a long-running server.

`DataHubSnapshotContextResolver` binds every decision to a snapshot that expires after a
bounded age, and `DataHubSnapshotLoader` can fetch a new one — but nothing connected the two.
A server started against live DataHub therefore worked until the first snapshot aged out and
then refused every request with `DATAHUB_CONTEXT_STALE`. Correct, and useless.

This refresher closes that gap with one rule that matters more than the scheduling:

    **A failed refresh never replaces the snapshot.**

Installing a partial or degraded snapshot would convert an outage into silent governance
drift — the pipeline would keep answering, from metadata that no longer reflects DataHub.
Instead the existing snapshot is left to expire on its own schedule and the request path fails
closed, which is the behaviour the whole product is built on.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone

from toxicjoin.context.datahub import DataHubSnapshot, DataHubSnapshotContextResolver
from toxicjoin.models import StrictModel


logger = logging.getLogger(__name__)

SnapshotLoader = Callable[[], Awaitable[DataHubSnapshot]]

_DEFAULT_REFRESH_RATIO = 0.5
_MIN_REFRESH_INTERVAL_SECONDS = 5.0
_DEFAULT_RETRY_BACKOFF_SECONDS = 10.0
_MAX_RETRY_BACKOFF_SECONDS = 120.0


class RefresherHealth(StrictModel):
    """Operational state of the background refresh loop, for readiness reporting."""

    running: bool
    snapshot_fresh: bool
    consecutive_failures: int
    last_success_at: datetime | None = None
    last_failure_reason: str | None = None


class DataHubSnapshotRefresher:
    """Refresh a resolver's snapshot on a daemon thread, well before it expires.

    The loader is injected rather than constructed here so the refresh policy can be tested
    without an MCP server, and so the caller keeps ownership of credential handling.
    """

    def __init__(
        self,
        *,
        resolver: DataHubSnapshotContextResolver,
        loader: SnapshotLoader,
        refresh_ratio: float = _DEFAULT_REFRESH_RATIO,
        retry_backoff_seconds: float = _DEFAULT_RETRY_BACKOFF_SECONDS,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if not 0 < refresh_ratio < 1:
            raise ValueError("refresh_ratio must be in (0, 1)")
        if retry_backoff_seconds <= 0:
            raise ValueError("retry_backoff_seconds must be positive")

        self._resolver = resolver
        self._loader = loader
        self._retry_backoff_seconds = float(retry_backoff_seconds)
        # Refresh at a fraction of the freshness window so a single failed attempt still
        # leaves time for a retry before the current snapshot expires.
        self._interval_seconds = max(
            _MIN_REFRESH_INTERVAL_SECONDS,
            resolver.max_age_seconds * refresh_ratio,
        )
        self._clock = clock or (lambda: datetime.now(timezone.utc))

        self._state_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._consecutive_failures = 0
        self._last_success_at: datetime | None = None
        self._last_failure_reason: str | None = None

    @property
    def interval_seconds(self) -> float:
        return self._interval_seconds

    def refresh_now(self) -> DataHubSnapshot:
        """Fetch and install one snapshot synchronously. Raises on failure.

        Used at startup, where failing fast is right: a server that cannot reach DataHub must
        not come up claiming live governance.
        """

        snapshot = asyncio.run(self._loader())
        self._install(snapshot)
        return snapshot

    def start(self) -> None:
        with self._state_lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run,
                name="toxicjoin-datahub-refresher",
                daemon=True,
            )
            self._thread.start()

    def stop(self, *, timeout: float = 5.0) -> None:
        self._stop_event.set()
        with self._state_lock:
            thread = self._thread
            self._thread = None
        if thread is not None:
            thread.join(timeout=timeout)

    def health(self) -> RefresherHealth:
        with self._state_lock:
            thread = self._thread
            return RefresherHealth(
                running=thread is not None and thread.is_alive(),
                snapshot_fresh=self._resolver.is_fresh(),
                consecutive_failures=self._consecutive_failures,
                last_success_at=self._last_success_at,
                last_failure_reason=self._last_failure_reason,
            )

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        try:
            asyncio.set_event_loop(loop)
            while not self._stop_event.wait(self._next_delay()):
                self._refresh_once(loop)
        finally:
            try:
                loop.close()
            finally:
                asyncio.set_event_loop(None)

    def _next_delay(self) -> float:
        with self._state_lock:
            failures = self._consecutive_failures
        if failures == 0:
            return self._interval_seconds
        # Back off after failures, but never past the point where the snapshot would have
        # expired unnoticed: a stale snapshot must be retried, not abandoned.
        backoff = self._retry_backoff_seconds * (2 ** min(failures - 1, 4))
        return min(backoff, _MAX_RETRY_BACKOFF_SECONDS, self._interval_seconds)

    def _refresh_once(self, loop: asyncio.AbstractEventLoop) -> None:
        try:
            snapshot = loop.run_until_complete(self._loader())
        except Exception as exc:
            with self._state_lock:
                self._consecutive_failures += 1
                self._last_failure_reason = type(exc).__name__
                failures = self._consecutive_failures
            # The snapshot is deliberately left untouched. Requests keep using the last
            # verified governance until it expires, then fail closed.
            logger.warning(
                "DataHub snapshot refresh failed (%s consecutive); keeping the previous "
                "snapshot until it expires: %s",
                failures,
                type(exc).__name__,
            )
            return
        self._install(snapshot)

    def _install(self, snapshot: DataHubSnapshot) -> None:
        self._resolver.replace_snapshot(snapshot)
        with self._state_lock:
            self._consecutive_failures = 0
            self._last_failure_reason = None
            self._last_success_at = self._clock()

    def __enter__(self) -> "DataHubSnapshotRefresher":
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()
