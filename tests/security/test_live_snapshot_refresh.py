"""The live governance path must stay fresh, and must fail closed rather than drift.

A long-running server bound to live DataHub previously worked until its first snapshot aged
out and then refused every request. Adding a refresher fixes that, but introduces a sharper
risk: a refresher that installs a degraded snapshot converts an outage into silent governance
drift, where the pipeline keeps answering from metadata that no longer reflects DataHub.

These tests pin the safe half of that trade as hard as the useful half.
"""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone

import pytest

from toxicjoin.context.datahub import DataHubSnapshot, DataHubSnapshotContextResolver
from toxicjoin.context.fixture import FixtureCatalog
from toxicjoin.context.governance import GovernanceContextStaleError
from toxicjoin.context.refresher import DataHubSnapshotRefresher
from toxicjoin.demo import default_fixture_catalog
from toxicjoin.models import QueryPlan


def _snapshot(*, version: str, observed_at: datetime) -> DataHubSnapshot:
    catalog = default_fixture_catalog()
    return DataHubSnapshot(
        catalog=FixtureCatalog(version=version, datasets=catalog.datasets),
        verified_entities=tuple(d.urn for d in catalog.datasets.values()),
        field_counts={name: len(d.fields) for name, d in catalog.datasets.items()},
        lineage_sample={"relationships": [{"direction": "UPSTREAM"}]},
        discovered_tools=("get_entities", "get_lineage", "list_schema_fields"),
        observed_at=observed_at,
    )


def _plan() -> QueryPlan:
    return QueryPlan(
        statement_type="SELECT",
        source_datasets=("orders",),
        projected_columns=(),
    )


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc)


def test_refresh_installs_a_newer_snapshot(now: datetime) -> None:
    resolver = DataHubSnapshotContextResolver(
        _snapshot(version="v1", observed_at=now),
        max_age_seconds=300.0,
        clock=lambda: now,
    )
    replacement = _snapshot(version="v2", observed_at=now)

    async def loader() -> DataHubSnapshot:
        return replacement

    refresher = DataHubSnapshotRefresher(resolver=resolver, loader=loader)
    refresher.refresh_now()

    assert resolver.snapshot.catalog.version == "v2"
    assert refresher.health().consecutive_failures == 0


def test_failed_refresh_never_replaces_the_snapshot(now: datetime) -> None:
    """The invariant the whole design rests on: an outage must not become drift."""

    original = _snapshot(version="trusted", observed_at=now)
    resolver = DataHubSnapshotContextResolver(
        original,
        max_age_seconds=300.0,
        clock=lambda: now,
    )

    async def failing_loader() -> DataHubSnapshot:
        raise RuntimeError("DataHub unreachable")

    refresher = DataHubSnapshotRefresher(resolver=resolver, loader=failing_loader)
    with pytest.raises(RuntimeError):
        refresher.refresh_now()

    assert resolver.snapshot.catalog.version == "trusted"
    assert resolver.snapshot is original


def test_snapshot_still_expires_while_refresh_keeps_failing(now: datetime) -> None:
    """Keeping the old snapshot is not the same as trusting it forever."""

    clock = {"value": now}
    resolver = DataHubSnapshotContextResolver(
        _snapshot(version="trusted", observed_at=now),
        max_age_seconds=60.0,
        clock=lambda: clock["value"],
    )

    assert resolver.is_fresh() is True
    clock["value"] = now + timedelta(seconds=61)

    assert resolver.is_fresh() is False
    with pytest.raises(GovernanceContextStaleError):
        resolver.resolve(_plan())


def test_background_loop_refreshes_and_recovers_from_failure(now: datetime) -> None:
    resolver = DataHubSnapshotContextResolver(
        _snapshot(version="v0", observed_at=now),
        max_age_seconds=300.0,
        clock=lambda: now,
    )
    attempts = {"count": 0}
    completed = threading.Event()

    async def flaky_loader() -> DataHubSnapshot:
        attempts["count"] += 1
        if attempts["count"] == 1:
            raise RuntimeError("transient outage")
        completed.set()
        return _snapshot(version="recovered", observed_at=now)

    refresher = DataHubSnapshotRefresher(
        resolver=resolver,
        loader=flaky_loader,
        refresh_ratio=0.01,
        retry_backoff_seconds=0.01,
    )
    with refresher:
        assert completed.wait(timeout=10.0), "refresher never recovered"

    assert resolver.snapshot.catalog.version == "recovered"
    assert refresher.health().consecutive_failures == 0


def test_health_reports_failures_without_hiding_them(now: datetime) -> None:
    resolver = DataHubSnapshotContextResolver(
        _snapshot(version="v0", observed_at=now),
        max_age_seconds=300.0,
        clock=lambda: now,
    )

    async def failing_loader() -> DataHubSnapshot:
        raise ConnectionError("gms down")

    refresher = DataHubSnapshotRefresher(resolver=resolver, loader=failing_loader)
    with pytest.raises(ConnectionError):
        refresher.refresh_now()

    health = refresher.health()
    assert health.last_success_at is None
    assert health.snapshot_fresh is True


def test_refresh_interval_stays_inside_the_freshness_window() -> None:
    """A refresh scheduled after expiry would guarantee a stale gap every cycle."""

    resolver = DataHubSnapshotContextResolver(
        _snapshot(version="v0", observed_at=datetime.now(timezone.utc)),
        max_age_seconds=300.0,
    )

    async def loader() -> DataHubSnapshot:  # pragma: no cover - never awaited here
        raise AssertionError

    refresher = DataHubSnapshotRefresher(resolver=resolver, loader=loader)

    assert refresher.interval_seconds < resolver.max_age_seconds


def test_stopping_the_refresher_joins_its_thread(now: datetime) -> None:
    resolver = DataHubSnapshotContextResolver(
        _snapshot(version="v0", observed_at=now),
        max_age_seconds=300.0,
        clock=lambda: now,
    )

    async def loader() -> DataHubSnapshot:
        return _snapshot(version="v0", observed_at=now)

    refresher = DataHubSnapshotRefresher(
        resolver=resolver,
        loader=loader,
        refresh_ratio=0.01,
    )
    refresher.start()
    assert refresher.health().running is True
    refresher.stop()

    assert refresher.health().running is False


@pytest.mark.parametrize("ratio", (0.0, 1.0, 1.5, -0.2))
def test_invalid_refresh_ratio_is_rejected(ratio: float, now: datetime) -> None:
    resolver = DataHubSnapshotContextResolver(
        _snapshot(version="v0", observed_at=now),
        max_age_seconds=300.0,
        clock=lambda: now,
    )

    async def loader() -> DataHubSnapshot:  # pragma: no cover - never awaited
        raise AssertionError

    with pytest.raises(ValueError):
        DataHubSnapshotRefresher(resolver=resolver, loader=loader, refresh_ratio=ratio)
