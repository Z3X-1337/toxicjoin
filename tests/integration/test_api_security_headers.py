from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from toxicjoin.api import create_app
from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog, seed_database
from toxicjoin.execute import DuckDBExecutor
from toxicjoin.pipeline import ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import ReceiptMode, ReceiptStore


def test_api_responses_use_security_and_no_cache_headers(tmp_path: Path) -> None:
    database = tmp_path / "demo.duckdb"
    seed_database(database)
    pipeline = ToxicJoinPipeline(
        context_resolver=FixtureContextResolver(default_fixture_catalog()),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(database),
    )
    app = create_app(pipeline)

    with TestClient(app) as client:
        response = client.get("/api/health")

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, max-age=0"
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["permissions-policy"] == (
        "camera=(), microphone=(), geolocation=()"
    )
