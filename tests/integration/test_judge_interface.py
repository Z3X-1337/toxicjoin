from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from toxicjoin.api import create_app
from toxicjoin.benchmark.evidence import BENCHMARK_EVIDENCE
from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog, seed_database
from toxicjoin.execute import DuckDBExecutor
from toxicjoin.pipeline import ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import ReceiptMode, ReceiptStore


def _pipeline(tmp_path: Path) -> ToxicJoinPipeline:
    database = tmp_path / "demo.duckdb"
    seed_database(database)
    return ToxicJoinPipeline(
        context_resolver=FixtureContextResolver(default_fixture_catalog()),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(database),
    )


def _web_dist(tmp_path: Path) -> Path:
    dist = tmp_path / "dist"
    assets = dist / "assets"
    assets.mkdir(parents=True)
    (dist / "index.html").write_text(
        "<!doctype html><html><body><div id='root'>ToxicJoin Judge UI</div></body></html>",
        encoding="utf-8",
    )
    (assets / "app-123.js").write_text(
        "console.log('toxicjoin');",
        encoding="utf-8",
    )
    return dist


def test_benchmark_summary_endpoint_serves_measured_evidence(tmp_path: Path) -> None:
    app = create_app(_pipeline(tmp_path))

    with TestClient(app) as client:
        response = client.get("/api/benchmark/summary")

    assert response.status_code == 200
    assert response.json() == BENCHMARK_EVIDENCE.model_dump(mode="json")
    assert response.headers["cache-control"] == "no-store, max-age=0"
    assert response.headers["pragma"] == "no-cache"


def test_prebuilt_judge_interface_and_assets_use_safe_cache_policies(
    tmp_path: Path,
) -> None:
    app = create_app(
        _pipeline(tmp_path),
        web_dist=_web_dist(tmp_path),
    )

    with TestClient(app) as client:
        root = client.get("/")
        asset = client.get("/assets/app-123.js")
        nested = client.get("/judge/rewrite-churn-regions")

    assert root.status_code == 200
    assert "ToxicJoin Judge UI" in root.text
    assert root.headers["cache-control"] == "no-cache, max-age=0"
    assert "frame-ancestors 'none'" in root.headers["content-security-policy"]
    assert root.headers["cross-origin-opener-policy"] == "same-origin"
    assert root.headers["cross-origin-resource-policy"] == "same-origin"

    assert asset.status_code == 200
    assert asset.text == "console.log('toxicjoin');"
    assert asset.headers["cache-control"] == "public, max-age=31536000, immutable"

    assert nested.status_code == 200
    assert "ToxicJoin Judge UI" in nested.text


def test_spa_fallback_never_masks_api_or_missing_asset_errors(tmp_path: Path) -> None:
    app = create_app(
        _pipeline(tmp_path),
        web_dist=_web_dist(tmp_path),
    )

    with TestClient(app) as client:
        unknown_api = client.get("/api/not-a-real-endpoint")
        missing_asset = client.get("/missing.js")

    assert unknown_api.status_code == 404
    assert unknown_api.headers["content-type"].startswith("application/json")
    assert "ToxicJoin Judge UI" not in unknown_api.text
    assert missing_asset.status_code == 404
    assert missing_asset.json() == {"detail": {"code": "ASSET_NOT_FOUND"}}


def test_service_root_discloses_when_frontend_is_not_built(tmp_path: Path) -> None:
    app = create_app(_pipeline(tmp_path), web_dist=tmp_path / "missing")

    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {
        "name": "ToxicJoin",
        "version": "0.1.0",
        "judge_interface": "not_built",
        "api_docs": "/docs",
    }
    assert response.headers["cache-control"] == "no-cache, max-age=0"
