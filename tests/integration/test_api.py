from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from toxicjoin.api import create_app
from toxicjoin.api.models import DEFAULT_SUBJECT_KEY
from toxicjoin.api.scenarios import (
    ALLOW_PUBLIC_AGGREGATE_SQL,
    BLOCKED_EXPORT_SQL,
    FLAGSHIP_REWRITE_SQL,
)
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


def _payload(sql: str, purpose: str) -> dict:
    return {
        "task_purpose": purpose,
        "sql": sql,
        "subject_key": DEFAULT_SUBJECT_KEY.model_dump(mode="json"),
        "dialect": "duckdb",
    }


def test_health_discloses_fixture_mode_and_readiness(tmp_path) -> None:
    app = create_app(_pipeline(tmp_path))

    with TestClient(app) as client:
        response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "version": "0.1.0",
        "mode": "fixture",
        "policy_version": "0.1.0",
        "database_ready": True,
        "receipt_store_ready": True,
    }


def test_demo_scenarios_are_curated_and_labeled(tmp_path) -> None:
    app = create_app(_pipeline(tmp_path))

    with TestClient(app) as client:
        response = client.get("/api/demo/scenarios")

    assert response.status_code == 200
    scenarios = response.json()["scenarios"]
    assert [item["scenario_id"] for item in scenarios] == [
        "rewrite-churn-regions",
        "block-sensitive-export",
        "allow-public-order-counts",
    ]
    assert {item["expected_initial_decision"] for item in scenarios} == {
        "ALLOW",
        "BLOCK",
        "REWRITE",
    }


def test_analyze_returns_rewrite_and_persisted_receipt(tmp_path) -> None:
    pipeline = _pipeline(tmp_path)
    app = create_app(pipeline)

    with TestClient(app) as client:
        response = client.post(
            "/api/analyze",
            json=_payload(
                FLAGSHIP_REWRITE_SQL,
                "Identify regions with elevated churn risk",
            ),
        )

    assert response.status_code == 200
    body = response.json()
    assert body["initial_decision"]["decision"] == "REWRITE"
    assert body["final_decision"]["decision"] == "ALLOW"
    assert body["effective_decision"] == "ALLOW"
    assert "HAVING" in body["safe_sql"].upper()
    assert body["verification"] is None
    receipt_id = body["receipt"]["receipt_id"]
    assert pipeline.receipt_store.read(receipt_id).receipt_id == receipt_id


def test_execute_safe_returns_real_preview_but_receipt_has_no_rows(tmp_path) -> None:
    pipeline = _pipeline(tmp_path)
    app = create_app(pipeline)

    with TestClient(app) as client:
        response = client.post(
            "/api/execute-safe",
            json=_payload(
                FLAGSHIP_REWRITE_SQL,
                "Identify regions with elevated churn risk",
            ),
        )
        body = response.json()
        receipt_response = client.get(
            f"/api/receipts/{body['receipt']['receipt_id']}"
        )

    assert response.status_code == 200
    assert body["effective_decision"] == "ALLOW"
    assert body["verification"]["passed"] is True
    rows = body["verification"]["execution"]["rows"]
    assert len(rows) == 3
    assert {int(row[2]) for row in rows} == {40}
    assert receipt_response.status_code == 200
    receipt_json = receipt_response.text
    assert '"rows"' not in receipt_json
    assert receipt_response.json()["execution"]["preview_row_count"] == 3


def test_blocked_query_never_returns_execution(tmp_path) -> None:
    app = create_app(_pipeline(tmp_path))

    with TestClient(app) as client:
        response = client.post(
            "/api/execute-safe",
            json=_payload(
                BLOCKED_EXPORT_SQL,
                "Export customers with sensitive support cases",
            ),
        )

    assert response.status_code == 200
    body = response.json()
    assert body["effective_decision"] == "BLOCK"
    assert "COMPOSITIONAL_REIDENTIFICATION_RISK" in body["initial_decision"][
        "reason_codes"
    ]
    assert body["verification"] is None
    assert body["receipt"]["execution"] is None


def test_public_count_star_query_is_allowed_and_executed(tmp_path) -> None:
    app = create_app(_pipeline(tmp_path))

    with TestClient(app) as client:
        response = client.post(
            "/api/execute-safe",
            json=_payload(
                ALLOW_PUBLIC_AGGREGATE_SQL,
                "Count orders by public category",
            ),
        )

    assert response.status_code == 200
    body = response.json()
    assert body["initial_decision"]["decision"] == "ALLOW"
    assert body["effective_decision"] == "ALLOW"
    assert body["original_plan"]["contains_wildcard"] is False
    assert len(body["verification"]["execution"]["rows"]) == 4


def test_invalid_request_is_rejected_by_schema(tmp_path) -> None:
    app = create_app(_pipeline(tmp_path))

    with TestClient(app) as client:
        response = client.post(
            "/api/analyze",
            json={
                "task_purpose": "",
                "sql": "",
                "subject_key": {},
                "unexpected": "field",
            },
        )

    assert response.status_code == 422


def test_missing_receipt_returns_stable_404(tmp_path) -> None:
    app = create_app(_pipeline(tmp_path))

    with TestClient(app) as client:
        response = client.get("/api/receipts/tj_0123456789abcdef")

    assert response.status_code == 404
    assert response.json() == {"detail": {"code": "RECEIPT_NOT_FOUND"}}


def test_tampered_receipt_returns_integrity_failure_without_details(tmp_path) -> None:
    pipeline = _pipeline(tmp_path)
    app = create_app(pipeline)

    with TestClient(app) as client:
        created = client.post(
            "/api/analyze",
            json=_payload(
                FLAGSHIP_REWRITE_SQL,
                "Identify regions with elevated churn risk",
            ),
        ).json()
        receipt_id = created["receipt"]["receipt_id"]
        path = pipeline.receipt_store.root / f"{receipt_id}.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload["task_purpose"] = "tampered"
        path.write_text(json.dumps(payload), encoding="utf-8")
        response = client.get(f"/api/receipts/{receipt_id}")

    assert response.status_code == 409
    assert response.json() == {
        "detail": {"code": "RECEIPT_INTEGRITY_FAILURE"}
    }
    assert "hash" not in response.text.lower()


def test_default_app_seeds_runtime_without_import_side_effects(
    tmp_path,
    monkeypatch,
) -> None:
    runtime = tmp_path / "runtime"
    monkeypatch.setenv("TOXICJOIN_RUNTIME_DIR", str(runtime))
    app = create_app()
    assert not runtime.exists()

    with TestClient(app) as client:
        response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert (runtime / "demo.duckdb").is_file()
