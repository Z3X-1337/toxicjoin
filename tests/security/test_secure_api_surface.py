from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from toxicjoin.api import create_app
from toxicjoin.api.models import DEFAULT_SUBJECT_KEY
from toxicjoin.api.scenarios import FLAGSHIP_REWRITE_SQL
from toxicjoin.auth import ApiKeyAuthenticator, ApiKeyCredentialConfig, AuthScope
from toxicjoin.context import (
    DataHubSnapshot,
    DataHubSnapshotContextResolver,
    FixtureContextResolver,
)
from toxicjoin.demo import default_fixture_catalog, seed_database
from toxicjoin.execute import DuckDBExecutor
from toxicjoin.pipeline import ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import ReceiptMode, ReceiptStore


SYSTEM_KEY = "system-read-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
ANALYZE_KEY = "analyze-only-key-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def _credential(
    credential_id: str,
    api_key: str,
    *scopes: AuthScope,
) -> ApiKeyCredentialConfig:
    return ApiKeyCredentialConfig(
        credential_id=credential_id,
        api_key=api_key,
        principal_id="secure-surface-principal",
        scopes=scopes,
    )


def _authenticator() -> ApiKeyAuthenticator:
    return ApiKeyAuthenticator(
        (
            _credential("system", SYSTEM_KEY, AuthScope.SYSTEM_READ),
            _credential("analyze", ANALYZE_KEY, AuthScope.ANALYZE),
        )
    )


def _headers(api_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {api_key}"}


def _pipeline(
    tmp_path: Path,
    *,
    database_exists: bool = True,
    receipt_store: ReceiptStore | None = None,
) -> ToxicJoinPipeline:
    database = tmp_path / "demo.duckdb"
    if database_exists:
        seed_database(database)
    return ToxicJoinPipeline(
        context_resolver=FixtureContextResolver(default_fixture_catalog()),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=receipt_store or ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(database),
        include_sanitized_sql=False,
    )


def _live_pipeline(tmp_path: Path) -> ToxicJoinPipeline:
    catalog = default_fixture_catalog()
    snapshot = DataHubSnapshot(
        catalog=catalog,
        verified_entities=tuple(dataset.urn for dataset in catalog.datasets.values()),
        field_counts={
            name: len(dataset.fields) for name, dataset in catalog.datasets.items()
        },
        lineage_sample={"relationships": [{"direction": "UPSTREAM"}]},
        discovered_tools=("get_entities", "get_lineage", "list_schema_fields"),
    )
    database = tmp_path / "live.duckdb"
    seed_database(database)
    return ToxicJoinPipeline(
        context_resolver=DataHubSnapshotContextResolver(snapshot),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(tmp_path / "live-receipts"),
        mode=ReceiptMode.LIVE,
        executor=DuckDBExecutor(database),
        include_sanitized_sql=False,
    )


def _payload() -> dict:
    return {
        "task_purpose": "Secure API surface regression",
        "sql": FLAGSHIP_REWRITE_SQL,
        "subject_key": DEFAULT_SUBJECT_KEY.model_dump(mode="json"),
        "dialect": "duckdb",
    }


def test_liveness_is_public_minimal_and_independent_of_readiness(tmp_path) -> None:
    app = create_app(_pipeline(tmp_path, database_exists=False))

    with TestClient(app) as client:
        health = client.get("/api/health")
        ready = client.get("/api/ready")

    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
    assert ready.status_code == 503
    assert ready.json()["status"] == "degraded"
    assert ready.json()["database_ready"] is False
    assert "version" not in health.json()
    assert "mode" not in health.json()
    assert "policy_version" not in health.json()


def test_authenticated_surface_removes_docs_demo_and_benchmark(tmp_path) -> None:
    app = create_app(_pipeline(tmp_path), authenticator=_authenticator())

    with TestClient(app) as client:
        health = client.get("/api/health")
        responses = {
            path: client.get(path)
            for path in (
                "/docs",
                "/redoc",
                "/openapi.json",
                "/api/demo/scenarios",
                "/api/benchmark/summary",
            )
        }

    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
    assert all(response.status_code == 404 for response in responses.values())


def test_live_surface_is_always_restricted(tmp_path) -> None:
    app = create_app(_live_pipeline(tmp_path), authenticator=_authenticator())

    with TestClient(app) as client:
        health = client.get("/api/health")
        ready = client.get("/api/ready", headers=_headers(SYSTEM_KEY))
        docs = client.get("/docs")
        openapi = client.get("/openapi.json")
        demo = client.get("/api/demo/scenarios")
        benchmark = client.get("/api/benchmark/summary")

    assert health.status_code == 200
    assert health.json() == {"status": "ok"}
    assert ready.status_code == 200
    assert ready.json()["mode"] == "live"
    assert docs.status_code == 404
    assert openapi.status_code == 404
    assert demo.status_code == 404
    assert benchmark.status_code == 404


def test_readiness_requires_explicit_system_scope_when_auth_enabled(tmp_path) -> None:
    app = create_app(_pipeline(tmp_path), authenticator=_authenticator())

    with TestClient(app) as client:
        missing = client.get("/api/ready")
        wrong_scope = client.get("/api/ready", headers=_headers(ANALYZE_KEY))
        allowed = client.get("/api/ready", headers=_headers(SYSTEM_KEY))

    assert missing.status_code == 401
    assert missing.json() == {"detail": {"code": "AUTH_MISSING_BEARER"}}
    assert wrong_scope.status_code == 403
    assert wrong_scope.json() == {
        "detail": {
            "code": "AUTH_INSUFFICIENT_SCOPE",
            "required_scope": "system:read",
        }
    }
    assert allowed.status_code == 200
    assert allowed.json()["status"] == "ok"
    assert allowed.json()["mode"] == "fixture"
    assert allowed.json()["database_ready"] is True


def test_fixture_judge_keeps_docs_demo_and_benchmark_without_auth(tmp_path) -> None:
    app = create_app(_pipeline(tmp_path))

    with TestClient(app) as client:
        docs = client.get("/docs")
        openapi = client.get("/openapi.json")
        demo = client.get("/api/demo/scenarios")
        benchmark = client.get("/api/benchmark/summary")

    assert docs.status_code == 200
    assert openapi.status_code == 200
    assert demo.status_code == 200
    assert benchmark.status_code == 200


def test_restricted_surface_rejects_untrusted_host(tmp_path) -> None:
    app = create_app(_pipeline(tmp_path), authenticator=_authenticator())

    with TestClient(app) as client:
        accepted = client.get("/api/health")
        rejected = client.get("/api/health", headers={"Host": "evil.example"})

    assert accepted.status_code == 200
    assert rejected.status_code == 400
    assert "evil.example" not in rejected.text


def test_allowed_hosts_are_strict_and_https_emits_hsts(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("TOXICJOIN_ALLOWED_HOSTS", "secure.example")
    app = create_app(_pipeline(tmp_path), authenticator=_authenticator())

    with TestClient(app, base_url="https://secure.example") as client:
        response = client.get("/api/health")

    assert response.status_code == 200
    assert response.headers["strict-transport-security"] == (
        "max-age=31536000; includeSubDomains"
    )

    monkeypatch.setenv("TOXICJOIN_ALLOWED_HOSTS", "*")
    with pytest.raises(ValueError, match="cannot contain wildcard"):
        create_app(_pipeline(tmp_path / "wildcard"), authenticator=_authenticator())


@pytest.mark.parametrize(
    "configured_hosts",
    (
        "",
        "https://secure.example",
        "secure.example/path",
        "secure example",
        ",".join(f"host-{index}.example" for index in range(33)),
    ),
)
def test_allowed_hosts_fail_closed_for_invalid_configuration(
    tmp_path,
    monkeypatch,
    configured_hosts: str,
) -> None:
    monkeypatch.setenv("TOXICJOIN_ALLOWED_HOSTS", configured_hosts)

    with pytest.raises(ValueError):
        create_app(_pipeline(tmp_path), authenticator=_authenticator())


def test_forwarded_proto_header_does_not_create_https_trust(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("TOXICJOIN_ALLOWED_HOSTS", "secure.example")
    app = create_app(_pipeline(tmp_path), authenticator=_authenticator())

    with TestClient(app, base_url="http://secure.example") as client:
        response = client.get(
            "/api/health",
            headers={"X-Forwarded-Proto": "https"},
        )

    assert response.status_code == 200
    assert "strict-transport-security" not in response.headers


def test_csp_has_no_external_script_or_style_origin(tmp_path) -> None:
    app = create_app(_pipeline(tmp_path))

    with TestClient(app) as client:
        response = client.get("/api/health")

    csp = response.headers["content-security-policy"]
    assert "script-src 'self'" in csp
    assert "style-src 'self' 'unsafe-inline'" in csp
    assert "http://" not in csp
    assert "https://" not in csp
    assert "cdn.jsdelivr" not in csp


class FailingReceiptStore(ReceiptStore):
    def write(self, receipt):
        raise RuntimeError("INTERNAL_SECRET_EXCEPTION_MARKER")


def test_pipeline_failure_returns_stable_code_without_exception_type_or_message(
    tmp_path,
) -> None:
    store = FailingReceiptStore(tmp_path / "receipts")
    app = create_app(_pipeline(tmp_path, receipt_store=store))
    with TestClient(app) as client:
        response = client.post("/api/analyze", json=_payload())

    assert response.status_code == 503
    assert response.json() == {
        "detail": {"code": "PIPELINE_PERSISTENCE_FAILURE"}
    }
    assert "RuntimeError" not in response.text
    assert "error_type" not in response.text
    assert "INTERNAL_SECRET_EXCEPTION_MARKER" not in response.text


def test_restricted_service_root_does_not_disclose_version_or_docs(tmp_path) -> None:
    app = create_app(_pipeline(tmp_path), authenticator=_authenticator())

    with TestClient(app) as client:
        response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {"name": "ToxicJoin"}
    assert "version" not in response.text
    assert "/docs" not in response.text


def test_restricted_surface_never_serves_explicit_judge_distribution(tmp_path) -> None:
    marker = "RESTRICTED_JUDGE_ASSET_MUST_NOT_ESCAPE"
    web_dist = tmp_path / "web-dist"
    assets = web_dist / "assets"
    assets.mkdir(parents=True)
    (web_dist / "index.html").write_text(
        f"<html><body>{marker}</body></html>",
        encoding="utf-8",
    )
    (assets / "probe.js").write_text(marker, encoding="utf-8")

    app = create_app(
        _pipeline(tmp_path / "runtime"),
        web_dist=web_dist,
        authenticator=_authenticator(),
    )

    with TestClient(app) as client:
        root = client.get("/")
        asset = client.get("/assets/probe.js")

    assert root.status_code == 200
    assert root.json() == {"name": "ToxicJoin"}
    assert marker not in root.text
    assert asset.status_code == 404
    assert marker not in asset.text
