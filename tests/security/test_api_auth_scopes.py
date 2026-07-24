from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from toxicjoin.api import (
    ApiKeyAuthenticator,
    ApiKeyRecord,
    AuthScope,
    create_app,
    hash_api_key,
    load_authenticator_from_env,
)
from toxicjoin.api.models import DEFAULT_SUBJECT_KEY
from toxicjoin.api.scenarios import ALLOW_PUBLIC_AGGREGATE_SQL
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


ALICE_KEY = "alice-test-api-key"
BOB_KEY = "bob-test-api-key"
ADMIN_KEY = "admin-test-api-key"
ANALYZE_ONLY_KEY = "analyze-only-test-api-key"


def _record(
    principal_id: str,
    raw_key: str,
    *scopes: AuthScope,
) -> ApiKeyRecord:
    return ApiKeyRecord(
        principal_id=principal_id,
        key_sha256=hash_api_key(raw_key),
        scopes=scopes,
    )


def _authenticator() -> ApiKeyAuthenticator:
    return ApiKeyAuthenticator(
        (
            _record(
                "alice",
                ALICE_KEY,
                AuthScope.ANALYZE,
                AuthScope.EXECUTE,
                AuthScope.RECEIPTS_READ,
            ),
            _record("bob", BOB_KEY, AuthScope.RECEIPTS_READ),
            _record(
                "admin",
                ADMIN_KEY,
                AuthScope.RECEIPTS_READ,
                AuthScope.RECEIPTS_READ_ANY,
            ),
            _record(
                "analyst",
                ANALYZE_ONLY_KEY,
                AuthScope.ANALYZE,
            ),
        )
    )


def _fixture_pipeline(tmp_path) -> ToxicJoinPipeline:
    database = tmp_path / "demo.duckdb"
    seed_database(database)
    return ToxicJoinPipeline(
        context_resolver=FixtureContextResolver(default_fixture_catalog()),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(database),
    )


def _live_pipeline(tmp_path) -> ToxicJoinPipeline:
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
    return ToxicJoinPipeline(
        context_resolver=DataHubSnapshotContextResolver(snapshot),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(tmp_path / "live-receipts"),
        mode=ReceiptMode.LIVE,
        executor=None,
    )


def _payload() -> dict:
    return {
        "task_purpose": "Count orders by public category",
        "sql": ALLOW_PUBLIC_AGGREGATE_SQL,
        "subject_key": DEFAULT_SUBJECT_KEY.model_dump(mode="json"),
        "dialect": "duckdb",
    }


def _bearer(raw_key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {raw_key}"}


def test_auth_configuration_accepts_hashes_only() -> None:
    raw = json.dumps(
        [
            {
                "principal_id": "alice",
                "key_sha256": hash_api_key(ALICE_KEY),
                "scopes": ["analyze"],
            }
        ]
    )
    authenticator = load_authenticator_from_env({"TOXICJOIN_API_KEYS_JSON": raw})

    assert authenticator is not None
    assert authenticator.authenticate(ALICE_KEY) is not None
    assert authenticator.authenticate("wrong") is None

    plaintext = json.dumps(
        [
            {
                "principal_id": "alice",
                "key": ALICE_KEY,
                "scopes": ["analyze"],
            }
        ]
    )
    with pytest.raises(ValueError, match="configuration is invalid"):
        ApiKeyAuthenticator.from_json(plaintext)


def test_protected_api_rejects_missing_and_invalid_bearer(tmp_path) -> None:
    app = create_app(_fixture_pipeline(tmp_path), authenticator=_authenticator())

    with TestClient(app) as client:
        missing = client.post("/api/analyze", json=_payload())
        invalid = client.post(
            "/api/analyze",
            json=_payload(),
            headers=_bearer("not-a-real-key"),
        )

    assert missing.status_code == 401
    assert missing.json() == {"detail": {"code": "AUTH_REQUIRED"}}
    assert missing.headers["www-authenticate"] == "Bearer"
    assert invalid.status_code == 401
    assert invalid.json() == {"detail": {"code": "AUTH_INVALID"}}


def test_scope_confusion_is_rejected_before_execution(tmp_path) -> None:
    pipeline = _fixture_pipeline(tmp_path)
    app = create_app(pipeline, authenticator=_authenticator())

    with TestClient(app) as client:
        analyze = client.post(
            "/api/analyze",
            json=_payload(),
            headers=_bearer(ANALYZE_ONLY_KEY),
        )
        execute = client.post(
            "/api/execute-safe",
            json=_payload(),
            headers=_bearer(ANALYZE_ONLY_KEY),
        )

    assert analyze.status_code == 200
    assert analyze.json()["receipt"]["principal_id"] == "analyst"
    assert execute.status_code == 403
    assert execute.json() == {
        "detail": {
            "code": "AUTH_SCOPE_DENIED",
            "required_scope": "execute",
        }
    }
    assert len(list(pipeline.receipt_store.root.glob("*.json"))) == 1


def test_receipts_are_principal_owned_with_admin_override(tmp_path) -> None:
    pipeline = _fixture_pipeline(tmp_path)
    app = create_app(pipeline, authenticator=_authenticator())

    with TestClient(app) as client:
        created = client.post(
            "/api/analyze",
            json=_payload(),
            headers=_bearer(ALICE_KEY),
        )
        receipt_id = created.json()["receipt"]["receipt_id"]

        alice = client.get(
            f"/api/receipts/{receipt_id}",
            headers=_bearer(ALICE_KEY),
        )
        bob = client.get(
            f"/api/receipts/{receipt_id}",
            headers=_bearer(BOB_KEY),
        )
        admin = client.get(
            f"/api/receipts/{receipt_id}",
            headers=_bearer(ADMIN_KEY),
        )

    assert created.status_code == 200
    assert created.json()["receipt"]["principal_id"] == "alice"
    assert alice.status_code == 200
    assert alice.json()["principal_id"] == "alice"
    assert bob.status_code == 404
    assert bob.json() == {"detail": {"code": "RECEIPT_NOT_FOUND"}}
    assert admin.status_code == 200
    assert admin.json()["principal_id"] == "alice"


def test_raw_api_key_never_enters_receipt_or_persisted_file(tmp_path) -> None:
    pipeline = _fixture_pipeline(tmp_path)
    app = create_app(pipeline, authenticator=_authenticator())

    with TestClient(app) as client:
        response = client.post(
            "/api/execute-safe",
            json=_payload(),
            headers=_bearer(ALICE_KEY),
        )

    assert response.status_code == 200
    body = response.text
    receipt_id = response.json()["receipt"]["receipt_id"]
    stored = (pipeline.receipt_store.root / f"{receipt_id}.json").read_text(
        encoding="utf-8"
    )
    assert ALICE_KEY not in body
    assert ALICE_KEY not in stored
    assert hash_api_key(ALICE_KEY) not in body
    assert hash_api_key(ALICE_KEY) not in stored


def test_non_fixture_api_fails_closed_without_authenticator(tmp_path) -> None:
    with pytest.raises(
        ValueError,
        match="non-fixture API deployments require API-key authentication",
    ):
        create_app(_live_pipeline(tmp_path))


def test_fixture_judge_remains_available_without_auth_configuration(tmp_path) -> None:
    pipeline = _fixture_pipeline(tmp_path)
    app = create_app(pipeline)

    with TestClient(app) as client:
        response = client.post("/api/analyze", json=_payload())

    assert response.status_code == 200
    assert response.json()["receipt"]["principal_id"] == "fixture-anonymous"
