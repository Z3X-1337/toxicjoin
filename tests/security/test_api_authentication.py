from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from toxicjoin.api import create_app
from toxicjoin.auth import (
    ApiKeyAuthenticator,
    ApiKeyCredentialConfig,
    AuthScope,
    RequestIdentity,
)
from toxicjoin.context import DataHubSnapshot, DataHubSnapshotContextResolver
from toxicjoin.demo import default_fixture_catalog, seed_database
from toxicjoin.execute import DuckDBExecutor
from toxicjoin.models import ColumnRef
from toxicjoin.pipeline import ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import ReceiptMode, ReceiptStore, compute_content_hash


SUBJECT = ColumnRef(dataset="customers", field_path="customer_id", alias="c")
ANALYZE_KEY = "analyze-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
EXECUTE_KEY = "execute-key-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
OTHER_KEY = "other-key-cccccccccccccccccccccccccccccccc"


def _live_resolver() -> DataHubSnapshotContextResolver:
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
    return DataHubSnapshotContextResolver(snapshot)


def _pipeline(tmp_path) -> ToxicJoinPipeline:
    database = tmp_path / "live.duckdb"
    seed_database(database)
    return ToxicJoinPipeline(
        context_resolver=_live_resolver(),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.LIVE,
        executor=DuckDBExecutor(database),
        include_sanitized_sql=False,
    )


def _authenticator() -> ApiKeyAuthenticator:
    return ApiKeyAuthenticator(
        (
            ApiKeyCredentialConfig(
                credential_id="cred-analyze",
                api_key=ANALYZE_KEY,
                principal_id="principal-a",
                agent_id="agent-analysis",
                scopes=(AuthScope.ANALYZE, AuthScope.RECEIPTS_READ),
            ),
            ApiKeyCredentialConfig(
                credential_id="cred-execute",
                api_key=EXECUTE_KEY,
                principal_id="principal-a",
                agent_id="agent-executor",
                scopes=(
                    AuthScope.ANALYZE,
                    AuthScope.EXECUTE,
                    AuthScope.RECEIPTS_READ,
                ),
            ),
            ApiKeyCredentialConfig(
                credential_id="cred-other",
                api_key=OTHER_KEY,
                principal_id="principal-b",
                scopes=(AuthScope.RECEIPTS_READ,),
            ),
        )
    )


def _headers(key: str, *, session: str | None = None) -> dict[str, str]:
    headers = {"Authorization": f"Bearer {key}"}
    if session is not None:
        headers["X-ToxicJoin-Session"] = session
    return headers


def _request(sql: str = "SELECT c.coarse_region FROM customers c LIMIT 5") -> dict:
    return {
        "task_purpose": "List coarse regions",
        "sql": sql,
        "subject_key": SUBJECT.model_dump(mode="json"),
        "dialect": "duckdb",
    }


def test_live_api_refuses_to_start_without_authenticator(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("TOXICJOIN_API_KEYS_JSON", raising=False)

    with pytest.raises(ValueError, match="LIVE API requires configured authentication"):
        create_app(_pipeline(tmp_path))


def test_missing_and_invalid_bearer_are_unauthorized(tmp_path) -> None:
    app = create_app(_pipeline(tmp_path), authenticator=_authenticator())

    with TestClient(app) as client:
        missing = client.post("/api/analyze", json=_request())
        invalid = client.post(
            "/api/analyze",
            json=_request(),
            headers=_headers("invalid-key-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
        )

    assert missing.status_code == 401
    assert missing.json()["detail"]["code"] == "AUTH_MISSING_BEARER"
    assert missing.headers["www-authenticate"] == "Bearer"
    assert invalid.status_code == 401
    assert invalid.json()["detail"]["code"] == "AUTH_INVALID_API_KEY"


def test_scope_is_enforced_before_execution(tmp_path) -> None:
    app = create_app(_pipeline(tmp_path), authenticator=_authenticator())

    with TestClient(app) as client:
        analyze = client.post(
            "/api/analyze",
            json=_request(),
            headers=_headers(ANALYZE_KEY),
        )
        execute = client.post(
            "/api/execute-safe",
            json=_request(),
            headers=_headers(ANALYZE_KEY),
        )

    assert analyze.status_code == 200
    assert execute.status_code == 403
    assert execute.json()["detail"] == {
        "code": "AUTH_INSUFFICIENT_SCOPE",
        "required_scope": "execute",
    }


def test_authenticated_identity_is_hash_bound_to_receipt_without_api_key(tmp_path) -> None:
    app = create_app(_pipeline(tmp_path), authenticator=_authenticator())

    with TestClient(app) as client:
        response = client.post(
            "/api/execute-safe",
            json=_request(),
            headers=_headers(EXECUTE_KEY, session="session-20260724-01"),
        )

    assert response.status_code == 200
    body = response.json()
    receipt = body["receipt"]
    assert receipt["identity"] == {
        "principal_id": "principal-a",
        "credential_id": "cred-execute",
        "agent_id": "agent-executor",
        "session_id": "session-20260724-01",
    }
    assert EXECUTE_KEY not in response.text

    original_hash = receipt["content_sha256"]
    tampered = dict(receipt)
    tampered["identity"] = {
        **receipt["identity"],
        "principal_id": "principal-b",
    }
    assert compute_content_hash(tampered) != original_hash


def test_receipt_read_is_limited_to_owning_principal(tmp_path) -> None:
    app = create_app(_pipeline(tmp_path), authenticator=_authenticator())

    with TestClient(app) as client:
        created = client.post(
            "/api/analyze",
            json=_request(),
            headers=_headers(ANALYZE_KEY),
        )
        assert created.status_code == 200
        receipt_id = created.json()["receipt"]["receipt_id"]

        owner = client.get(
            f"/api/receipts/{receipt_id}",
            headers=_headers(EXECUTE_KEY),
        )
        other = client.get(
            f"/api/receipts/{receipt_id}",
            headers=_headers(OTHER_KEY),
        )

    assert owner.status_code == 200
    assert owner.json()["identity"]["principal_id"] == "principal-a"
    assert other.status_code == 404
    assert other.json()["detail"]["code"] == "RECEIPT_NOT_FOUND"


def test_malformed_session_is_rejected_and_not_persisted(tmp_path) -> None:
    pipeline = _pipeline(tmp_path)
    app = create_app(pipeline, authenticator=_authenticator())

    with TestClient(app) as client:
        response = client.post(
            "/api/analyze",
            json=_request(),
            headers=_headers(ANALYZE_KEY, session="bad session with spaces"),
        )

    assert response.status_code == 401
    assert response.json()["detail"]["code"] == "AUTH_INVALID_SESSION"
    assert not list(pipeline.receipt_store.root.glob("*.json"))


def test_fixture_api_remains_usable_without_bearer_and_is_explicitly_owned(
    tmp_path,
    monkeypatch,
) -> None:
    monkeypatch.delenv("TOXICJOIN_API_KEYS_JSON", raising=False)
    monkeypatch.setenv("TOXICJOIN_RUNTIME_DIR", str(tmp_path / "runtime"))
    app = create_app()

    with TestClient(app) as client:
        response = client.post("/api/analyze", json=_request())

    assert response.status_code == 200
    identity = response.json()["receipt"]["identity"]
    assert identity["principal_id"] == "fixture:anonymous"
    assert identity["credential_id"] == "fixture:anonymous"


def test_api_key_configuration_never_serializes_plaintext_key() -> None:
    credential = ApiKeyCredentialConfig(
        credential_id="cred-safe",
        api_key=ANALYZE_KEY,
        principal_id="principal-safe",
        scopes=(AuthScope.ANALYZE,),
    )

    assert ANALYZE_KEY not in repr(credential)
    assert "api_key" not in credential.model_dump(mode="json")
    authenticator = ApiKeyAuthenticator((credential,))
    assert ANALYZE_KEY not in repr(authenticator.__dict__)


def test_authenticator_environment_configuration_is_strict(monkeypatch) -> None:
    config = [
        {
            "credential_id": "cred-env",
            "api_key": ANALYZE_KEY,
            "principal_id": "principal-env",
            "scopes": ["analyze"],
        }
    ]
    monkeypatch.setenv("TOXICJOIN_API_KEYS_JSON", json.dumps(config))
    authenticator = ApiKeyAuthenticator.from_environment()

    assert authenticator is not None
    authenticated = authenticator.require_scope(ANALYZE_KEY, AuthScope.ANALYZE)
    assert authenticated.identity.principal_id == "principal-env"


def test_request_identity_rejects_untrusted_session_syntax() -> None:
    with pytest.raises(ValidationError):
        RequestIdentity(
            principal_id="principal-a",
            credential_id="cred-a",
            session_id="../bad/session",
        )
