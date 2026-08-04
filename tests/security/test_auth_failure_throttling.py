"""Credential probing must consume a budget.

The per-principal traffic limiter keys on an authenticated identity, so before this control
existed every rejected credential was unmetered: an attacker could try keys as fast as the
network allowed while legitimate traffic stayed rate limited.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from toxicjoin.api import create_app
from toxicjoin.api.limits import ApiResourceLimits, AuthFailureLimiter, TrafficLimitError
from toxicjoin.auth import ApiKeyAuthenticator, ApiKeyCredentialConfig, AuthScope
from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog
from toxicjoin.disclosure import DisclosureLedger
from toxicjoin.execute import DuckDBExecutor
from toxicjoin.pipeline import ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import ReceiptMode, ReceiptStore


VALID_KEY = "v" * 48


def _authenticator() -> ApiKeyAuthenticator:
    return ApiKeyAuthenticator(
        (
            ApiKeyCredentialConfig(
                credential_id="cred-1",
                api_key=VALID_KEY,
                principal_id="analyst-1",
                scopes=(AuthScope.SYSTEM_READ, AuthScope.ANALYZE),
            ),
        )
    )


@pytest.fixture
def client(seeded_database: Path, tmp_path: Path) -> TestClient:
    pipeline = ToxicJoinPipeline(
        context_resolver=FixtureContextResolver(default_fixture_catalog()),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(seeded_database),
        disclosure_ledger=DisclosureLedger(tmp_path / "disclosures.sqlite3"),
        stateful_privacy_required=True,
    )
    app = create_app(
        pipeline,
        authenticator=_authenticator(),
        resource_limits=ApiResourceLimits(auth_failure_limit=3, auth_failure_window_seconds=60.0),
    )
    return TestClient(app)


def test_repeated_invalid_credentials_are_throttled(client: TestClient) -> None:
    statuses = [
        client.get("/api/ready", headers={"Authorization": "Bearer wrong-key-value"}).status_code
        for _ in range(5)
    ]

    assert statuses[:3] == [401, 401, 401]
    assert statuses[3:] == [429, 429]


def test_throttled_response_advertises_retry_after(client: TestClient) -> None:
    for _ in range(3):
        client.get("/api/ready", headers={"Authorization": "Bearer wrong-key-value"})

    response = client.get("/api/ready", headers={"Authorization": "Bearer wrong-key-value"})

    assert response.status_code == 429
    assert response.json()["detail"]["code"] == "AUTH_FAILURE_LIMIT_EXCEEDED"
    assert int(response.headers["Retry-After"]) >= 1


def test_missing_bearer_header_also_consumes_budget(client: TestClient) -> None:
    for _ in range(3):
        assert client.get("/api/ready").status_code == 401

    assert client.get("/api/ready").status_code == 429


def test_valid_credentials_never_consume_the_failure_budget(client: TestClient) -> None:
    """A shared egress address must not be able to throttle its own legitimate traffic."""

    headers = {"Authorization": f"Bearer {VALID_KEY}"}
    for _ in range(10):
        assert client.get("/api/ready", headers=headers).status_code == 200


def test_successful_auth_after_failures_still_works_within_budget(client: TestClient) -> None:
    client.get("/api/ready", headers={"Authorization": "Bearer wrong-key-value"})

    response = client.get("/api/ready", headers={"Authorization": f"Bearer {VALID_KEY}"})

    assert response.status_code == 200


def test_failure_window_expires(monkeypatch: pytest.MonkeyPatch) -> None:
    now = [1000.0]
    limiter = AuthFailureLimiter(
        max_failures=2,
        window_seconds=60.0,
        clock=lambda: now[0],
    )

    limiter.record_failure("peer")
    limiter.record_failure("peer")
    with pytest.raises(TrafficLimitError):
        limiter.check("peer")

    now[0] += 61.0
    limiter.check("peer")


def test_tracked_key_table_is_bounded() -> None:
    """A spoofed-address flood must not grow the failure table without limit."""

    limiter = AuthFailureLimiter(
        max_failures=5,
        window_seconds=600.0,
        max_tracked_keys=16,
    )

    for index in range(200):
        limiter.record_failure(f"peer-{index}")

    assert len(limiter._failures) <= 16
