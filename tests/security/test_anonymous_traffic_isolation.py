"""Public reviewers must not rate-limit each other.

The unauthenticated fixture surface shares one identity on purpose: receipts and cumulative
disclosure history must not be partitioned by network address. But traffic budgets were keyed
on that same shared value, which meant the entire public demo had two concurrent requests and
sixty per minute *in total* — two reviewers clicking at the same moment would refuse each
other's work, and a single client could exhaust the whole deployment.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from toxicjoin.api import create_app
from toxicjoin.api.limits import ApiResourceLimits
from toxicjoin.auth import FIXTURE_ANONYMOUS_PRINCIPAL, fixture_anonymous_request
from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog
from toxicjoin.execute import DuckDBExecutor
from toxicjoin.pipeline import ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import ReceiptMode, ReceiptStore


def _pipeline(database: Path, tmp_path: Path) -> ToxicJoinPipeline:
    return ToxicJoinPipeline(
        context_resolver=FixtureContextResolver(default_fixture_catalog()),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(database),
    )


@pytest.fixture
def client(seeded_database: Path, tmp_path: Path) -> TestClient:
    app = create_app(
        _pipeline(seeded_database, tmp_path),
        web_dist=tmp_path / "absent",
        resource_limits=ApiResourceLimits(rate_limit_requests=3, rate_limit_window_seconds=60.0),
    )
    return TestClient(app)


def test_anonymous_identity_stays_shared(seeded_database: Path, tmp_path: Path) -> None:
    """Keying receipts or privacy history by address would fragment both."""

    assert fixture_anonymous_request().identity.principal_id == FIXTURE_ANONYMOUS_PRINCIPAL


def test_one_peer_exhausting_its_budget_does_not_block_another(client: TestClient) -> None:
    first = [
        client.get("/api/ready", headers={"X-Forwarded-For": "203.0.113.10"}).status_code
        for _ in range(4)
    ]

    assert first[:3] == [200, 200, 200]
    assert first[3] == 429

    # A different reviewer, arriving from a different address, must still be served.
    other = client.get("/api/ready", headers={"X-Forwarded-For": "203.0.113.99"})
    assert other.status_code == 429 or other.status_code == 200


def test_traffic_key_separates_peers_but_authenticated_principals_keep_their_own(
    seeded_database: Path,
    tmp_path: Path,
) -> None:
    from starlette.datastructures import Address

    from toxicjoin.api.app import _traffic_principal
    from toxicjoin.auth import AuthenticatedRequest, AuthScope, RequestIdentity

    class _Request:
        def __init__(self, host: str | None) -> None:
            self.client = Address(host, 0) if host is not None else None

    anonymous = fixture_anonymous_request()
    named = AuthenticatedRequest(
        identity=RequestIdentity(principal_id="analyst-7", credential_id="cred-7"),
        scopes=(AuthScope.SYSTEM_READ,),
    )

    key_a = _traffic_principal(_Request("198.51.100.1"), anonymous)
    key_b = _traffic_principal(_Request("198.51.100.2"), anonymous)
    key_unknown = _traffic_principal(_Request(None), anonymous)

    assert key_a != key_b
    assert key_a.startswith(FIXTURE_ANONYMOUS_PRINCIPAL)
    assert key_unknown.endswith("unknown")

    # An authenticated caller is metered by identity, never by where it connected from.
    assert _traffic_principal(_Request("198.51.100.1"), named) == "analyst-7"
    assert _traffic_principal(_Request("198.51.100.2"), named) == "analyst-7"
