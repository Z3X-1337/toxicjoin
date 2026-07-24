from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

import pytest
from fastapi.testclient import TestClient
from sqlglot import exp

from toxicjoin.api import create_app
from toxicjoin.api.limits import (
    ApiResourceLimits,
    PrincipalTrafficLimiter,
    TrafficLimitError,
)
from toxicjoin.auth import ApiKeyAuthenticator, ApiKeyCredentialConfig, AuthScope
from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog, seed_database
from toxicjoin.execute import DuckDBExecutor
from toxicjoin.models import ColumnRef, ReasonCode
from toxicjoin.pipeline import ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import ReceiptMode, ReceiptStore
from toxicjoin.sql import SqlAnalysisError, analyze_sql
from toxicjoin.sql.budget import (
    MAX_SQL_AST_DEPTH,
    MAX_SQL_AST_NODES,
    MAX_SQL_TEXT_BYTES,
    _count_bounded,
)


SUBJECT = ColumnRef(dataset="customers", field_path="customer_id", alias="c")
KEY_A = "resource-budget-key-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
KEY_B = "resource-budget-key-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def _request(sql: str = "SELECT c.coarse_region FROM customers c LIMIT 5") -> dict:
    return {
        "task_purpose": "Resource budget regression",
        "sql": sql,
        "subject_key": SUBJECT.model_dump(mode="json"),
        "dialect": "duckdb",
    }


def _authenticator() -> ApiKeyAuthenticator:
    return ApiKeyAuthenticator(
        (
            ApiKeyCredentialConfig(
                credential_id="cred-a",
                api_key=KEY_A,
                principal_id="principal-shared",
                scopes=(AuthScope.ANALYZE, AuthScope.EXECUTE),
            ),
            ApiKeyCredentialConfig(
                credential_id="cred-b",
                api_key=KEY_B,
                principal_id="principal-shared",
                scopes=(AuthScope.ANALYZE, AuthScope.EXECUTE),
            ),
        )
    )


def _headers(key: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {key}"}


def _pipeline(tmp_path, *, resolver=None) -> ToxicJoinPipeline:
    database = tmp_path / "demo.duckdb"
    seed_database(database)
    return ToxicJoinPipeline(
        context_resolver=resolver or FixtureContextResolver(default_fixture_catalog()),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(database),
        include_sanitized_sql=False,
    )


def test_oversized_declared_body_is_rejected_before_auth_or_persistence(tmp_path) -> None:
    pipeline = _pipeline(tmp_path)
    limits = ApiResourceLimits(max_request_bytes=1024)
    app = create_app(
        pipeline,
        authenticator=_authenticator(),
        resource_limits=limits,
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/analyze",
            content=b"x" * 2048,
            headers={"Content-Type": "application/json"},
        )

    assert response.status_code == 413
    assert response.json()["detail"] == {
        "code": "REQUEST_BODY_TOO_LARGE",
        "max_bytes": 1024,
    }
    assert response.headers["cache-control"] == "no-store, max-age=0"
    assert not list(pipeline.receipt_store.root.glob("*.json"))


def test_chunked_body_cannot_bypass_actual_byte_limit(tmp_path) -> None:
    pipeline = _pipeline(tmp_path)
    limits = ApiResourceLimits(max_request_bytes=1024)
    app = create_app(
        pipeline,
        authenticator=_authenticator(),
        resource_limits=limits,
    )

    def chunks():
        yield b"x" * 700
        yield b"y" * 700

    with TestClient(app) as client:
        response = client.post(
            "/api/analyze",
            content=chunks(),
            headers={
                "Content-Type": "application/json",
                "Transfer-Encoding": "chunked",
            },
        )

    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "REQUEST_BODY_TOO_LARGE"
    assert not list(pipeline.receipt_store.root.glob("*.json"))


def test_sql_text_budget_fails_before_analysis() -> None:
    sql = "SELECT '" + ("x" * MAX_SQL_TEXT_BYTES) + "'"

    with pytest.raises(SqlAnalysisError) as captured:
        analyze_sql(sql)

    assert captured.value.reason_code == ReasonCode.QUERY_COMPLEXITY_LIMIT
    assert "byte budget" in captured.value.detail


def test_sql_ast_node_budget_rejects_wide_projection_bomb() -> None:
    # Keep the tree shallow so the node budget, not the depth budget, is the first
    # deterministic guard reached.
    expressions = ", ".join(str(index) for index in range(MAX_SQL_AST_NODES + 100))

    with pytest.raises(SqlAnalysisError) as captured:
        analyze_sql(f"SELECT {expressions}")

    assert captured.value.reason_code == ReasonCode.QUERY_COMPLEXITY_LIMIT
    assert "node budget" in captured.value.detail


def test_sql_nested_expression_bomb_fails_closed() -> None:
    expression = "1"
    for _ in range(MAX_SQL_AST_DEPTH + 8):
        expression = f"COALESCE({expression}, 0)"

    with pytest.raises(SqlAnalysisError) as captured:
        analyze_sql(f"SELECT {expression}")

    assert captured.value.reason_code == ReasonCode.QUERY_COMPLEXITY_LIMIT
    assert any(
        marker in captured.value.detail
        for marker in ("depth budget", "parser recursion budget")
    )


def test_ast_depth_counter_rejects_deep_tree_when_parser_can_materialize_it() -> None:
    node: exp.Expression = exp.Literal.number(1)
    for _ in range(MAX_SQL_AST_DEPTH + 1):
        node = exp.Paren(this=node)
    root = exp.Select(expressions=[node])

    with pytest.raises(SqlAnalysisError) as captured:
        _count_bounded(root, initial_count=0)

    assert captured.value.reason_code == ReasonCode.QUERY_COMPLEXITY_LIMIT
    assert "depth budget" in captured.value.detail


def test_rate_limit_is_shared_across_credentials_of_one_principal(tmp_path) -> None:
    pipeline = _pipeline(tmp_path)
    limits = ApiResourceLimits(
        rate_limit_requests=1,
        rate_limit_window_seconds=60,
        max_concurrent_per_principal=2,
    )
    app = create_app(
        pipeline,
        authenticator=_authenticator(),
        resource_limits=limits,
    )

    with TestClient(app) as client:
        first = client.post(
            "/api/analyze",
            json=_request(),
            headers=_headers(KEY_A),
        )
        second = client.post(
            "/api/analyze",
            json=_request(),
            headers=_headers(KEY_B),
        )

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json()["detail"]["code"] == "RATE_LIMIT_EXCEEDED"
    assert int(second.headers["retry-after"]) >= 1
    assert len(list(pipeline.receipt_store.root.glob("*.json"))) == 1


def test_sliding_window_recovers_after_expiry() -> None:
    now = [100.0]
    limits = ApiResourceLimits(
        rate_limit_requests=2,
        rate_limit_window_seconds=10,
        max_concurrent_per_principal=2,
    )
    limiter = PrincipalTrafficLimiter(limits, clock=lambda: now[0])

    with limiter.acquire("principal-a"):
        pass
    with limiter.acquire("principal-a"):
        pass

    with pytest.raises(TrafficLimitError, match="RATE_LIMIT_EXCEEDED"):
        with limiter.acquire("principal-a"):
            pass

    now[0] = 111.0
    with limiter.acquire("principal-a"):
        pass


class BlockingResolver:
    def __init__(self) -> None:
        self.delegate = FixtureContextResolver(default_fixture_catalog())
        self.started = threading.Event()
        self.release = threading.Event()
        self.calls = 0

    def resolve(self, query_plan):
        self.calls += 1
        self.started.set()
        if not self.release.wait(timeout=5):
            raise RuntimeError("test resolver release timeout")
        return self.delegate.resolve(query_plan)


def test_concurrency_limit_rejects_second_same_principal_before_resolver(tmp_path) -> None:
    resolver = BlockingResolver()
    pipeline = _pipeline(tmp_path, resolver=resolver)
    limits = ApiResourceLimits(
        rate_limit_requests=10,
        rate_limit_window_seconds=60,
        max_concurrent_per_principal=1,
    )
    app = create_app(
        pipeline,
        authenticator=_authenticator(),
        resource_limits=limits,
    )

    with TestClient(app) as client_a, TestClient(app) as client_b:
        with ThreadPoolExecutor(max_workers=1) as pool:
            first_future = pool.submit(
                client_a.post,
                "/api/analyze",
                json=_request(),
                headers=_headers(KEY_A),
            )
            assert resolver.started.wait(timeout=3)
            try:
                second = client_b.post(
                    "/api/analyze",
                    json=_request(),
                    headers=_headers(KEY_B),
                )
            finally:
                resolver.release.set()
            first = first_future.result(timeout=5)

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.json()["detail"]["code"] == "CONCURRENCY_LIMIT_EXCEEDED"
    assert resolver.calls == 1
    assert len(list(pipeline.receipt_store.root.glob("*.json"))) == 1


def test_resource_limit_environment_configuration_is_strict() -> None:
    limits = ApiResourceLimits.from_environment(
        {
            "TOXICJOIN_MAX_REQUEST_BYTES": "65536",
            "TOXICJOIN_RATE_LIMIT_REQUESTS": "12",
            "TOXICJOIN_RATE_LIMIT_WINDOW_SECONDS": "30",
            "TOXICJOIN_MAX_CONCURRENT_PER_PRINCIPAL": "1",
        }
    )
    assert limits.max_request_bytes == 65536
    assert limits.rate_limit_requests == 12
    assert limits.rate_limit_window_seconds == 30
    assert limits.max_concurrent_per_principal == 1

    with pytest.raises(ValueError):
        ApiResourceLimits.from_environment({"TOXICJOIN_RATE_LIMIT_REQUESTS": "0"})
