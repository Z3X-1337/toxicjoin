from __future__ import annotations

from collections.abc import Iterator

import pytest
from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from fastapi.testclient import TestClient

from toxicjoin.api import ApiResourceLimits, create_app
from toxicjoin.api.limits import ResponseBodyLimitMiddleware
from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog, seed_database
from toxicjoin.execute import DuckDBExecutor, ExecutionOutputLimits
from toxicjoin.models import ColumnRef, Decision, ReasonCode
from toxicjoin.pipeline import PipelineRequest, ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import ReceiptMode, ReceiptStore


SUBJECT = ColumnRef(dataset="customers", field_path="customer_id", alias="c")
CELL_MARKER = "OVERSIZED_CELL_MUST_NOT_ESCAPE"
RESPONSE_MARKER = "OVERSIZED_RESPONSE_MUST_NOT_ESCAPE"


def _pipeline(
    tmp_path,
    *,
    output_limits: ExecutionOutputLimits | None = None,
) -> ToxicJoinPipeline:
    database = tmp_path / "demo.duckdb"
    if not database.exists():
        seed_database(database)
    return ToxicJoinPipeline(
        context_resolver=FixtureContextResolver(default_fixture_catalog()),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(database, output_limits=output_limits),
        include_sanitized_sql=True,
    )


def _request(sql: str, *, task_purpose: str = "Output budget regression") -> PipelineRequest:
    return PipelineRequest(
        task_purpose=task_purpose,
        sql=sql,
        subject_key=SUBJECT,
        dialect="duckdb",
    )


def test_oversized_single_cell_is_blocked_and_never_released(tmp_path) -> None:
    limits = ExecutionOutputLimits(max_cell_bytes=1024, max_result_bytes=4096)
    pipeline = _pipeline(tmp_path, output_limits=limits)
    sql = (
        "SELECT c.coarse_region || repeat('"
        + CELL_MARKER
        + "', 80) AS region_blob FROM customers c LIMIT 1"
    )

    result = pipeline.execute_safe(_request(sql))

    assert result.initial_decision.decision == Decision.ALLOW
    assert result.effective_decision == Decision.BLOCK
    assert result.verification is not None
    assert result.verification.execution_attempted is True
    assert result.verification.execution is None
    assert result.verification.execution_error is not None
    assert ReasonCode.RESULT_SIZE_LIMIT.value in result.verification.execution_error
    assert result.receipt.execution is None
    assert CELL_MARKER not in result.model_dump_json()
    stored = pipeline.receipt_store.read(result.receipt.receipt_id)
    assert stored.execution is None
    assert CELL_MARKER not in stored.model_dump_json()


def test_total_execution_payload_budget_blocks_many_individually_valid_cells(
    tmp_path,
) -> None:
    limits = ExecutionOutputLimits(max_cell_bytes=1024, max_result_bytes=4096)
    pipeline = _pipeline(tmp_path, output_limits=limits)
    sql = (
        "SELECT c.coarse_region || repeat('x', 900) AS region_blob "
        "FROM customers c LIMIT 10"
    )

    result = pipeline.execute_safe(_request(sql))

    assert result.initial_decision.decision == Decision.ALLOW
    assert result.effective_decision == Decision.BLOCK
    assert result.verification is not None
    assert result.verification.execution is None
    assert result.verification.execution_error is not None
    assert ReasonCode.RESULT_SIZE_LIMIT.value in result.verification.execution_error
    assert "execution payload" in result.verification.execution_error
    assert result.receipt.execution is None


def test_response_limit_replaces_oversized_pipeline_response_without_partial_leak(
    tmp_path,
) -> None:
    pipeline = _pipeline(tmp_path)
    limits = ApiResourceLimits(max_response_bytes=4096)
    app = create_app(pipeline, resource_limits=limits)
    projections = ", ".join(
        f"c.coarse_region AS {RESPONSE_MARKER.lower()}_{index:03d}"
        for index in range(180)
    )
    payload = {
        "task_purpose": "x" * 2000,
        "sql": f"SELECT {projections} FROM customers c LIMIT 1",
        "subject_key": SUBJECT.model_dump(mode="json"),
        "dialect": "duckdb",
    }

    with TestClient(app) as client:
        response = client.post("/api/analyze", json=payload)

    assert response.status_code == 422
    assert response.json() == {
        "detail": {
            "code": "RESPONSE_SIZE_LIMIT_EXCEEDED",
            "max_bytes": 4096,
        }
    }
    assert RESPONSE_MARKER.lower() not in response.text
    assert response.headers["cache-control"] == "no-store, max-age=0"
    assert response.headers["x-content-type-options"] == "nosniff"
    # Analysis may already have created its immutable audit receipt; the response
    # gate controls release, not the audit trail.
    assert len(list(pipeline.receipt_store.root.glob("*.json"))) == 1


def test_response_limit_buffers_streaming_chunks_before_any_release() -> None:
    app = FastAPI()
    app.add_middleware(ResponseBodyLimitMiddleware, max_bytes=4096)

    @app.get("/api/stream")
    def stream() -> StreamingResponse:
        def chunks() -> Iterator[bytes]:
            yield (RESPONSE_MARKER + "a" * 2500).encode()
            yield (RESPONSE_MARKER + "b" * 2500).encode()

        return StreamingResponse(chunks(), media_type="text/plain")

    with TestClient(app) as client:
        response = client.get("/api/stream")

    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "RESPONSE_SIZE_LIMIT_EXCEEDED"
    assert RESPONSE_MARKER not in response.text


def test_small_api_response_remains_unchanged_under_budget(tmp_path) -> None:
    pipeline = _pipeline(tmp_path)
    app = create_app(
        pipeline,
        resource_limits=ApiResourceLimits(max_response_bytes=4096),
    )

    with TestClient(app) as client:
        response = client.get("/api/health")

    assert response.status_code == 200
    assert response.json()["mode"] == "fixture"
    assert len(response.content) < 4096


def test_execution_output_limit_environment_configuration_is_strict() -> None:
    limits = ExecutionOutputLimits.from_environment(
        {
            "TOXICJOIN_MAX_CELL_BYTES": "2048",
            "TOXICJOIN_MAX_RESULT_BYTES": "8192",
        }
    )
    assert limits.max_cell_bytes == 2048
    assert limits.max_result_bytes == 8192

    with pytest.raises(ValueError):
        ExecutionOutputLimits.from_environment(
            {
                "TOXICJOIN_MAX_CELL_BYTES": "8192",
                "TOXICJOIN_MAX_RESULT_BYTES": "4096",
            }
        )
    with pytest.raises(ValueError):
        ExecutionOutputLimits.from_environment(
            {"TOXICJOIN_MAX_CELL_BYTES": "not-an-integer"}
        )


def test_api_response_limit_environment_configuration_is_strict() -> None:
    limits = ApiResourceLimits.from_environment(
        {"TOXICJOIN_MAX_RESPONSE_BYTES": "65536"}
    )
    assert limits.max_response_bytes == 65536

    with pytest.raises(ValueError):
        ApiResourceLimits.from_environment(
            {"TOXICJOIN_MAX_RESPONSE_BYTES": "1024"}
        )
