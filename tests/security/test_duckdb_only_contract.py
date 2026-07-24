from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from toxicjoin.api import create_app
from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog, seed_database
from toxicjoin.execute import (
    DuckDBExecutor,
    ExecutionAuthorization,
    ExecutionAuthorizationError,
    ExecutionAuthorizer,
)
from toxicjoin.models import ColumnRef
from toxicjoin.pipeline import PipelineRequest, ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import ReceiptMode, ReceiptStore
from toxicjoin.verify import verify_and_execute


SUBJECT = ColumnRef(dataset="customers", field_path="customer_id", alias="c")
SQL = "SELECT c.coarse_region FROM customers c LIMIT 5"
TASK = "List coarse regions"


def _resolver() -> FixtureContextResolver:
    return FixtureContextResolver(default_fixture_catalog())


def _engine() -> PolicyEngine:
    return PolicyEngine(load_policy())


def test_pipeline_request_rejects_non_duckdb_dialect() -> None:
    with pytest.raises(ValidationError):
        PipelineRequest(
            task_purpose=TASK,
            sql=SQL,
            subject_key=SUBJECT,
            dialect="postgres",
        )


def test_http_api_rejects_non_duckdb_dialect_before_pipeline(tmp_path) -> None:
    database = tmp_path / "demo.duckdb"
    seed_database(database)
    pipeline = ToxicJoinPipeline(
        context_resolver=_resolver(),
        policy_engine=_engine(),
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(database),
    )
    app = create_app(pipeline)

    with TestClient(app) as client:
        response = client.post(
            "/api/execute-safe",
            json={
                "task_purpose": TASK,
                "sql": SQL,
                "subject_key": SUBJECT.model_dump(mode="json"),
                "dialect": "postgres",
            },
        )

    assert response.status_code == 422
    assert not list((tmp_path / "receipts").glob("*.json"))


def test_execution_authorizer_rejects_non_duckdb_dialect_before_analysis() -> None:
    authorizer = ExecutionAuthorizer(
        context_resolver=_resolver(),
        policy_engine=_engine(),
        secret_key=b"ToxicJoin duckdb-only contract test key!!",
    )

    with pytest.raises(ExecutionAuthorizationError, match="AUTH_UNSUPPORTED_DIALECT"):
        authorizer.issue(
            "SELECT 1",
            task_purpose=TASK,
            subject_key=SUBJECT,
            dialect="postgres",
        )


def test_authorization_schema_cannot_carry_alternate_dialect() -> None:
    with pytest.raises(ValidationError):
        ExecutionAuthorization(
            authorization_id="tj_auth_" + "0" * 32,
            issued_at=1.0,
            expires_at=2.0,
            dialect="mysql",
            sql_sha256="0" * 64,
            query_plan_sha256="0" * 64,
            context_sha256="0" * 64,
            policy_sha256="0" * 64,
            policy_decision_sha256="0" * 64,
            task_purpose_sha256="0" * 64,
            subject_key=SUBJECT,
            rewrite_parent_sha256=None,
            mac_sha256="0" * 64,
        )


def test_direct_verifier_fails_closed_on_non_duckdb_execution_dialect(tmp_path) -> None:
    database = tmp_path / "demo.duckdb"
    seed_database(database)
    result = verify_and_execute(
        SQL,
        task_purpose=TASK,
        subject_key=SUBJECT,
        context_resolver=_resolver(),
        policy_engine=_engine(),
        executor=DuckDBExecutor(database),
        required_minimum_group_size=20,
        require_subject_threshold=False,
        dialect="postgres",
    )

    assert result.passed is False
    assert result.execution is None
    assert result.execution_attempted is False
    auth_check = next(
        check for check in result.checks if check.name == "execution_authorization"
    )
    assert auth_check.passed is False
    assert "AUTH_UNSUPPORTED_DIALECT" in auth_check.detail
