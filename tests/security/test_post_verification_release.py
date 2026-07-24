from __future__ import annotations

import hashlib

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from toxicjoin.api import create_app
from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog
from toxicjoin.execute import ExecutionResult
from toxicjoin.models import ColumnRef, Decision, ReasonCode
from toxicjoin.pipeline import PipelineRequest, ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import ReceiptMode, ReceiptStore
from toxicjoin.sql import analyze_sql
from toxicjoin.verify import (
    VerificationCheck,
    VerificationResult,
    verify_and_execute,
)


SUBJECT = ColumnRef(dataset="customers", field_path="customer_id", alias="c")
SQL = """
SELECT
  c.coarse_region,
  AVG(r.churn_score) AS average_churn,
  COUNT(DISTINCT c.customer_id) AS subject_count
FROM customers c
JOIN retention_scores r ON c.customer_id = r.customer_id
GROUP BY c.coarse_region
HAVING COUNT(DISTINCT c.customer_id) >= 20
""".strip()
SECRET_MARKER = "QUARANTINED_RESULT_MUST_NOT_ESCAPE"


class UnsafeObservedResultExecutor:
    """Return a result that contradicts the trusted subject threshold."""

    def bind_authority(self, **_: object) -> None:
        return None

    def issue_authorization(self, *_: object, **__: object) -> object:
        return object()

    def execute_authorized(self, sql: str, **kwargs: object) -> ExecutionResult:
        dialect = str(kwargs.get("dialect", "duckdb"))
        plan = analyze_sql(sql, dialect=dialect)
        return ExecutionResult(
            authorization_id="tj_auth_" + "0" * 32,
            query_sha256=hashlib.sha256(sql.encode("utf-8")).hexdigest(),
            query_plan=plan,
            columns=("coarse_region", "average_churn", "subject_count"),
            rows=(("central", SECRET_MARKER, 1),),
            preview_row_count=1,
            truncated=False,
            elapsed_ms=0.0,
        )


def _resolver() -> FixtureContextResolver:
    return FixtureContextResolver(default_fixture_catalog())


def _engine() -> PolicyEngine:
    return PolicyEngine(load_policy())


def test_failed_post_verification_quarantines_execution_rows() -> None:
    result = verify_and_execute(
        SQL,
        task_purpose="Find regions with elevated churn risk",
        subject_key=SUBJECT,
        context_resolver=_resolver(),
        policy_engine=_engine(),
        executor=UnsafeObservedResultExecutor(),  # type: ignore[arg-type]
        required_minimum_group_size=20,
        require_subject_threshold=True,
    )

    assert result.passed is False
    assert result.execution_attempted is True
    assert result.execution_quarantined is True
    assert result.execution is None
    assert any(
        check.name == "observed_group_sizes" and not check.passed
        for check in result.checks
    )
    assert SECRET_MARKER not in result.model_dump_json()


def test_schema_rejects_failed_verification_with_released_rows() -> None:
    execution = UnsafeObservedResultExecutor().execute_authorized(
        SQL,
        dialect="duckdb",
    )

    with pytest.raises(
        ValidationError,
        match="failed verification cannot release execution rows",
    ):
        VerificationResult(
            passed=False,
            query_plan=execution.query_plan,
            policy_decision=None,
            checks=(
                VerificationCheck(
                    name="observed_group_sizes",
                    passed=False,
                    detail="minimum observed group size is 1",
                ),
            ),
            execution=execution,
            execution_attempted=True,
        )


def test_pipeline_persists_block_receipt_without_releasing_quarantined_rows(
    tmp_path,
) -> None:
    store = ReceiptStore(tmp_path / "receipts")
    pipeline = ToxicJoinPipeline(
        context_resolver=_resolver(),
        policy_engine=_engine(),
        receipt_store=store,
        mode=ReceiptMode.FIXTURE,
        executor=UnsafeObservedResultExecutor(),  # type: ignore[arg-type]
        include_sanitized_sql=False,
    )

    result = pipeline.execute_safe(
        PipelineRequest(
            task_purpose="Find regions with elevated churn risk",
            sql=SQL,
            subject_key=SUBJECT,
        )
    )

    assert result.final_decision is not None
    assert result.final_decision.decision == Decision.BLOCK
    assert result.final_decision.reason_codes == (ReasonCode.VERIFICATION_FAILED,)
    assert result.verification is not None
    assert result.verification.execution is None
    assert result.verification.execution_quarantined is True
    assert result.receipt.execution is None
    assert store.read(result.receipt.receipt_id) == result.receipt


def test_api_returns_controlled_block_without_quarantined_rows(tmp_path) -> None:
    pipeline = ToxicJoinPipeline(
        context_resolver=_resolver(),
        policy_engine=_engine(),
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.FIXTURE,
        executor=UnsafeObservedResultExecutor(),  # type: ignore[arg-type]
        include_sanitized_sql=False,
    )
    app = create_app(pipeline)

    with TestClient(app) as client:
        response = client.post(
            "/api/execute-safe",
            json={
                "task_purpose": "Find regions with elevated churn risk",
                "sql": SQL,
                "subject_key": SUBJECT.model_dump(mode="json"),
                "dialect": "duckdb",
            },
        )

    assert response.status_code == 200
    body = response.json()
    assert body["effective_decision"] == "BLOCK"
    assert body["verification"]["passed"] is False
    assert body["verification"]["execution_attempted"] is True
    assert body["verification"]["execution_quarantined"] is True
    assert body["verification"]["execution"] is None
    assert body["receipt"]["execution"] is None
    assert SECRET_MARKER not in response.text
