from __future__ import annotations

from pathlib import Path

from toxicjoin.context import FixtureContextResolver
from toxicjoin.context.fixture import ContextResolution
from toxicjoin.demo import seed_database
from toxicjoin.execute import DuckDBExecutor
from toxicjoin.models import ColumnRef, Decision, QueryPlan, ReasonCode
from toxicjoin.pipeline import PipelineRequest, ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import ReceiptMode, ReceiptStore


ROOT = Path(__file__).parents[2]
CATALOG = ROOT / "demo" / "fixtures" / "catalog.json"
SUBJECT = ColumnRef(dataset="customers", field_path="customer_id", alias="c")


FLAGSHIP_SQL = """
SELECT
  c.coarse_region,
  AVG(r.churn_score) AS average_churn,
  COUNT(DISTINCT c.customer_id) AS subject_count
FROM customers c
JOIN retention_scores r ON c.customer_id = r.customer_id
GROUP BY c.coarse_region
"""


BLOCKED_SQL = """
SELECT c.customer_id, c.age_band, c.precise_area, s.case_category
FROM customers c
JOIN support_cases s ON c.customer_id = s.customer_id
"""


class ExplodingResolver:
    def resolve(self, _: QueryPlan) -> ContextResolution:
        raise RuntimeError("simulated unavailable context service")


def _pipeline(tmp_path, *, resolver=None, with_executor: bool = True) -> ToxicJoinPipeline:
    database = tmp_path / "demo.duckdb"
    seed_database(database)
    return ToxicJoinPipeline(
        context_resolver=resolver or FixtureContextResolver.from_path(CATALOG),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(database) if with_executor else None,
    )


def _request(sql: str, *, purpose: str = "Find regions with elevated churn risk") -> PipelineRequest:
    return PipelineRequest(
        task_purpose=purpose,
        sql=sql,
        subject_key=SUBJECT,
    )


def test_invalid_sql_fails_closed_and_writes_receipt(tmp_path) -> None:
    pipeline = _pipeline(tmp_path)

    result = pipeline.analyze(_request("DELETE FROM customers"))

    assert result.effective_decision == Decision.BLOCK
    assert result.initial_decision.reason_codes == (ReasonCode.UNSUPPORTED_STATEMENT,)
    assert result.original_plan is None
    stored = pipeline.receipt_store.read(result.receipt.receipt_id)
    assert stored == result.receipt
    assert stored.sql.sanitized_original is None


def test_context_outage_fails_closed_without_leaking_exception_text(tmp_path) -> None:
    pipeline = _pipeline(tmp_path, resolver=ExplodingResolver())

    result = pipeline.analyze(_request("SELECT c.coarse_region FROM customers c"))

    assert result.effective_decision == Decision.BLOCK
    assert result.initial_decision.reason_codes == (ReasonCode.DATAHUB_UNAVAILABLE,)
    assert result.receipt.initial_evidence == {
        "stage": "context_resolution",
        "error_type": "RuntimeError",
        "fail_closed": True,
    }
    assert "simulated unavailable" not in result.receipt.model_dump_json()


def test_blocked_compositional_query_writes_nonexecuted_receipt(tmp_path) -> None:
    pipeline = _pipeline(tmp_path)

    result = pipeline.execute_safe(
        _request(
            BLOCKED_SQL,
            purpose="Export customers with sensitive support cases",
        )
    )

    assert result.effective_decision == Decision.BLOCK
    assert result.initial_decision.decision == Decision.BLOCK
    assert ReasonCode.COMPOSITIONAL_REIDENTIFICATION_RISK in (
        result.initial_decision.reason_codes
    )
    assert result.verification is None
    assert result.receipt.execution is None


def test_analyze_rewrites_but_does_not_execute(tmp_path) -> None:
    pipeline = _pipeline(tmp_path)

    result = pipeline.analyze(_request(FLAGSHIP_SQL))

    assert result.initial_decision.decision == Decision.REWRITE
    assert result.final_decision is not None
    assert result.final_decision.decision == Decision.ALLOW
    assert result.safe_sql is not None
    assert result.verification is None
    assert result.receipt.initial_decision == Decision.REWRITE
    assert result.receipt.final_decision == Decision.ALLOW
    assert result.receipt.execution is None
    assert result.receipt.sql.safe_sha256 is not None


def test_execute_rewrite_runs_real_duckdb_and_stores_sanitized_receipt(tmp_path) -> None:
    pipeline = _pipeline(tmp_path)

    result = pipeline.execute_safe(_request(FLAGSHIP_SQL))

    assert result.effective_decision == Decision.ALLOW
    assert result.verification is not None
    assert result.verification.passed is True
    assert result.verification.execution is not None
    assert result.verification.execution.rows
    assert result.receipt.execution is not None
    assert result.receipt.execution.preview_row_count == 3
    encoded = result.receipt.model_dump_json()
    assert '"rows"' not in encoded
    assert "RAW_SECRET" not in encoded
    stored = pipeline.receipt_store.read(result.receipt.receipt_id)
    assert stored.content_sha256 == result.receipt.content_sha256


def test_allowed_low_risk_query_executes_without_group_threshold(tmp_path) -> None:
    pipeline = _pipeline(tmp_path)
    sql = "SELECT o.category, COUNT(*) AS order_count FROM orders o GROUP BY o.category"

    result = pipeline.execute_safe(
        _request(sql, purpose="Count orders by public category")
    )

    assert result.initial_decision.decision == Decision.ALLOW
    assert result.effective_decision == Decision.ALLOW
    assert result.verification is not None
    assert result.verification.passed is True
    assert any(
        check.name == "trusted_subject_threshold" and check.passed
        for check in result.verification.checks
    )
    assert any(
        check.name == "bounded_preview" and check.passed
        for check in result.verification.checks
    )


def test_executor_unavailable_turns_allow_into_final_block(tmp_path) -> None:
    pipeline = _pipeline(tmp_path, with_executor=False)
    sql = "SELECT o.category, COUNT(*) AS order_count FROM orders o GROUP BY o.category"

    result = pipeline.execute_safe(
        _request(sql, purpose="Count orders by public category")
    )

    assert result.initial_decision.decision == Decision.ALLOW
    assert result.final_decision is not None
    assert result.final_decision.decision == Decision.BLOCK
    assert result.final_decision.reason_codes == (ReasonCode.VERIFICATION_FAILED,)
    assert result.receipt.final_decision == Decision.BLOCK
    assert result.receipt.execution is None
