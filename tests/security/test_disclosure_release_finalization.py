from __future__ import annotations

from pathlib import Path

from toxicjoin.auth import RequestIdentity, bind_request_identity
from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog, seed_database
from toxicjoin.disclosure import DisclosureCommitment, DisclosureLedger
from toxicjoin.execute import DuckDBExecutor
from toxicjoin.models import ColumnRef, Decision, ReasonCode
from toxicjoin.pipeline import PipelineRequest, ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import ReceiptMode, ReceiptStore


_SUBJECT = ColumnRef(dataset="customers", field_path="customer_id")
_TASK = "Regression: failed execution must not consume privacy history"


def _identity() -> RequestIdentity:
    return RequestIdentity(
        principal_id="release-state-principal",
        credential_id="release-state-credential",
        agent_id="release-state-agent",
        session_id="release-state-session",
    )


def _sql(region: str) -> str:
    return (
        "SELECT COUNT(DISTINCT c.customer_id) AS subject_count "
        f"FROM customers c WHERE c.coarse_region = '{region}'"
    )


def _commitment(ledger: DisclosureLedger, receipt_id: str) -> DisclosureCommitment:
    record = ledger.read_receipt(receipt_id)
    return DisclosureCommitment(
        record_id=record.record_id,
        receipt_id=record.event.receipt_id,
        scope_sha256=record.event.scope.scope_sha256,
        event_sha256=record.event_sha256,
        content_sha256=record.content_sha256,
    )


def test_execution_failure_aborts_reservation_and_does_not_poison_scope(tmp_path: Path) -> None:
    database = tmp_path / "fixture.duckdb"
    seed_database(database)
    ledger = DisclosureLedger(tmp_path / "disclosures.sqlite3")
    pipeline = ToxicJoinPipeline(
        context_resolver=FixtureContextResolver(default_fixture_catalog()),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(database),
        disclosure_ledger=ledger,
        stateful_privacy_required=True,
        include_sanitized_sql=False,
    )

    # Remove the warehouse only after construction. Policy/governance resolution remains
    # available from the fixture catalog, so the request reaches authorization and creates
    # a PENDING disclosure reservation before DuckDB fails to open the read-only database.
    database.unlink()

    with bind_request_identity(_identity()):
        failed = pipeline.execute_safe(
            PipelineRequest(task_purpose=_TASK, sql=_sql("north"), subject_key=_SUBJECT)
        )

    assert failed.initial_decision.decision == Decision.ALLOW
    assert failed.effective_decision == Decision.BLOCK
    assert failed.verification is not None
    assert failed.verification.execution is None
    assert failed.verification.execution_attempted is True
    assert ReasonCode.VERIFICATION_FAILED in failed.final_decision.reason_codes

    failed_commitment = _commitment(ledger, failed.receipt.receipt_id)
    assert ledger.release_state(failed_commitment) == "ABORTED"

    public_error = failed.verification.execution_error or ""
    assert "protected execution failed" in public_error
    assert str(database) not in public_error
    assert "DuckDB rejected" not in public_error
    assert "unable to establish hardened read-only DuckDB connection" not in public_error

    # A different protected cohort is now allowed because the first request never released
    # data and therefore must not count toward active cumulative disclosure history.
    seed_database(database)
    with bind_request_identity(_identity()):
        next_result = pipeline.execute_safe(
            PipelineRequest(task_purpose=_TASK, sql=_sql("south"), subject_key=_SUBJECT)
        )

    assert next_result.effective_decision == Decision.ALLOW
    assert next_result.verification is not None
    assert next_result.verification.execution is not None
    next_commitment = _commitment(ledger, next_result.receipt.receipt_id)
    assert ledger.release_state(next_commitment) == "RELEASED"


def test_released_protected_query_blocks_identical_new_receipt(tmp_path: Path) -> None:
    database = tmp_path / "fixture.duckdb"
    seed_database(database)
    ledger = DisclosureLedger(tmp_path / "disclosures.sqlite3")
    pipeline = ToxicJoinPipeline(
        context_resolver=FixtureContextResolver(default_fixture_catalog()),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(database),
        disclosure_ledger=ledger,
        stateful_privacy_required=True,
        include_sanitized_sql=False,
    )

    request = PipelineRequest(task_purpose=_TASK, sql=_sql("north"), subject_key=_SUBJECT)
    with bind_request_identity(_identity()):
        first = pipeline.execute_safe(request)
        repeat = pipeline.execute_safe(request)

    assert first.effective_decision == Decision.ALLOW
    assert repeat.initial_decision.decision == Decision.ALLOW
    assert repeat.effective_decision == Decision.BLOCK
    assert repeat.final_decision is not None
    assert repeat.final_decision.reason_codes == (ReasonCode.CUMULATIVE_DISCLOSURE_RISK,)
    assert repeat.verification is not None
    assert repeat.verification.execution_attempted is False
    assert repeat.verification.execution is None
