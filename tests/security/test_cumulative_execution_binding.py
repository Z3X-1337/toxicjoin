from __future__ import annotations

from pathlib import Path

import pytest

from toxicjoin.auth import RequestIdentity, bind_request_identity
from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog, seed_database
from toxicjoin.disclosure import (
    DisclosureCommitment,
    DisclosureLedger,
    build_disclosure_event_from_resolver,
)
from toxicjoin.execute import (
    DuckDBExecutor,
    ExecutionAuthorizationError,
    ExecutionAuthorizer,
)
from toxicjoin.models import ColumnRef, Decision, ReasonCode
from toxicjoin.pipeline import PipelineRequest, ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import ReceiptMode, ReceiptStore
from toxicjoin.sql import analyze_sql


_SUBJECT = ColumnRef(dataset="customers", field_path="customer_id")
_TASK = "Count customers for an approved aggregate analytics task"


def _identity() -> RequestIdentity:
    return RequestIdentity(
        principal_id="principal-a",
        credential_id="credential-a",
        agent_id="agent-a",
        session_id="session-a",
    )


def _count_sql(region: str, *, alias: str = "subject_count") -> str:
    return (
        f"SELECT COUNT(DISTINCT c.customer_id) AS {alias} "
        f"FROM customers c WHERE c.coarse_region = '{region}'"
    )


def _pipeline(tmp_path: Path) -> ToxicJoinPipeline:
    database = tmp_path / "fixture.duckdb"
    seed_database(database)
    return ToxicJoinPipeline(
        context_resolver=FixtureContextResolver(default_fixture_catalog()),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(database),
        disclosure_ledger=DisclosureLedger(tmp_path / "disclosures.sqlite3"),
        stateful_privacy_required=True,
        include_sanitized_sql=False,
    )


def test_allow_allow_pair_becomes_blocked_only_after_first_release(tmp_path: Path) -> None:
    pipeline = _pipeline(tmp_path)
    first_request = PipelineRequest(
        task_purpose=_TASK,
        sql=_count_sql("north"),
        subject_key=_SUBJECT,
    )
    second_request = PipelineRequest(
        task_purpose=_TASK,
        sql=_count_sql("south"),
        subject_key=_SUBJECT,
    )

    # Each query is request-locally ALLOW under the deterministic policy.
    first_plan = analyze_sql(first_request.sql, dialect="duckdb")
    second_plan = analyze_sql(second_request.sql, dialect="duckdb")
    assert pipeline.policy_engine.evaluate(
        pipeline.context_resolver.resolve(first_plan).to_policy_input(
            task_purpose=_TASK,
            query_plan=first_plan,
            subject_key=_SUBJECT,
        )
    ).decision == Decision.ALLOW
    assert pipeline.policy_engine.evaluate(
        pipeline.context_resolver.resolve(second_plan).to_policy_input(
            task_purpose=_TASK,
            query_plan=second_plan,
            subject_key=_SUBJECT,
        )
    ).decision == Decision.ALLOW

    with bind_request_identity(_identity()):
        first = pipeline.execute_safe(first_request)
        second = pipeline.execute_safe(second_request)

    assert first.effective_decision == Decision.ALLOW
    assert first.verification is not None and first.verification.execution is not None
    assert first.receipt.execution is not None
    assert second.initial_decision.decision == Decision.ALLOW
    assert second.effective_decision == Decision.BLOCK
    assert second.final_decision is not None
    assert second.final_decision.reason_codes == (ReasonCode.CUMULATIVE_DISCLOSURE_RISK,)
    assert second.verification is not None
    assert second.verification.execution is None
    assert second.receipt.execution is None
    assert "cumulative_disclosure" in {
        check.name for check in second.verification.checks if not check.passed
    }
    assert pipeline.disclosure_ledger is not None
    assert pipeline.disclosure_ledger.verify_all() == 1


def test_identical_cohort_with_alias_change_is_blocked_after_release(tmp_path: Path) -> None:
    pipeline = _pipeline(tmp_path)
    first = PipelineRequest(
        task_purpose=_TASK,
        sql=_count_sql("north", alias="subject_count"),
        subject_key=_SUBJECT,
    )
    repeat = PipelineRequest(
        task_purpose=_TASK,
        sql=_count_sql("north", alias="renamed_count"),
        subject_key=_SUBJECT,
    )

    with bind_request_identity(_identity()):
        first_result = pipeline.execute_safe(first)
        repeat_result = pipeline.execute_safe(repeat)

    assert first_result.effective_decision == Decision.ALLOW
    assert repeat_result.initial_decision.decision == Decision.ALLOW
    assert repeat_result.effective_decision == Decision.BLOCK
    assert repeat_result.verification is not None
    cumulative = next(
        check
        for check in repeat_result.verification.checks
        if check.name == "cumulative_disclosure"
    )
    assert cumulative.passed is False
    assert "REPEAT_PROTECTED_RELEASE_BLOCK" in cumulative.detail
    assert repeat_result.verification.execution_attempted is False
    assert repeat_result.verification.execution is None
    assert pipeline.disclosure_ledger is not None
    assert pipeline.disclosure_ledger.verify_all() == 1


def test_required_state_missing_fails_closed_before_execution(tmp_path: Path) -> None:
    database = tmp_path / "fixture.duckdb"
    seed_database(database)
    pipeline = ToxicJoinPipeline(
        context_resolver=FixtureContextResolver(default_fixture_catalog()),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(database),
        disclosure_ledger=None,
        stateful_privacy_required=True,
        include_sanitized_sql=False,
    )

    with bind_request_identity(_identity()):
        result = pipeline.execute_safe(
            PipelineRequest(task_purpose=_TASK, sql=_count_sql("north"), subject_key=_SUBJECT)
        )

    assert result.initial_decision.decision == Decision.ALLOW
    assert result.effective_decision == Decision.BLOCK
    assert result.final_decision is not None
    assert result.final_decision.reason_codes == (ReasonCode.DISCLOSURE_STATE_UNAVAILABLE,)
    assert result.verification is not None
    assert result.verification.execution is None
    assert result.receipt.execution is None


def test_inactive_fixture_pipeline_drops_disclosure_authority_and_remains_stateless(
    tmp_path: Path,
) -> None:
    database = tmp_path / "fixture.duckdb"
    seed_database(database)
    inactive_ledger = DisclosureLedger(tmp_path / "inactive-disclosures.sqlite3")
    pipeline = ToxicJoinPipeline(
        context_resolver=FixtureContextResolver(default_fixture_catalog()),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(database),
        disclosure_ledger=inactive_ledger,
        stateful_privacy_required=False,
        include_sanitized_sql=False,
    )

    assert pipeline.disclosure_ledger is None
    with bind_request_identity(_identity()):
        first = pipeline.execute_safe(
            PipelineRequest(task_purpose=_TASK, sql=_count_sql("north"), subject_key=_SUBJECT)
        )
        second = pipeline.execute_safe(
            PipelineRequest(task_purpose=_TASK, sql=_count_sql("south"), subject_key=_SUBJECT)
        )

    assert first.effective_decision == Decision.ALLOW
    assert second.effective_decision == Decision.ALLOW
    assert first.verification is not None and first.verification.execution is not None
    assert second.verification is not None and second.verification.execution is not None
    assert inactive_ledger.verify_all() == 0


def _committed_authorizer(tmp_path: Path):
    resolver = FixtureContextResolver(default_fixture_catalog())
    policy = PolicyEngine(load_policy())
    ledger = DisclosureLedger(tmp_path / "disclosures.sqlite3")
    sql = _count_sql("north")
    plan = analyze_sql(sql, dialect="duckdb")
    resolution = resolver.resolve(plan)
    decision = policy.evaluate(
        resolution.to_policy_input(
            task_purpose=_TASK,
            query_plan=plan,
            subject_key=_SUBJECT,
        )
    )
    assert decision.decision == Decision.ALLOW
    event = build_disclosure_event_from_resolver(
        identity=_identity(),
        resolver=resolver,
        resolution=resolution,
        query_plan=plan,
        subject_key=_SUBJECT,
        receipt_id="tj_00000000000000aa",
        policy_version=decision.policy_version,
    )
    composition = ledger.evaluate_and_commit(event, sql=sql)
    assert composition.commitment is not None
    authorizer = ExecutionAuthorizer(
        context_resolver=resolver,
        policy_engine=policy,
        disclosure_ledger=ledger,
        require_disclosure_commitment=True,
        secret_key=b"a" * 32,
    )
    return authorizer, ledger, sql, composition.commitment


def test_direct_authorizer_cannot_bypass_or_replay_required_commitment(tmp_path: Path) -> None:
    authorizer, ledger, sql, commitment = _committed_authorizer(tmp_path)

    with bind_request_identity(_identity()):
        with pytest.raises(
            ExecutionAuthorizationError,
            match="AUTH_DISCLOSURE_COMMITMENT_REQUIRED",
        ):
            authorizer.issue(sql, task_purpose=_TASK, subject_key=_SUBJECT)
        authorization = authorizer.issue(
            sql,
            task_purpose=_TASK,
            subject_key=_SUBJECT,
            disclosure_commitment=commitment,
        )
        ledger.verify_authorization_claim(commitment, authorization.authorization_id)

        with pytest.raises(
            ExecutionAuthorizationError,
            match="AUTH_DISCLOSURE_COMMITMENT_REPLAYED",
        ):
            authorizer.issue(
                sql,
                task_purpose=_TASK,
                subject_key=_SUBJECT,
                disclosure_commitment=commitment,
            )

    assert authorization.disclosure_commitment == commitment
    assert ledger.verify_all() == 1


def test_commitment_for_different_sql_or_forged_hash_is_rejected(tmp_path: Path) -> None:
    authorizer, _, sql, commitment = _committed_authorizer(tmp_path)
    changed_sql = _count_sql("south")
    forged = DisclosureCommitment(
        record_id=commitment.record_id,
        receipt_id=commitment.receipt_id,
        scope_sha256=commitment.scope_sha256,
        event_sha256="0" * 64,
        content_sha256=commitment.content_sha256,
    )

    with bind_request_identity(_identity()):
        with pytest.raises(
            ExecutionAuthorizationError,
            match="AUTH_DISCLOSURE_COMMITMENT_INVALID",
        ):
            authorizer.issue(
                changed_sql,
                task_purpose=_TASK,
                subject_key=_SUBJECT,
                disclosure_commitment=commitment,
            )
        with pytest.raises(
            ExecutionAuthorizationError,
            match="AUTH_DISCLOSURE_COMMITMENT_INVALID",
        ):
            authorizer.issue(
                sql,
                task_purpose=_TASK,
                subject_key=_SUBJECT,
                disclosure_commitment=forged,
            )


def test_executor_rejects_disclosure_authority_substitution(tmp_path: Path) -> None:
    database = tmp_path / "fixture.duckdb"
    seed_database(database)
    resolver = FixtureContextResolver(default_fixture_catalog())
    policy = PolicyEngine(load_policy())
    first_ledger = DisclosureLedger(tmp_path / "first.sqlite3")
    second_ledger = DisclosureLedger(tmp_path / "second.sqlite3")
    executor = DuckDBExecutor(database)

    executor.bind_authority(
        context_resolver=resolver,
        policy_engine=policy,
        disclosure_ledger=first_ledger,
        require_disclosure_commitment=True,
    )
    with pytest.raises(ValueError, match="authority does not match"):
        executor.bind_authority(
            context_resolver=resolver,
            policy_engine=policy,
            disclosure_ledger=second_ledger,
            require_disclosure_commitment=True,
        )
    with pytest.raises(ValueError, match="authority does not match"):
        executor.bind_authority(
            context_resolver=resolver,
            policy_engine=policy,
            disclosure_ledger=first_ledger,
            require_disclosure_commitment=False,
        )
