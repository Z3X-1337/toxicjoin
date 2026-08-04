"""Cumulative disclosure budget semantics.

The gate previously permitted exactly one protected release per privacy scope for the
lifetime of the ledger, which made the stateful mode single-shot: the second analytical
query a principal ever ran was refused. The allowance is now a bounded, configurable budget
over a rolling window. These tests pin both halves of that trade: work is possible, and the
bound is still enforced and still fails closed.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from toxicjoin.auth import RequestIdentity, bind_request_identity
from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog
from toxicjoin.disclosure import CompositionRule, DisclosureBudget, DisclosureLedger
from toxicjoin.disclosure.composition import evaluate_composition_history
from toxicjoin.disclosure.models import (
    DISCLOSURE_BUDGET_ENV,
    DISCLOSURE_BUDGET_WINDOW_ENV,
)
from toxicjoin.execute import DuckDBExecutor
from toxicjoin.models import ColumnRef, Decision
from toxicjoin.pipeline import PipelineRequest, ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import ReceiptMode, ReceiptStore

from _budget_fixtures import protected_candidate, protected_record


SUBJECT = ColumnRef(dataset="customers", field_path="customer_id", alias="c")


def _identity() -> RequestIdentity:
    return RequestIdentity(
        principal_id="analyst-budget",
        credential_id="cred-budget",
        agent_id="agent-budget",
    )


def _pipeline(database: Path, tmp_path: Path, budget: DisclosureBudget) -> ToxicJoinPipeline:
    return ToxicJoinPipeline(
        context_resolver=FixtureContextResolver(default_fixture_catalog()),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(database),
        disclosure_ledger=DisclosureLedger(tmp_path / "disclosures.sqlite3", budget=budget),
        stateful_privacy_required=True,
    )


def _region_query(region: str) -> str:
    return (
        "SELECT c.coarse_region, AVG(r.churn_score) AS average_churn, "
        "COUNT(DISTINCT c.customer_id) AS subject_count "
        "FROM customers c JOIN retention_scores r ON c.customer_id = r.customer_id "
        f"WHERE c.coarse_region = '{region}' "
        "GROUP BY c.coarse_region HAVING COUNT(DISTINCT c.customer_id) >= 20"
    )


def test_default_budget_permits_more_than_one_protected_release(
    seeded_database: Path,
    tmp_path: Path,
) -> None:
    """The regression that made stateful mode unusable: query two was always refused."""

    pipeline = _pipeline(seeded_database, tmp_path, DisclosureBudget())
    decisions = []
    with bind_request_identity(_identity()):
        for region in ("north", "central", "south"):
            request = PipelineRequest(
                task_purpose="regional churn",
                sql=_region_query(region),
                subject_key=SUBJECT,
            )
            decisions.append(pipeline.execute_safe(request).effective_decision)

    assert decisions == [Decision.ALLOW, Decision.ALLOW, Decision.ALLOW]


def test_budget_exhaustion_still_fails_closed(
    seeded_database: Path,
    tmp_path: Path,
) -> None:
    pipeline = _pipeline(
        seeded_database,
        tmp_path,
        DisclosureBudget(max_protected_releases=2),
    )
    results = []
    with bind_request_identity(_identity()):
        for region in ("north", "central", "south"):
            request = PipelineRequest(
                task_purpose="regional churn",
                sql=_region_query(region),
                subject_key=SUBJECT,
            )
            results.append(pipeline.execute_safe(request))

    assert [result.effective_decision for result in results] == [
        Decision.ALLOW,
        Decision.ALLOW,
        Decision.BLOCK,
    ]
    exhausted = results[-1]
    assert exhausted.verification is not None
    assert exhausted.verification.execution is None
    assert exhausted.verification.execution_attempted is False
    detail = next(
        check.detail
        for check in exhausted.verification.checks
        if check.name == "cumulative_disclosure"
    )
    assert "CUMULATIVE_BUDGET_EXHAUSTED" in detail


def test_releases_outside_the_window_no_longer_restrict_new_work() -> None:
    """A rolling window is what makes the budget recover instead of latching shut."""

    budget = DisclosureBudget(max_protected_releases=1, window_seconds=3600.0)
    now = datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc)
    stale = protected_record(created_at=now - timedelta(seconds=7200))

    evaluation = evaluate_composition_history(
        (stale,),
        protected_candidate(),
        budget=budget,
        now=now,
    )

    assert evaluation.allowed is True
    assert evaluation.rule == CompositionRule.FIRST_PROTECTED_RELEASE
    assert evaluation.prior_protected_count == 0


def test_releases_inside_the_window_still_count() -> None:
    budget = DisclosureBudget(max_protected_releases=1, window_seconds=3600.0)
    now = datetime(2026, 8, 4, 12, 0, tzinfo=timezone.utc)
    recent = protected_record(created_at=now - timedelta(seconds=60))

    evaluation = evaluate_composition_history(
        (recent,),
        protected_candidate(),
        budget=budget,
        now=now,
    )

    assert evaluation.allowed is False
    assert evaluation.rule == CompositionRule.CUMULATIVE_BUDGET_EXHAUSTED


def test_budget_is_configurable_from_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(DISCLOSURE_BUDGET_ENV, "12")
    monkeypatch.setenv(DISCLOSURE_BUDGET_WINDOW_ENV, "600")

    budget = DisclosureBudget.from_environment()

    assert budget.max_protected_releases == 12
    assert budget.window_seconds == 600.0


def test_invalid_budget_configuration_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(DISCLOSURE_BUDGET_ENV, "not-a-number")

    with pytest.raises(ValueError):
        DisclosureBudget.from_environment()


def test_budget_cannot_be_configured_to_zero() -> None:
    with pytest.raises(ValueError):
        DisclosureBudget(max_protected_releases=0)
