from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from research.trust_kernel.authorization import (
    AuthorizationBoundDuckDBExecutor,
    AuthorizationError,
    issue_execution_authorization,
    verify_execution_authorization,
)
from toxicjoin.context import FixtureCatalog, FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog, seed_database
from toxicjoin.execute import DuckDBExecutor
from toxicjoin.models import ColumnRef
from toxicjoin.policy import PolicyEngine, load_policy


SECRET = b"ToxicJoin research authorization key" + b"!" * 16
NOW = datetime(2026, 7, 23, 22, 0, tzinfo=timezone.utc)
TASK = "Count synthetic subjects by coarse region"
SQL = (
    "SELECT c.coarse_region, COUNT(DISTINCT c.customer_id) AS subject_count "
    "FROM customers c GROUP BY c.coarse_region ORDER BY c.coarse_region"
)
SUBJECT = ColumnRef(dataset="customers", field_path="customer_id", alias="c")


def _resolver() -> FixtureContextResolver:
    return FixtureContextResolver(default_fixture_catalog())


def _engine() -> PolicyEngine:
    return PolicyEngine(load_policy())


def _authorization(*, ttl_seconds: int = 60):
    return issue_execution_authorization(
        sql=SQL,
        task_purpose=TASK,
        subject_key=SUBJECT,
        context_resolver=_resolver(),
        policy_engine=_engine(),
        secret_key=SECRET,
        ttl_seconds=ttl_seconds,
        now=NOW,
    )


def test_exact_authorization_executes_and_mismatches_fail_closed(tmp_path):
    database = tmp_path / "warehouse.duckdb"
    seed_database(database)
    executor = AuthorizationBoundDuckDBExecutor(
        DuckDBExecutor(database), secret_key=SECRET
    )
    authorization = _authorization()

    result = executor.execute_authorized(
        authorization=authorization,
        sql=SQL,
        task_purpose=TASK,
        subject_key=SUBJECT,
        context_resolver=_resolver(),
        policy_engine=_engine(),
        now=NOW + timedelta(seconds=1),
    )
    assert result.preview_row_count == 3

    # LIMIT is intentionally not represented in ToxicJoin's current QueryPlan model,
    # but the exact-SQL binding must still reject this post-authorization mutation.
    changed_sql = SQL + " LIMIT 1"
    verification = verify_execution_authorization(
        authorization=authorization,
        sql=changed_sql,
        task_purpose=TASK,
        subject_key=SUBJECT,
        context_resolver=_resolver(),
        policy_engine=_engine(),
        secret_key=SECRET,
        now=NOW + timedelta(seconds=1),
    )
    assert verification.passed is False
    assert "sql" in verification.failed_checks

    with pytest.raises(AuthorizationError):
        executor.execute_authorized(
            authorization=authorization,
            sql=changed_sql,
            task_purpose=TASK,
            subject_key=SUBJECT,
            context_resolver=_resolver(),
            policy_engine=_engine(),
            now=NOW + timedelta(seconds=1),
        )

    # A true structural mutation changes both exact SQL and parsed-plan bindings.
    structural_sql = (
        "SELECT c.coarse_region, c.age_band, "
        "COUNT(DISTINCT c.customer_id) AS subject_count "
        "FROM customers c GROUP BY c.coarse_region, c.age_band "
        "ORDER BY c.coarse_region, c.age_band"
    )
    structural_check = verify_execution_authorization(
        authorization=authorization,
        sql=structural_sql,
        task_purpose=TASK,
        subject_key=SUBJECT,
        context_resolver=_resolver(),
        policy_engine=_engine(),
        secret_key=SECRET,
        now=NOW + timedelta(seconds=1),
    )
    assert structural_check.passed is False
    assert "sql" in structural_check.failed_checks
    assert "query_plan" in structural_check.failed_checks


def test_context_policy_subject_task_mac_and_expiry_are_bound():
    authorization = _authorization(ttl_seconds=5)

    catalog_payload = default_fixture_catalog().model_dump(mode="json")
    catalog_payload["datasets"]["customers"]["fields"]["coarse_region"][
        "category"
    ] = "UNCLASSIFIED"
    changed_resolver = FixtureContextResolver(FixtureCatalog.model_validate(catalog_payload))
    changed_context = verify_execution_authorization(
        authorization=authorization,
        sql=SQL,
        task_purpose=TASK,
        subject_key=SUBJECT,
        context_resolver=changed_resolver,
        policy_engine=_engine(),
        secret_key=SECRET,
        now=NOW + timedelta(seconds=1),
    )
    assert changed_context.passed is False
    assert "governance_context" in changed_context.failed_checks
    assert "fresh_policy_allow" in changed_context.failed_checks

    changed_policy = load_policy().model_copy(
        update={"minimum_group_size": load_policy().minimum_group_size + 1}
    )
    policy_check = verify_execution_authorization(
        authorization=authorization,
        sql=SQL,
        task_purpose=TASK,
        subject_key=SUBJECT,
        context_resolver=_resolver(),
        policy_engine=PolicyEngine(changed_policy),
        secret_key=SECRET,
        now=NOW + timedelta(seconds=1),
    )
    assert policy_check.passed is False
    assert "policy_config" in policy_check.failed_checks

    changed_subject = ColumnRef(dataset="customers", field_path="customer_id")
    subject_check = verify_execution_authorization(
        authorization=authorization,
        sql=SQL,
        task_purpose=TASK,
        subject_key=changed_subject,
        context_resolver=_resolver(),
        policy_engine=_engine(),
        secret_key=SECRET,
        now=NOW + timedelta(seconds=1),
    )
    assert subject_check.passed is False
    assert "subject_key" in subject_check.failed_checks

    # Task purpose is independently bound even though the current policy engine does
    # not use purpose as a decision variable.
    task_check = verify_execution_authorization(
        authorization=authorization,
        sql=SQL,
        task_purpose=TASK + " changed",
        subject_key=SUBJECT,
        context_resolver=_resolver(),
        policy_engine=_engine(),
        secret_key=SECRET,
        now=NOW + timedelta(seconds=1),
    )
    assert task_check.passed is False
    assert "task_purpose" in task_check.failed_checks

    forged = authorization.model_copy(update={"mac_sha256": "0" * 64})
    forged_check = verify_execution_authorization(
        authorization=forged,
        sql=SQL,
        task_purpose=TASK,
        subject_key=SUBJECT,
        context_resolver=_resolver(),
        policy_engine=_engine(),
        secret_key=SECRET,
        now=NOW + timedelta(seconds=1),
    )
    assert forged_check.passed is False
    assert "authorization_mac" in forged_check.failed_checks

    expired_check = verify_execution_authorization(
        authorization=authorization,
        sql=SQL,
        task_purpose=TASK,
        subject_key=SUBJECT,
        context_resolver=_resolver(),
        policy_engine=_engine(),
        secret_key=SECRET,
        now=NOW + timedelta(seconds=5),
    )
    assert expired_check.passed is False
    assert "authorization_expired" in expired_check.failed_checks


def test_safe_rewrite_can_be_bound_to_its_parent_sql(tmp_path):
    database = tmp_path / "warehouse.duckdb"
    seed_database(database)
    resolver = _resolver()
    engine = _engine()
    original_sql = (
        "SELECT c.coarse_region, AVG(r.churn_score) AS average_churn, "
        "COUNT(DISTINCT c.customer_id) AS subject_count "
        "FROM customers c JOIN retention_scores r "
        "ON c.customer_id = r.customer_id "
        "GROUP BY c.coarse_region ORDER BY c.coarse_region"
    )
    safe_sql = (
        "SELECT c.coarse_region, AVG(r.churn_score) AS average_churn, "
        "COUNT(DISTINCT c.customer_id) AS subject_count "
        "FROM customers c JOIN retention_scores r "
        "ON c.customer_id = r.customer_id "
        "GROUP BY c.coarse_region "
        "HAVING COUNT(DISTINCT c.customer_id) >= 20 "
        "ORDER BY c.coarse_region"
    )
    subject = ColumnRef(dataset="customers", field_path="customer_id", alias="c")
    authorization = issue_execution_authorization(
        sql=safe_sql,
        task_purpose="Find regions with elevated churn risk",
        subject_key=subject,
        context_resolver=resolver,
        policy_engine=engine,
        secret_key=SECRET,
        rewrite_parent_sql=original_sql,
        now=NOW,
    )

    executor = AuthorizationBoundDuckDBExecutor(
        DuckDBExecutor(database), secret_key=SECRET
    )
    result = executor.execute_authorized(
        authorization=authorization,
        sql=safe_sql,
        task_purpose="Find regions with elevated churn risk",
        subject_key=subject,
        context_resolver=resolver,
        policy_engine=engine,
        rewrite_parent_sql=original_sql,
        now=NOW + timedelta(seconds=1),
    )
    assert result.preview_row_count == 3

    wrong_parent = verify_execution_authorization(
        authorization=authorization,
        sql=safe_sql,
        task_purpose="Find regions with elevated churn risk",
        subject_key=subject,
        context_resolver=resolver,
        policy_engine=engine,
        secret_key=SECRET,
        rewrite_parent_sql=original_sql + " ",
        now=NOW + timedelta(seconds=1),
    )
    assert wrong_parent.passed is False
    assert "rewrite_parent" in wrong_parent.failed_checks
