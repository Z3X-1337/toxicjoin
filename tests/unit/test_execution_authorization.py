from __future__ import annotations

from dataclasses import dataclass

import pytest

from toxicjoin.context import FixtureCatalog, FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog
from toxicjoin.execute import (
    ExecutionAuthorizationError,
    ExecutionAuthorizer,
)
from toxicjoin.models import ColumnRef
from toxicjoin.policy import PolicyEngine, load_policy


SECRET = b"ToxicJoin execution authorization test key!!"
TASK = "List coarse regions for a bounded preview"
SQL = "SELECT c.coarse_region FROM customers c LIMIT 5"
SUBJECT = ColumnRef(dataset="customers", field_path="customer_id", alias="c")


@dataclass
class MutableResolver:
    delegate: FixtureContextResolver

    def resolve(self, query_plan):
        return self.delegate.resolve(query_plan)


def _resolver() -> FixtureContextResolver:
    return FixtureContextResolver(default_fixture_catalog())


def _engine() -> PolicyEngine:
    return PolicyEngine(load_policy())


def test_authorization_is_exact_and_single_use() -> None:
    now = [1_000.0]
    resolver = _resolver()
    engine = _engine()
    authorizer = ExecutionAuthorizer(
        context_resolver=resolver,
        policy_engine=engine,
        secret_key=SECRET,
        ttl_seconds=5,
        clock=lambda: now[0],
    )
    authorization = authorizer.issue(
        SQL,
        task_purpose=TASK,
        subject_key=SUBJECT,
    )

    plan = authorizer.verify_and_consume(
        authorization,
        SQL,
        task_purpose=TASK,
        subject_key=SUBJECT,
    )
    assert {ref.key for ref in plan.projected_columns} == {"customers.coarse_region"}

    with pytest.raises(ExecutionAuthorizationError, match="AUTH_REPLAYED"):
        authorizer.verify_and_consume(
            authorization,
            SQL,
            task_purpose=TASK,
            subject_key=SUBJECT,
        )


def test_post_authorization_sql_mutation_fails_before_execution() -> None:
    authorizer = ExecutionAuthorizer(
        context_resolver=_resolver(),
        policy_engine=_engine(),
        secret_key=SECRET,
    )
    authorization = authorizer.issue(
        SQL,
        task_purpose=TASK,
        subject_key=SUBJECT,
    )

    with pytest.raises(ExecutionAuthorizationError, match="AUTH_SQL_MISMATCH"):
        authorizer.verify_and_consume(
            authorization,
            SQL + " ",
            task_purpose=TASK,
            subject_key=SUBJECT,
        )


def test_task_subject_and_rewrite_parent_are_bound() -> None:
    authorizer = ExecutionAuthorizer(
        context_resolver=_resolver(),
        policy_engine=_engine(),
        secret_key=SECRET,
    )
    parent_sql = "SELECT c.coarse_region FROM customers c"
    authorization = authorizer.issue(
        SQL,
        task_purpose=TASK,
        subject_key=SUBJECT,
        rewrite_parent_sql=parent_sql,
    )

    with pytest.raises(ExecutionAuthorizationError, match="AUTH_TASK_MISMATCH"):
        authorizer.verify_and_consume(
            authorization,
            SQL,
            task_purpose=TASK + " changed",
            subject_key=SUBJECT,
            rewrite_parent_sql=parent_sql,
        )

    with pytest.raises(ExecutionAuthorizationError, match="AUTH_SUBJECT_MISMATCH"):
        authorizer.verify_and_consume(
            authorization,
            SQL,
            task_purpose=TASK,
            subject_key=ColumnRef(dataset="customers", field_path="customer_id"),
            rewrite_parent_sql=parent_sql,
        )

    with pytest.raises(ExecutionAuthorizationError, match="AUTH_REWRITE_PARENT_MISMATCH"):
        authorizer.verify_and_consume(
            authorization,
            SQL,
            task_purpose=TASK,
            subject_key=SUBJECT,
            rewrite_parent_sql=parent_sql + " ",
        )


def test_governance_context_drift_invalidates_authorization() -> None:
    mutable = MutableResolver(_resolver())
    engine = _engine()
    authorizer = ExecutionAuthorizer(
        context_resolver=mutable,
        policy_engine=engine,
        secret_key=SECRET,
    )
    authorization = authorizer.issue(
        SQL,
        task_purpose=TASK,
        subject_key=SUBJECT,
    )

    payload = default_fixture_catalog().model_dump(mode="json")
    payload["datasets"]["customers"]["fields"]["coarse_region"]["category"] = "UNCLASSIFIED"
    mutable.delegate = FixtureContextResolver(FixtureCatalog.model_validate(payload))

    with pytest.raises(ExecutionAuthorizationError, match="AUTH_CONTEXT_MISMATCH"):
        authorizer.verify_and_consume(
            authorization,
            SQL,
            task_purpose=TASK,
            subject_key=SUBJECT,
        )


def test_policy_drift_invalidates_authorization() -> None:
    resolver = _resolver()
    engine = _engine()
    authorizer = ExecutionAuthorizer(
        context_resolver=resolver,
        policy_engine=engine,
        secret_key=SECRET,
    )
    authorization = authorizer.issue(
        SQL,
        task_purpose=TASK,
        subject_key=SUBJECT,
    )

    engine.config = load_policy().model_copy(
        update={"minimum_group_size": load_policy().minimum_group_size + 1}
    )

    with pytest.raises(ExecutionAuthorizationError, match="AUTH_POLICY_MISMATCH"):
        authorizer.verify_and_consume(
            authorization,
            SQL,
            task_purpose=TASK,
            subject_key=SUBJECT,
        )


def test_expired_and_forged_authorizations_fail_closed() -> None:
    now = [2_000.0]
    authorizer = ExecutionAuthorizer(
        context_resolver=_resolver(),
        policy_engine=_engine(),
        secret_key=SECRET,
        ttl_seconds=2,
        clock=lambda: now[0],
    )
    authorization = authorizer.issue(
        SQL,
        task_purpose=TASK,
        subject_key=SUBJECT,
    )

    forged = authorization.model_copy(update={"mac_sha256": "0" * 64})
    with pytest.raises(ExecutionAuthorizationError, match="AUTH_INVALID_MAC"):
        authorizer.verify_and_consume(
            forged,
            SQL,
            task_purpose=TASK,
            subject_key=SUBJECT,
        )

    now[0] = authorization.expires_at
    with pytest.raises(ExecutionAuthorizationError, match="AUTH_EXPIRED"):
        authorizer.verify_and_consume(
            authorization,
            SQL,
            task_purpose=TASK,
            subject_key=SUBJECT,
        )
