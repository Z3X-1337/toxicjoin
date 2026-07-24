from __future__ import annotations

import pytest

from toxicjoin.auth import RequestIdentity, bind_request_identity
from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog
from toxicjoin.execute import ExecutionAuthorizationError, ExecutionAuthorizer
from toxicjoin.models import ColumnRef
from toxicjoin.policy import PolicyEngine, load_policy


SQL = "SELECT c.coarse_region FROM customers c LIMIT 5"
TASK = "List coarse regions"
SUBJECT = ColumnRef(dataset="customers", field_path="customer_id", alias="c")
SECRET = b"ToxicJoin identity authorization test key!!"


def test_execution_authorization_is_bound_to_authenticated_identity() -> None:
    authorizer = ExecutionAuthorizer(
        context_resolver=FixtureContextResolver(default_fixture_catalog()),
        policy_engine=PolicyEngine(load_policy()),
        secret_key=SECRET,
    )
    principal_a = RequestIdentity(
        principal_id="principal-a",
        credential_id="credential-a",
        agent_id="agent-a",
        session_id="session-a",
    )
    principal_b = RequestIdentity(
        principal_id="principal-b",
        credential_id="credential-b",
        agent_id="agent-b",
        session_id="session-b",
    )

    with bind_request_identity(principal_a):
        authorization = authorizer.issue(
            SQL,
            task_purpose=TASK,
            subject_key=SUBJECT,
        )

    with bind_request_identity(principal_b):
        with pytest.raises(
            ExecutionAuthorizationError,
            match="AUTH_IDENTITY_MISMATCH",
        ):
            authorizer.verify_and_consume(
                authorization,
                SQL,
                task_purpose=TASK,
                subject_key=SUBJECT,
            )

    with bind_request_identity(principal_a):
        plan = authorizer.verify_and_consume(
            authorization,
            SQL,
            task_purpose=TASK,
            subject_key=SUBJECT,
        )

    assert {ref.key for ref in plan.projected_columns} == {"customers.coarse_region"}
