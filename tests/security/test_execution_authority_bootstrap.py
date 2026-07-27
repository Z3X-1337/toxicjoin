from __future__ import annotations

import pytest

from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog
from toxicjoin.execute import DuckDBExecutor, ExecutionAuthorizer
from toxicjoin.models import ColumnRef
from toxicjoin.pipeline import ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import ReceiptMode, ReceiptStore
from toxicjoin.verify import verify_and_execute


_SUBJECT = ColumnRef(dataset="customers", field_path="customer_id", alias="c")
_SQL = "SELECT c.coarse_region FROM customers c LIMIT 5"


def _resolver() -> FixtureContextResolver:
    return FixtureContextResolver(default_fixture_catalog())


def _engine() -> PolicyEngine:
    return PolicyEngine(load_policy())


def test_pipeline_bootstraps_one_canonical_execution_authority(tmp_path) -> None:
    resolver = _resolver()
    engine = _engine()
    executor = DuckDBExecutor(tmp_path / "unused.duckdb")

    ToxicJoinPipeline(
        context_resolver=resolver,
        policy_engine=engine,
        receipt_store=ReceiptStore(tmp_path / "receipts"),
        mode=ReceiptMode.FIXTURE,
        executor=executor,
    )

    assert executor.authorization_bound is True
    executor.bind_authority(
        context_resolver=resolver,
        policy_engine=engine,
    )

    with pytest.raises(ValueError, match="already bound to a different execution authorizer"):
        executor.bind_authorizer(
            ExecutionAuthorizer(
                context_resolver=resolver,
                policy_engine=engine,
                secret_key=b"replacement-authority-key-at-least-32-bytes",
            )
        )


def test_pipeline_rejects_externally_prebound_executor(tmp_path) -> None:
    resolver = _resolver()
    engine = _engine()
    executor = DuckDBExecutor(tmp_path / "unused.duckdb")
    executor.bind_authorizer(
        ExecutionAuthorizer(
            context_resolver=resolver,
            policy_engine=engine,
            secret_key=b"prebound-authority-key-at-least-32-bytes!!",
        )
    )

    with pytest.raises(ValueError, match="execution authority is pipeline-owned"):
        ToxicJoinPipeline(
            context_resolver=resolver,
            policy_engine=engine,
            receipt_store=ReceiptStore(tmp_path / "receipts"),
            mode=ReceiptMode.FIXTURE,
            executor=executor,
        )


def test_direct_verifier_cannot_bootstrap_unbound_executor(tmp_path) -> None:
    resolver = _resolver()
    engine = _engine()
    executor = DuckDBExecutor(tmp_path / "unused.duckdb")

    result = verify_and_execute(
        _SQL,
        task_purpose="authority bootstrap regression probe",
        subject_key=_SUBJECT,
        context_resolver=resolver,
        policy_engine=engine,
        executor=executor,
        required_minimum_group_size=engine.config.minimum_group_size,
        require_subject_threshold=False,
    )

    assert result.passed is False
    assert result.execution is None
    assert result.execution_attempted is False
    assert executor.authorization_bound is False
    failed = [check for check in result.checks if not check.passed]
    assert failed[-1].name == "execution_authorization"
    assert "no execution authorizer bound" in failed[-1].detail
