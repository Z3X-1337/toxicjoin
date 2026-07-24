from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

import toxicjoin.verify.governance as governance_verify
from toxicjoin.context.governance import (
    GovernanceContextBinding,
    GovernanceContextStaleError,
)
from toxicjoin.context.models import ContextResolution
from toxicjoin.models import ColumnRef, ReasonCode
from toxicjoin.sql import analyze_sql
from toxicjoin.verify.engine import VerificationResult


class _BindingResolver:
    def __init__(
        self,
        binding: GovernanceContextBinding,
        *,
        current_binding: GovernanceContextBinding | None = None,
        stale_on_current: bool = False,
    ) -> None:
        self.binding = binding
        self.current_binding = current_binding or binding
        self.stale_on_current = stale_on_current
        self.resolution = ContextResolution(
            projected_context=(),
            all_referenced_context=(),
            failures=(),
        )

    def resolve_with_governance_binding(self, query_plan: Any):
        del query_plan
        return self.resolution, self.binding

    def current_governance_binding(self) -> GovernanceContextBinding:
        if self.stale_on_current:
            raise GovernanceContextStaleError("snapshot expired during verification")
        return self.current_binding

    def resolve(self, query_plan: Any) -> ContextResolution:
        del query_plan
        return self.resolution


class _RecordingExecutor:
    def __init__(self) -> None:
        self.bound_resolver: Any | None = None
        self.expected_binding: GovernanceContextBinding | None = None
        self.authorization_calls = 0

    def bind_authority(self, *, context_resolver: Any, **kwargs: Any) -> None:
        del kwargs
        self.bound_resolver = context_resolver

    def issue_authorization(self, sql: str, **kwargs: Any) -> object:
        del sql
        self.authorization_calls += 1
        self.expected_binding = kwargs.get("expected_governance_binding")
        return object()

    def execute_authorized(self, sql: str, **kwargs: Any) -> object:
        raise AssertionError(f"test stub must not execute SQL: {sql!r}, {kwargs!r}")


def _binding(snapshot_byte: str, *, observed_at: datetime) -> GovernanceContextBinding:
    return GovernanceContextBinding(
        source="datahub-mcp",
        snapshot_sha256=snapshot_byte * 64,
        catalog_version="datahub-mcp:test-v1",
        observed_at=observed_at,
        expires_at=observed_at + timedelta(minutes=5),
    )


def _install_verifier_stub(monkeypatch, resolver: _BindingResolver) -> None:
    def fake_verify_and_execute(
        sql: str,
        *,
        context_resolver: Any,
        executor: Any,
        policy_engine: Any,
        task_purpose: str,
        subject_key: ColumnRef,
        dialect: str,
        **kwargs: Any,
    ) -> VerificationResult:
        del kwargs
        plan = analyze_sql(sql, dialect=dialect)
        context_resolver.resolve(plan)
        executor.bind_authority(
            context_resolver=context_resolver,
            policy_engine=policy_engine,
        )
        executor.issue_authorization(
            sql,
            task_purpose=task_purpose,
            subject_key=subject_key,
            dialect=dialect,
        )
        return VerificationResult(
            passed=True,
            query_plan=plan,
            policy_decision=None,
            checks=(),
        )

    monkeypatch.setattr(governance_verify, "_verify_and_execute", fake_verify_and_execute)


def test_verifier_passes_exact_captured_binding_to_authorization(monkeypatch) -> None:
    observed_at = datetime(2026, 7, 25, 18, 0, tzinfo=timezone.utc)
    binding = _binding("a", observed_at=observed_at)
    resolver = _BindingResolver(binding)
    executor = _RecordingExecutor()
    _install_verifier_stub(monkeypatch, resolver)

    result = governance_verify.verify_and_execute(
        "SELECT 1",
        task_purpose="P3-B verifier binding test",
        subject_key=ColumnRef(dataset="customers", field_path="customer_id"),
        context_resolver=resolver,
        policy_engine=object(),
        executor=executor,
        required_minimum_group_size=5,
        require_subject_threshold=False,
    )

    assert result.passed is True
    assert executor.authorization_calls == 1
    assert executor.expected_binding == binding
    assert executor.bound_resolver is resolver


def test_snapshot_replacement_before_authorization_fails_closed(monkeypatch) -> None:
    observed_at = datetime(2026, 7, 25, 18, 0, tzinfo=timezone.utc)
    verification_binding = _binding("a", observed_at=observed_at)
    replacement_binding = _binding("b", observed_at=observed_at + timedelta(seconds=1))
    resolver = _BindingResolver(
        verification_binding,
        current_binding=replacement_binding,
    )
    executor = _RecordingExecutor()
    _install_verifier_stub(monkeypatch, resolver)

    result = governance_verify.verify_and_execute(
        "SELECT 1",
        task_purpose="P3-B drift rejection test",
        subject_key=ColumnRef(dataset="customers", field_path="customer_id"),
        context_resolver=resolver,
        policy_engine=object(),
        executor=executor,
        required_minimum_group_size=5,
        require_subject_threshold=False,
    )

    assert result.passed is False
    assert result.failure_reason_codes == (ReasonCode.DATAHUB_CONTEXT_DRIFT,)
    assert result.execution_attempted is False
    assert executor.authorization_calls == 0


def test_snapshot_expiry_before_authorization_fails_closed(monkeypatch) -> None:
    observed_at = datetime(2026, 7, 25, 18, 0, tzinfo=timezone.utc)
    binding = _binding("a", observed_at=observed_at)
    resolver = _BindingResolver(binding, stale_on_current=True)
    executor = _RecordingExecutor()
    _install_verifier_stub(monkeypatch, resolver)

    result = governance_verify.verify_and_execute(
        "SELECT 1",
        task_purpose="P3-B freshness rejection test",
        subject_key=ColumnRef(dataset="customers", field_path="customer_id"),
        context_resolver=resolver,
        policy_engine=object(),
        executor=executor,
        required_minimum_group_size=5,
        require_subject_threshold=False,
    )

    assert result.passed is False
    assert result.failure_reason_codes == (ReasonCode.DATAHUB_CONTEXT_STALE,)
    assert result.execution_attempted is False
    assert executor.authorization_calls == 0
