from __future__ import annotations

import pytest

from toxicjoin.execute import DuckDBExecutor, ExecutionAuthorizer, ExecutionError
from toxicjoin.models import ColumnRef
from toxicjoin.proofs import PreExecutionPrivacyProof


def test_executor_rejects_privacy_proof_with_legacy_authorizer_before_dispatch(tmp_path) -> None:
    executor = DuckDBExecutor(tmp_path / "unused.duckdb")
    executor.bind_authorizer(
        ExecutionAuthorizer(
            context_resolver=object(),
            policy_engine=object(),
            secret_key=b"legacy-authorization-key-at-least-32-bytes",
            clock=lambda: 1_800_000_000.0,
        )
    )
    proof = PreExecutionPrivacyProof.model_construct()

    with pytest.raises(
        ExecutionError,
        match="AUTH_PRIVACY_PROOF_BINDING_REQUIRED",
    ):
        executor.issue_authorization(
            "SELECT 1",
            task_purpose="dispatch guard",
            subject_key=ColumnRef(dataset="patients", field_path="customer_id"),
            privacy_proof=proof,
        )
