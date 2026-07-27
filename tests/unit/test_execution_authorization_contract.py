from __future__ import annotations

import inspect
from typing import cast

import pytest

from toxicjoin.execute import (
    ExecutionAuthorization,
    ExecutionAuthorizationError,
    ExecutionAuthorizer,
    ProofBoundExecutionAuthorizer,
)
from toxicjoin.execute.authorization import ContextResolver
from toxicjoin.models import ColumnRef
from toxicjoin.policy import PolicyEngine
from toxicjoin.proofs import PreExecutionPrivacyProof

_AUTH_KEY = b"unified-execution-contract-key-32-bytes!!"
_SUBJECT = ColumnRef(dataset="customers", field_path="customer_id")


def _call_contract(method) -> tuple[tuple[str, inspect._ParameterKind, object], ...]:
    signature = inspect.signature(method)
    return tuple(
        (name, parameter.kind, parameter.default)
        for name, parameter in signature.parameters.items()
        if name != "self"
    )


def _legacy_authorizer() -> ExecutionAuthorizer:
    return ExecutionAuthorizer(
        context_resolver=cast(ContextResolver, object()),
        policy_engine=cast(PolicyEngine, object()),
        secret_key=_AUTH_KEY,
    )


def test_legacy_and_proof_bound_issue_share_one_call_contract() -> None:
    assert _call_contract(ExecutionAuthorizer.issue) == _call_contract(
        ProofBoundExecutionAuthorizer.issue
    )


def test_legacy_and_proof_bound_consume_share_one_call_contract() -> None:
    assert _call_contract(ExecutionAuthorizer.verify_and_consume) == _call_contract(
        ProofBoundExecutionAuthorizer.verify_and_consume
    )


def test_legacy_issue_rejects_supplied_privacy_proof_before_authority_state() -> None:
    authorizer = _legacy_authorizer()
    proof = cast(PreExecutionPrivacyProof, object())

    with pytest.raises(ExecutionAuthorizationError) as captured:
        authorizer.issue(
            "SELECT 1",
            task_purpose="contract regression probe",
            subject_key=_SUBJECT,
            privacy_proof=proof,
        )

    assert captured.value.code == "AUTH_PRIVACY_PROOF_BINDING_REQUIRED"


def test_legacy_consume_rejects_supplied_privacy_proof_before_capability_state() -> None:
    authorizer = _legacy_authorizer()
    proof = cast(PreExecutionPrivacyProof, object())
    authorization = cast(ExecutionAuthorization, object())

    with pytest.raises(ExecutionAuthorizationError) as captured:
        authorizer.verify_and_consume(
            authorization,
            "SELECT 1",
            task_purpose="contract regression probe",
            subject_key=_SUBJECT,
            privacy_proof=proof,
        )

    assert captured.value.code == "AUTH_PRIVACY_PROOF_BINDING_REQUIRED"
