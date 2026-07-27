from __future__ import annotations

import pytest

from toxicjoin.execute import (
    ExecutionAuthorizationError,
    ExecutionAuthorizer,
    ProofBoundExecutionAuthorization,
    ProofBoundExecutionAuthorizer,
)
from toxicjoin.models import ColumnRef

EXECUTION_KEY = b"phase15-shared-execution-key-32-bytes!!"
PROOF_KEY = b"phase15-proof-integrity-key-distinct-32-bytes!!"
PROVENANCE_KEY = b"phase15-agent-provenance-key-distinct-32-bytes!!"
SQL = "SELECT 1"
PURPOSE = "phase15 protocol separation"
SUBJECT = ColumnRef(dataset="customers", field_path="customer_id")


def _proof_bound_capability() -> ProofBoundExecutionAuthorization:
    return ProofBoundExecutionAuthorization(
        authorization_id="tj_auth_" + "1" * 32,
        issued_at=1_800_000_000.0,
        expires_at=1_800_000_005.0,
        dialect="duckdb",
        sql_sha256="2" * 64,
        query_plan_sha256="3" * 64,
        context_sha256="4" * 64,
        governance_binding=None,
        policy_sha256="5" * 64,
        policy_decision_sha256="6" * 64,
        task_purpose_sha256="7" * 64,
        request_identity_sha256="8" * 64,
        subject_key=SUBJECT,
        rewrite_parent_sha256=None,
        disclosure_commitment=None,
        privacy_proof_sha256="9" * 64,
        mac_sha256="0" * 64,
    )


def _authorizers() -> tuple[ExecutionAuthorizer, ProofBoundExecutionAuthorizer]:
    legacy = ExecutionAuthorizer(
        context_resolver=object(),
        policy_engine=object(),
        secret_key=EXECUTION_KEY,
        clock=lambda: 1_800_000_000.0,
    )
    proof_bound = ProofBoundExecutionAuthorizer(
        context_resolver=object(),
        policy_engine=object(),
        privacy_proof_integrity_key=PROOF_KEY,
        agent_provenance_integrity_key=PROVENANCE_KEY,
        warehouse_snapshot_provider=lambda: "a" * 64,
        secret_key=EXECUTION_KEY,
        clock=lambda: 1_800_000_000.0,
    )
    return legacy, proof_bound


def test_legacy_and_proof_bound_execution_protocols_have_distinct_mac_domains() -> None:
    """A proof-bound capability must not authenticate as a legacy capability under key reuse."""

    legacy, proof_bound = _authorizers()
    capability = _proof_bound_capability()

    legacy_mac = legacy._mac(capability)
    proof_bound_mac = proof_bound._mac(capability)

    assert legacy_mac != proof_bound_mac, (
        "legacy and proof-bound execution capabilities share one MAC protocol domain; "
        "a proof-bound capability can be reinterpreted by the legacy verifier when the execution "
        "key is reused"
    )


def test_legacy_verifier_rejects_strict_capability_even_when_execution_key_is_reused() -> None:
    """Protocol separation must fail before legacy policy/context processing can reinterpret it."""

    legacy, proof_bound = _authorizers()
    unsigned = _proof_bound_capability()
    capability = unsigned.model_copy(update={"mac_sha256": proof_bound._mac(unsigned)})

    with pytest.raises(ExecutionAuthorizationError, match="AUTH_INVALID_MAC"):
        legacy.verify_and_consume(
            capability,
            SQL,
            task_purpose=PURPOSE,
            subject_key=SUBJECT,
        )
