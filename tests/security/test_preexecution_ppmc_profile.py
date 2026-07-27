from __future__ import annotations

import pytest

from tests.unit.test_preexecution_privacy_proof import (
    IDENTITY,
    ISSUED_AT,
    KEY,
    PURPOSE,
    SQL,
    SUBJECT,
    _artifacts,
    _proof,
)
from toxicjoin.execute.proof_binding import (
    ExecutionPrivacyProofBindingError,
    verify_execution_privacy_proof,
)
from toxicjoin.proofs import (
    PreExecutionProofError,
    build_preexecution_privacy_proof,
    compute_preexecution_privacy_proof_hmac,
    compute_preexecution_privacy_proof_sha256,
    verify_preexecution_privacy_proof,
)
from toxicjoin.prospective.forbidden import build_forbidden_predicate_policy
from toxicjoin.prospective.policy_oracle import (
    PolicyEngineLocalOracle,
    build_policy_oracle_governance_context,
)
from toxicjoin.prospective.ppmc import (
    PpmcStatus,
    build_ppmc_search_config,
    check_prospective_privacy,
)
from toxicjoin.sql import analyze_sql


def _weak_bound_ppmc(artifacts):
    policy_engine = artifacts["policy_engine"]
    grammar = artifacts["grammar"]
    context = artifacts["context"]
    oracle = PolicyEngineLocalOracle(
        policy_engine,
        grammar,
        build_policy_oracle_governance_context(
            context.projected_context + context.all_referenced_context
        ),
    )
    return check_prospective_privacy(
        initial_state=artifacts["state"],
        grammar=grammar,
        forbidden_policy=build_forbidden_predicate_policy(
            minimum_group_size=policy_engine.config.minimum_group_size
        ),
        governance_binding=artifacts["trust_binding"],
        local_oracle=oracle,
        config=build_ppmc_search_config(bound=0, max_states=100),
    )


def _resign_with_weak_bound(proof):
    weak_config = build_ppmc_search_config(
        bound=0,
        max_states=proof.ppmc_max_states,
    )
    unsigned = proof.model_copy(
        update={
            "ppmc_bound": 0,
            "ppmc_config_sha256": weak_config.config_sha256,
            "privacy_proof_sha256": "0" * 64,
            "integrity_hmac_sha256": "0" * 64,
        }
    )
    with_content = unsigned.model_copy(
        update={
            "privacy_proof_sha256": compute_preexecution_privacy_proof_sha256(unsigned)
        }
    )
    return with_content.model_copy(
        update={
            "integrity_hmac_sha256": compute_preexecution_privacy_proof_hmac(
                with_content,
                integrity_key=KEY,
            )
        }
    )


def test_preexecution_builder_rejects_weak_ppmc_bound() -> None:
    artifacts = _artifacts()
    weak_ppmc = _weak_bound_ppmc(artifacts)
    assert weak_ppmc.status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND
    assert weak_ppmc.bound == 0

    with pytest.raises(PreExecutionProofError, match="PROOF_PPMC_PROFILE_INVALID"):
        build_preexecution_privacy_proof(
            identity=IDENTITY,
            task_purpose=PURPOSE,
            sql=SQL,
            subject_key=SUBJECT,
            context=artifacts["context"],
            governance_binding=artifacts["governance_binding"],
            evidence_bundle=artifacts["bundle"],
            evidence_validation=artifacts["validation"],
            policy_engine=artifacts["policy_engine"],
            state=artifacts["state"],
            grammar=artifacts["grammar"],
            governance_trust_binding=artifacts["trust_binding"],
            ppmc_result=weak_ppmc,
            integrity_key=KEY,
            issued_at=ISSUED_AT,
        )


def test_proof_verifier_rejects_valid_hmac_with_weak_ppmc_profile() -> None:
    proof, _ = _proof()
    weak_proof = _resign_with_weak_bound(proof)

    result = verify_preexecution_privacy_proof(
        weak_proof,
        integrity_key=KEY,
        now=ISSUED_AT,
    )

    assert result.valid is False
    assert tuple(failure.value for failure in result.failures) == (
        "PROOF_PPMC_PROFILE_INVALID",
    )


def test_execution_verifier_rejects_valid_hmac_with_weak_ppmc_profile() -> None:
    proof, artifacts = _proof()
    weak_proof = _resign_with_weak_bound(proof)
    plan = analyze_sql(SQL)
    decision = artifacts["policy_engine"].evaluate(
        artifacts["context"].to_policy_input(
            task_purpose=PURPOSE,
            query_plan=plan,
            subject_key=SUBJECT,
        )
    )

    with pytest.raises(
        ExecutionPrivacyProofBindingError,
        match="AUTH_PRIVACY_PROOF_PROFILE_INVALID",
    ):
        verify_execution_privacy_proof(
            weak_proof,
            integrity_key=KEY,
            now_epoch_seconds=ISSUED_AT.timestamp(),
            sql=SQL,
            query_plan=plan,
            resolution=artifacts["context"],
            governance_binding=artifacts["governance_binding"],
            policy_engine=artifacts["policy_engine"],
            policy_decision=decision,
            task_purpose=PURPOSE,
            identity=IDENTITY,
            subject_key=SUBJECT,
        )
