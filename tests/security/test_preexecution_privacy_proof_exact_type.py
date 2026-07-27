from __future__ import annotations

from datetime import timedelta
from pathlib import Path
import runpy

import pytest

from toxicjoin.auth import bind_request_identity
from toxicjoin.proofs import (
    AgentPpmcProofBinding,
    PreExecutionPrivacyProof,
    ProofVerificationFailure,
    RepairProofBinding,
    compute_preexecution_privacy_proof_hmac,
    compute_preexecution_privacy_proof_sha256,
    verify_preexecution_privacy_proof,
)

_HELPERS = runpy.run_path(
    str(Path(__file__).with_name("test_agent_preexecution_proof_authority.py"))
)
_upstream = _HELPERS["_upstream"]
_proof_authority = _HELPERS["_proof_authority"]
IDENTITY = _HELPERS["IDENTITY"]
SQL = _HELPERS["SQL"]
PROOF_KEY = _HELPERS["PROOF_KEY"]
NOW = _HELPERS["NOW"]


def _valid_agent_proof(monkeypatch: pytest.MonkeyPatch) -> PreExecutionPrivacyProof:
    _, proposal, evaluation, ppmc_evaluation, state, grammar = _upstream(monkeypatch)
    with bind_request_identity(IDENTITY):
        return _proof_authority().build(
            proposal=proposal,
            evaluation=evaluation,
            ppmc_evaluation=ppmc_evaluation,
            sql=SQL,
            state=state,
            grammar=grammar,
        )


def _malicious_proof_subclass(
    legitimate: PreExecutionPrivacyProof,
) -> PreExecutionPrivacyProof:
    class MaliciousPrivacyProof(PreExecutionPrivacyProof):
        def model_dump(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
            return legitimate.model_dump(*args, **kwargs)

    return MaliciousPrivacyProof.model_construct(
        **{
            **legitimate.__dict__,
            "disclosure_state_sha256": "f" * 64,
            "ppmc_result_sha256": "e" * 64,
        }
    )


def test_verifier_rejects_privacy_proof_subclass_before_virtual_serialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legitimate = _valid_agent_proof(monkeypatch)
    malicious = _malicious_proof_subclass(legitimate)

    assert malicious.disclosure_state_sha256 != legitimate.disclosure_state_sha256
    assert malicious.ppmc_result_sha256 != legitimate.ppmc_result_sha256

    verification = verify_preexecution_privacy_proof(
        malicious,
        integrity_key=PROOF_KEY,
        now=NOW + timedelta(seconds=6),
    )

    assert verification.valid is False
    assert verification.failures == (ProofVerificationFailure.SCHEMA_INVALID,)


def test_proof_compute_helpers_reject_proof_subclass_before_virtual_serialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legitimate = _valid_agent_proof(monkeypatch)
    malicious = _malicious_proof_subclass(legitimate)

    with pytest.raises(TypeError, match="exact proof model type"):
        compute_preexecution_privacy_proof_sha256(malicious)
    with pytest.raises(TypeError, match="exact proof model type"):
        compute_preexecution_privacy_proof_hmac(
            malicious,
            integrity_key=PROOF_KEY,
        )


def test_verifier_rejects_nested_agent_provenance_subclass_before_dump(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legitimate = _valid_agent_proof(monkeypatch)
    provenance = legitimate.agent_ppmc_provenance
    assert provenance is not None

    class MaliciousProvenance(AgentPpmcProofBinding):
        def model_dump(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
            raise AssertionError("nested virtual serialization must not run")

    malicious_provenance = MaliciousProvenance.model_construct(**provenance.__dict__)
    malicious = PreExecutionPrivacyProof.model_construct(
        **{
            **legitimate.__dict__,
            "agent_ppmc_provenance": malicious_provenance,
        }
    )

    verification = verify_preexecution_privacy_proof(
        malicious,
        integrity_key=PROOF_KEY,
        now=NOW + timedelta(seconds=6),
    )

    assert verification.valid is False
    assert verification.failures == (ProofVerificationFailure.SCHEMA_INVALID,)


def test_verifier_rejects_nested_repair_subclass_before_dump(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legitimate = _valid_agent_proof(monkeypatch)

    class MaliciousRepair(RepairProofBinding):
        def model_dump(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
            raise AssertionError("nested virtual serialization must not run")

    malicious_repair = MaliciousRepair.model_construct(
        cpcc_result_sha256="a" * 64,
        remediation_space_sha256="b" * 64,
        selected_candidate_sha256="c" * 64,
        selected_validation_sha256="d" * 64,
        generated_sql_sha256="e" * 64,
        binding_sha256="f" * 64,
    )
    malicious = PreExecutionPrivacyProof.model_construct(
        **{
            **legitimate.__dict__,
            "repair": malicious_repair,
        }
    )

    verification = verify_preexecution_privacy_proof(
        malicious,
        integrity_key=PROOF_KEY,
        now=NOW + timedelta(seconds=6),
    )

    assert verification.valid is False
    assert verification.failures == (ProofVerificationFailure.SCHEMA_INVALID,)
