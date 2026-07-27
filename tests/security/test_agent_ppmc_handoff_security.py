from __future__ import annotations

import inspect
from pathlib import Path
import runpy

import pytest

from toxicjoin.agent.ppmc_authority import TrustedAgentPpmcEvaluation
from toxicjoin.agent.ppmc_handoff import (
    AgentPpmcEvaluationCapsule,
    AgentPpmcEvaluationCapsuleError,
    DataHubAgentPpmcHandoffAuthority,
    compute_agent_ppmc_evaluation_capsule_hmac,
    compute_agent_ppmc_evaluation_capsule_sha256,
    require_agent_ppmc_evaluation_capsule,
)
from toxicjoin.proofs.agent_provenance import compute_agent_ppmc_provenance_hmac

_HELPERS = runpy.run_path(
    str(Path(__file__).with_name("test_agent_preexecution_proof_authority.py"))
)
_upstream = _HELPERS["_upstream"]
PROVENANCE_KEY = _HELPERS["PROVENANCE_KEY"]

WRONG_KEY = b"phase-7-wrong-agent-provenance-key-32-bytes!!"


def test_ppmc_handoff_authenticates_exact_evaluation_and_rejects_wrong_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, _, capsule, _, _ = _upstream(monkeypatch)

    assert require_agent_ppmc_evaluation_capsule(
        capsule,
        integrity_key=PROVENANCE_KEY,
    ) is capsule.evaluation

    with pytest.raises(
        AgentPpmcEvaluationCapsuleError,
        match="AGENT_PPMC_HANDOFF_UNTRUSTED",
    ):
        require_agent_ppmc_evaluation_capsule(capsule, integrity_key=WRONG_KEY)


def test_ppmc_handoff_rejects_post_issue_capsule_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, _, capsule, _, _ = _upstream(monkeypatch)
    mutated = capsule.model_copy(update={"ppmc_result_sha256": "f" * 64})

    with pytest.raises(
        AgentPpmcEvaluationCapsuleError,
        match="AGENT_PPMC_HANDOFF_INVALID",
    ):
        require_agent_ppmc_evaluation_capsule(
            mutated,
            integrity_key=PROVENANCE_KEY,
        )


def test_ppmc_handoff_hmac_domain_is_separate_from_agent_provenance_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, _, capsule, _, _ = _upstream(monkeypatch)
    handoff_hmac = compute_agent_ppmc_evaluation_capsule_hmac(
        capsule,
        integrity_key=PROVENANCE_KEY,
    )
    same_payload_provenance_hmac = compute_agent_ppmc_provenance_hmac(
        capsule.model_dump(mode="json", exclude={"authority_hmac_sha256"}),
        integrity_key=PROVENANCE_KEY,
    )

    assert handoff_hmac == capsule.authority_hmac_sha256
    assert handoff_hmac != same_payload_provenance_hmac


def test_ppmc_handoff_compute_helpers_reject_nested_evaluation_subclass_before_dump(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, _, capsule, _, _ = _upstream(monkeypatch)

    class MaliciousEvaluation(TrustedAgentPpmcEvaluation):
        def model_dump(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
            raise AssertionError("virtual serialization must not run")

    malicious = MaliciousEvaluation.model_construct(**capsule.evaluation.__dict__)
    nested = AgentPpmcEvaluationCapsule.model_construct(
        **{**capsule.__dict__, "evaluation": malicious}
    )

    with pytest.raises(TypeError, match="exact evaluation type"):
        compute_agent_ppmc_evaluation_capsule_sha256(nested)
    with pytest.raises(TypeError, match="exact evaluation type"):
        compute_agent_ppmc_evaluation_capsule_hmac(
            nested,
            integrity_key=PROVENANCE_KEY,
        )
    with pytest.raises(
        AgentPpmcEvaluationCapsuleError,
        match="AGENT_PPMC_HANDOFF_INVALID",
    ):
        require_agent_ppmc_evaluation_capsule(
            nested,
            integrity_key=PROVENANCE_KEY,
        )


def test_ppmc_handoff_authority_exposes_security_owned_check_not_raw_result_builder() -> None:
    parameters = inspect.signature(DataHubAgentPpmcHandoffAuthority.check).parameters
    authority = DataHubAgentPpmcHandoffAuthority(
        provenance_integrity_key=PROVENANCE_KEY,
    )

    assert "evaluation" in parameters
    assert "governance_trust" in parameters
    assert "initial_state" in parameters
    assert "grammar" in parameters
    assert "forbidden_policy" in parameters
    assert "provenance_integrity_key" not in parameters
    assert not hasattr(authority, "build")


def test_ppmc_handoff_constructor_clears_key_from_outward_traceback_frames() -> None:
    marker = b"phase-7-short-secret-marker"

    with pytest.raises(AgentPpmcEvaluationCapsuleError) as captured:
        DataHubAgentPpmcHandoffAuthority(provenance_integrity_key=marker)

    traceback = captured.value.__traceback__
    while traceback is not None:
        frame = traceback.tb_frame
        if frame.f_code.co_filename.endswith("agent/ppmc_handoff.py"):
            assert marker not in frame.f_locals.values()
        traceback = traceback.tb_next
    assert captured.value.__context__ is None
    assert captured.value.__cause__ is None
