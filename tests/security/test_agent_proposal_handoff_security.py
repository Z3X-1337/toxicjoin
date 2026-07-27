from __future__ import annotations

import hashlib
import hmac
import inspect
import json
from pathlib import Path
import runpy

import pytest

from toxicjoin.agent.ppmc_handoff import (
    AgentPpmcEvaluationCapsuleError,
    DataHubAgentPpmcHandoffAuthority,
)
from toxicjoin.agent.proposal_authority import TrustedAgentProposalEvaluation
from toxicjoin.agent.proposal_handoff import (
    AgentProposalEvaluationCapsule,
    AgentProposalEvaluationCapsuleError,
    DataHubAgentProposalHandoffAuthority,
    compute_agent_proposal_evaluation_capsule_hmac,
    compute_agent_proposal_evaluation_capsule_sha256,
    require_agent_proposal_evaluation_capsule,
    seal_agent_proposal_evaluation_capsule,
)
from toxicjoin.agent.governance_trust import DataHubGovernanceTrustAuthority
from toxicjoin.policy import load_policy
from toxicjoin.prospective.forbidden import build_forbidden_predicate_policy

_HELPERS = runpy.run_path(
    str(Path(__file__).with_name("test_agent_preexecution_proof_authority.py"))
)
_upstream = _HELPERS["_upstream"]
PROVENANCE_KEY = _HELPERS["PROVENANCE_KEY"]
NOW = _HELPERS["NOW"]

WRONG_KEY = b"phase-8-wrong-agent-provenance-key-32-bytes!!"


def test_proposal_handoff_authenticates_exact_evaluation_and_rejects_wrong_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, evaluation, _, _, _ = _upstream(monkeypatch)
    capsule = seal_agent_proposal_evaluation_capsule(
        evaluation,
        integrity_key=PROVENANCE_KEY,
    )

    assert require_agent_proposal_evaluation_capsule(
        capsule,
        integrity_key=PROVENANCE_KEY,
    ) is capsule.evaluation

    with pytest.raises(
        AgentProposalEvaluationCapsuleError,
        match="AGENT_PROPOSAL_HANDOFF_UNTRUSTED",
    ):
        require_agent_proposal_evaluation_capsule(capsule, integrity_key=WRONG_KEY)


def test_proposal_handoff_hmac_domain_is_separate_from_ppmc_handoff_domain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, evaluation, _, _, _ = _upstream(monkeypatch)
    capsule = seal_agent_proposal_evaluation_capsule(
        evaluation,
        integrity_key=PROVENANCE_KEY,
    )
    payload = capsule.model_dump(mode="json", exclude={"authority_hmac_sha256"})
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    ppmc_domain_hmac = hmac.new(
        PROVENANCE_KEY,
        b"toxicjoin:agent-ppmc-evaluation-handoff:v1\x00" + encoded,
        hashlib.sha256,
    ).hexdigest()

    assert capsule.authority_hmac_sha256 == compute_agent_proposal_evaluation_capsule_hmac(
        capsule,
        integrity_key=PROVENANCE_KEY,
    )
    assert capsule.authority_hmac_sha256 != ppmc_domain_hmac


def test_proposal_handoff_compute_helpers_reject_nested_evaluation_subclass_before_dump(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, evaluation, _, _, _ = _upstream(monkeypatch)
    capsule = seal_agent_proposal_evaluation_capsule(
        evaluation,
        integrity_key=PROVENANCE_KEY,
    )

    class MaliciousEvaluation(TrustedAgentProposalEvaluation):
        def model_dump(self, *args, **kwargs):  # noqa: ANN002, ANN003, ANN201
            raise AssertionError("virtual serialization must not run")

    malicious = MaliciousEvaluation.model_construct(**evaluation.__dict__)
    nested = AgentProposalEvaluationCapsule.model_construct(
        **{**capsule.__dict__, "evaluation": malicious}
    )

    with pytest.raises(TypeError, match="exact evaluation type"):
        compute_agent_proposal_evaluation_capsule_sha256(nested)
    with pytest.raises(TypeError, match="exact evaluation type"):
        compute_agent_proposal_evaluation_capsule_hmac(
            nested,
            integrity_key=PROVENANCE_KEY,
        )
    with pytest.raises(
        AgentProposalEvaluationCapsuleError,
        match="AGENT_PROPOSAL_HANDOFF_INVALID",
    ):
        require_agent_proposal_evaluation_capsule(
            nested,
            integrity_key=PROVENANCE_KEY,
        )


def test_ppmc_handoff_rejects_raw_proposal_evaluation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, _, evaluation, _, state, grammar = _upstream(monkeypatch)
    governance_trust = DataHubGovernanceTrustAuthority(
        clock=lambda: NOW
    ).bind(evaluation)
    package_policy = load_policy()

    with pytest.raises(
        AgentPpmcEvaluationCapsuleError,
        match="AGENT_PPMC_HANDOFF_PROPOSAL_UNTRUSTED",
    ):
        DataHubAgentPpmcHandoffAuthority(
            provenance_integrity_key=PROVENANCE_KEY,
            clock=lambda: NOW,
        ).check(
            evaluation=evaluation,  # type: ignore[arg-type]
            governance_trust=governance_trust,
            initial_state=state,
            grammar=grammar,
            forbidden_policy=build_forbidden_predicate_policy(
                minimum_group_size=package_policy.minimum_group_size
            ),
        )


def test_proposal_handoff_authority_exposes_evaluate_not_raw_seal() -> None:
    parameters = inspect.signature(DataHubAgentProposalHandoffAuthority.evaluate).parameters

    assert "proposal" in parameters
    assert "goal" in parameters
    assert "planning_context" in parameters
    assert "authorized_task_purpose" in parameters
    assert "subject_key" in parameters
    assert "provenance_integrity_key" not in parameters
    assert not hasattr(DataHubAgentProposalHandoffAuthority, "seal")


def test_proposal_handoff_constructor_clears_key_from_outward_traceback_frames() -> None:
    marker = b"phase-8-short-secret-marker"

    with pytest.raises(AgentProposalEvaluationCapsuleError) as captured:
        DataHubAgentProposalHandoffAuthority(
            snapshot=None,  # type: ignore[arg-type]
            read_settings=None,  # type: ignore[arg-type]
            policy_engine=None,  # type: ignore[arg-type]
            provenance_integrity_key=marker,
        )

    traceback = captured.value.__traceback__
    while traceback is not None:
        frame = traceback.tb_frame
        if frame.f_code.co_filename.endswith("agent/proposal_handoff.py"):
            assert marker not in frame.f_locals.values()
        traceback = traceback.tb_next
    assert captured.value.__context__ is None
    assert captured.value.__cause__ is None
