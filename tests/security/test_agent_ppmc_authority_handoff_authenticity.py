from __future__ import annotations

from pathlib import Path
import runpy

import pytest

from toxicjoin.agent.ppmc_authority import (
    TrustedAgentPpmcEvaluation,
    compute_trusted_agent_ppmc_evaluation_sha256,
)
from toxicjoin.agent.proof_authority import AgentPreExecutionProofAuthorityError
from toxicjoin.auth import bind_request_identity
from toxicjoin.prospective.ppmc import PpmcSearchResult, compute_ppmc_result_sha256

_HELPERS = runpy.run_path(
    str(Path(__file__).with_name("test_agent_preexecution_proof_authority.py"))
)
_upstream = _HELPERS["_upstream"]
_proof_authority = _HELPERS["_proof_authority"]
IDENTITY = _HELPERS["IDENTITY"]
SQL = _HELPERS["SQL"]


def _forge_ppmc_transcript(
    evaluation: TrustedAgentPpmcEvaluation,
) -> TrustedAgentPpmcEvaluation:
    result_payload = evaluation.ppmc_result.model_dump(mode="json")
    result_payload["search_transcript_sha256"] = "f" * 64
    result_payload["result_sha256"] = "0" * 64
    provisional_result = PpmcSearchResult.model_construct(**result_payload)
    result_payload["result_sha256"] = compute_ppmc_result_sha256(provisional_result)
    forged_result = PpmcSearchResult.model_validate(result_payload)

    evaluation_payload = evaluation.model_dump(mode="json")
    evaluation_payload["ppmc_result"] = forged_result.model_dump(mode="json")
    evaluation_payload["ppmc_result_sha256"] = forged_result.result_sha256
    evaluation_payload["evaluation_sha256"] = "0" * 64
    provisional_evaluation = TrustedAgentPpmcEvaluation.model_construct(**evaluation_payload)
    evaluation_payload["evaluation_sha256"] = compute_trusted_agent_ppmc_evaluation_sha256(
        provisional_evaluation
    )
    return TrustedAgentPpmcEvaluation.model_validate(evaluation_payload)


def test_proof_authority_rejects_self_reconstructed_ppmc_authority_artifact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, proposal, evaluation, authenticated_ppmc, state, grammar = _upstream(monkeypatch)
    original_ppmc = authenticated_ppmc.evaluation
    forged_ppmc = _forge_ppmc_transcript(original_ppmc)

    assert forged_ppmc.ppmc_result_sha256 != original_ppmc.ppmc_result_sha256
    assert (
        forged_ppmc.ppmc_result.search_transcript_sha256
        != original_ppmc.ppmc_result.search_transcript_sha256
    )

    with bind_request_identity(IDENTITY):
        with pytest.raises(
            AgentPreExecutionProofAuthorityError,
            match="AGENT_PROOF_PPMC_AUTHORITY_UNTRUSTED",
        ):
            _proof_authority().build(
                proposal=proposal,
                evaluation=evaluation,
                ppmc_evaluation=forged_ppmc,
                sql=SQL,
                state=state,
                grammar=grammar,
            )
