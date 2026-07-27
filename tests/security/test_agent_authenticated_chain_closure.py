from __future__ import annotations

import inspect
from pathlib import Path
import runpy

import pytest

from toxicjoin.agent.ppmc_authority import DataHubAgentPpmcAuthority
from toxicjoin.agent.proof_authority import (
    AgentPreExecutionProofAuthorityError,
    DataHubAgentPreExecutionProofAuthority,
)
from toxicjoin.auth import bind_request_identity
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.prospective.grammar import (
    DeclaredSnapshotTransition,
    build_future_action_grammar_context,
    instantiate_future_action_grammar,
)
from toxicjoin.prospective.twin import (
    DisclosureState,
    compute_disclosure_state_sha256,
)

_PROOF_HELPERS = runpy.run_path(
    str(Path(__file__).with_name("test_agent_preexecution_proof_authority.py"))
)
_upstream = _PROOF_HELPERS["_upstream"]
_proof_authority = _PROOF_HELPERS["_proof_authority"]
IDENTITY = _PROOF_HELPERS["IDENTITY"]
SQL = _PROOF_HELPERS["SQL"]

_AUTHENTICITY_HELPERS = runpy.run_path(
    str(Path(__file__).with_name("test_agent_proposal_evaluation_authority_authenticity.py"))
)
_reconstruct_with_forged_authorized_purpose = _AUTHENTICITY_HELPERS[
    "_reconstruct_with_forged_authorized_purpose"
]


def _valid_state_with_different_snapshot(state: DisclosureState) -> DisclosureState:
    payload = state.model_dump(mode="json")
    payload["warehouse_snapshot_sha256"] = canonical_json_sha256(
        {"warehouse": "phase-9-chain-closure-alternate"}
    )
    payload["state_sha256"] = "0" * 64
    provisional = DisclosureState.model_construct(**payload)
    payload["state_sha256"] = compute_disclosure_state_sha256(provisional)
    return DisclosureState.model_validate(payload)


def test_ppmc_authority_does_not_accept_caller_supplied_f6_clearance_or_oracle() -> None:
    parameters = inspect.signature(DataHubAgentPpmcAuthority.check).parameters

    assert "evaluation" in parameters
    assert "governance_trust" in parameters
    assert "initial_state" in parameters
    assert "grammar" in parameters
    assert "forbidden_policy" in parameters
    assert "f6_clearance" not in parameters
    assert "governance_binding" not in parameters
    assert "local_oracle" not in parameters


def test_proof_authority_rejects_self_consistent_evaluation_not_bound_to_ppmc_capsule(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, proposal, evaluation, ppmc_evaluation, state, grammar = _upstream(monkeypatch)
    forged_evaluation = _reconstruct_with_forged_authorized_purpose(evaluation)

    assert forged_evaluation.proposal_sha256 == evaluation.proposal_sha256
    assert forged_evaluation.evaluation_sha256 != evaluation.evaluation_sha256
    assert ppmc_evaluation.agent_evaluation_sha256 == evaluation.evaluation_sha256

    with bind_request_identity(IDENTITY):
        with pytest.raises(
            AgentPreExecutionProofAuthorityError,
            match="AGENT_PROOF_EVALUATION_MISMATCH",
        ):
            _proof_authority().build(
                proposal=proposal,
                evaluation=forged_evaluation,
                ppmc_evaluation=ppmc_evaluation,
                sql=SQL,
                state=state,
                grammar=grammar,
            )


def test_proof_authority_rejects_valid_state_not_bound_to_ppmc_capsule(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, proposal, evaluation, ppmc_evaluation, state, grammar = _upstream(monkeypatch)
    alternate_state = _valid_state_with_different_snapshot(state)

    assert alternate_state.state_sha256 != state.state_sha256
    assert ppmc_evaluation.disclosure_state_sha256 == state.state_sha256

    with bind_request_identity(IDENTITY):
        with pytest.raises(
            AgentPreExecutionProofAuthorityError,
            match="AGENT_PROOF_STATE_MISMATCH",
        ):
            _proof_authority().build(
                proposal=proposal,
                evaluation=evaluation,
                ppmc_evaluation=ppmc_evaluation,
                sql=SQL,
                state=alternate_state,
                grammar=grammar,
            )


def test_proof_authority_rejects_valid_grammar_not_bound_to_ppmc_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, proposal, evaluation, ppmc_evaluation, state, grammar = _upstream(monkeypatch)
    assert state.warehouse_snapshot_sha256 is not None

    alternate_snapshot = canonical_json_sha256(
        {"warehouse": "phase-9-chain-closure-next"}
    )
    alternate_context = build_future_action_grammar_context(
        base_state=state,
        base_semantic=grammar.context.base_semantic,
        base_composition=grammar.context.base_composition,
        relevant_projection_fields=grammar.context.relevant_projection_fields,
        group_key_fields=grammar.context.group_key_fields,
        aggregate_allowlist=grammar.context.aggregate_allowlist,
        cohort_variant_hmacs=grammar.context.cohort_variant_hmacs,
        snapshot_transitions=(
            DeclaredSnapshotTransition(
                from_snapshot_sha256=state.warehouse_snapshot_sha256,
                to_snapshot_sha256=alternate_snapshot,
            ),
        ),
    )
    alternate_grammar = instantiate_future_action_grammar(alternate_context)

    assert alternate_grammar.context.initial_state_sha256 == state.state_sha256
    assert alternate_grammar.grammar_sha256 != grammar.grammar_sha256
    assert ppmc_evaluation.ppmc_result.grammar_sha256 == grammar.grammar_sha256

    with bind_request_identity(IDENTITY):
        with pytest.raises(
            AgentPreExecutionProofAuthorityError,
            match="AGENT_PROOF_GRAMMAR_MISMATCH",
        ):
            _proof_authority().build(
                proposal=proposal,
                evaluation=evaluation,
                ppmc_evaluation=ppmc_evaluation,
                sql=SQL,
                state=state,
                grammar=alternate_grammar,
            )


def test_proof_authority_surface_requires_authenticated_ppmc_capability() -> None:
    parameters = inspect.signature(DataHubAgentPreExecutionProofAuthority.build).parameters

    assert "ppmc_evaluation" in parameters
    assert "f6_clearance" not in parameters
    assert "ppmc_result" not in parameters
    assert "governance_trust_binding" not in parameters
    assert "local_oracle" not in parameters
