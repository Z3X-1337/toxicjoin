from __future__ import annotations

import pytest

from toxicjoin.proofs.agent_handoff import (
    AgentPreExecutionProofCapsule,
    compute_agent_preexecution_proof_capsule_hmac,
    compute_agent_preexecution_proof_capsule_sha256,
)
from toxicjoin.proofs.models import AgentPpmcProofBinding, PreExecutionPrivacyProof

KEY = b"phase6-compute-boundary-provenance-key!!"


class _ExplosiveAgentPpmcProofBinding(AgentPpmcProofBinding):
    def model_dump(self, *args, **kwargs):
        raise AssertionError("virtual serialization reached")


def _poisoned_capsule() -> AgentPreExecutionProofCapsule:
    provenance = _ExplosiveAgentPpmcProofBinding.model_construct()
    proof = PreExecutionPrivacyProof.model_construct(agent_ppmc_provenance=provenance)
    return AgentPreExecutionProofCapsule.model_construct(proof=proof)


def test_capsule_hash_helper_rejects_nested_subclass_before_model_dump() -> None:
    with pytest.raises(TypeError, match="exact provenance model type"):
        compute_agent_preexecution_proof_capsule_sha256(_poisoned_capsule())


def test_capsule_hmac_helper_rejects_nested_subclass_before_model_dump() -> None:
    with pytest.raises(TypeError, match="exact provenance model type"):
        compute_agent_preexecution_proof_capsule_hmac(
            _poisoned_capsule(),
            integrity_key=KEY,
        )
