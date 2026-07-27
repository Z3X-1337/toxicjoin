from __future__ import annotations

import pytest

from toxicjoin.agent.proof_handoff import (
    AgentProofHandoffAuthorityError,
    DataHubAgentProofHandoffAuthority,
)


def test_handoff_constructor_failure_clears_secret_traceback_locals() -> None:
    marker = b"phase6-traceback-secret-marker-32-bytes!!"

    with pytest.raises(
        AgentProofHandoffAuthorityError,
        match="AGENT_PROOF_INTEGRITY_KEY_INVALID",
    ) as captured:
        DataHubAgentProofHandoffAuthority(
            integrity_key=marker,
            provenance_integrity_key=marker,
        )

    error = captured.value
    assert error.__context__ is None
    assert error.__cause__ is None

    traceback = error.__traceback__
    inspected = 0
    while traceback is not None:
        frame = traceback.tb_frame
        if frame.f_code.co_filename.endswith("toxicjoin/agent/proof_handoff.py"):
            inspected += 1
            rendered = "\n".join(repr(value) for value in frame.f_locals.values())
            assert "phase6-traceback-secret-marker" not in rendered
        traceback = traceback.tb_next

    assert inspected >= 1
