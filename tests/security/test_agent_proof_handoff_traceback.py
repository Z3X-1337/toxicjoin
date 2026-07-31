from __future__ import annotations

import os

import pytest

from toxicjoin.agent import proof_handoff as proof_handoff_module
from toxicjoin.agent.proof_handoff import (
    AgentProofHandoffAuthorityError,
    DataHubAgentProofHandoffAuthority,
)


def _canonical_code_path(value: str | os.PathLike[str]) -> str:
    return os.path.normcase(os.path.realpath(os.fspath(value)))


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

    source_file = proof_handoff_module.__file__
    assert source_file is not None
    target = _canonical_code_path(source_file)
    traceback = error.__traceback__
    target_functions: list[str] = []
    while traceback is not None:
        frame = traceback.tb_frame
        if _canonical_code_path(frame.f_code.co_filename) == target:
            target_functions.append(frame.f_code.co_name)
            rendered = "\n".join(repr(value) for value in frame.f_locals.values())
            assert "phase6-traceback-secret-marker" not in rendered
        traceback = traceback.tb_next

    assert target_functions, "traceback invariant inspected zero real proof_handoff frames"
    assert "__init__" in target_functions
