from __future__ import annotations

import inspect

from toxicjoin.execute import ProofBoundExecutionAuthorizer


def test_strict_execution_authority_has_security_owned_warehouse_snapshot_source() -> None:
    """The execution verifier must be able to rebind the proof to the live warehouse snapshot.

    PPMC commits ``warehouse_snapshot_sha256`` through DisclosureState and the pre-execution
    proof carries that commitment.  A strict execution authority that cannot independently
    obtain the current warehouse snapshot has no way to reject a proof after an unmodelled
    warehouse change between proof issuance and execution.
    """

    parameters = inspect.signature(ProofBoundExecutionAuthorizer.__init__).parameters

    assert "warehouse_snapshot_provider" in parameters, (
        "strict proof-bound execution has no security-owned warehouse snapshot source; "
        "proof/runtime snapshot TOCTOU cannot be revalidated"
    )
