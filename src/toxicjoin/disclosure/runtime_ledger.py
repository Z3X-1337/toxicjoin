"""Topology-aware public disclosure ledger composition boundary."""

from __future__ import annotations

from toxicjoin.disclosure.secure_ledger import DisclosureLedger as _SQLiteDisclosureLedger
from toxicjoin.disclosure.topology import (
    DisclosureStateTopology,
    require_disclosure_state_topology,
    resolve_declared_replica_count,
)


class DisclosureLedger(_SQLiteDisclosureLedger):
    """Single-node SQLite disclosure authority with an explicit deployment topology gate.

    The underlying SQLite implementation remains the proven local transactional primitive. This
    public composition boundary prevents it from being silently used as authoritative cumulative
    privacy state when the deployment declares more than one application replica.
    """

    state_topology = DisclosureStateTopology.SINGLE_NODE

    def __init__(
        self,
        *args,
        deployment_replica_count: int | str | None = None,
        **kwargs,
    ) -> None:
        replica_count = resolve_declared_replica_count(deployment_replica_count)
        require_disclosure_state_topology(
            topology=self.state_topology,
            replica_count=replica_count,
        )
        super().__init__(*args, **kwargs)
        self.deployment_replica_count = replica_count
