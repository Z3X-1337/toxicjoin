"""Fail-closed deployment topology contract for cumulative disclosure state."""

from __future__ import annotations

import os
from enum import StrEnum

_REPLICA_COUNT_ENV = "TOXICJOIN_REPLICA_COUNT"
_MAX_DECLARED_REPLICAS = 10_000


class DisclosureStateTopology(StrEnum):
    """Persistence semantics that matter to cumulative privacy composition."""

    SINGLE_NODE = "SINGLE_NODE"
    SHARED_AUTHORITATIVE = "SHARED_AUTHORITATIVE"


class DisclosureStateTopologyError(RuntimeError):
    """Raised when deployment topology exceeds the guarantees of the configured state backend."""


def resolve_declared_replica_count(value: int | str | None = None) -> int:
    """Return a strict positive deployment replica count.

    ``None`` resolves from ``TOXICJOIN_REPLICA_COUNT`` and defaults to one. The value is a
    deployment declaration, not replica discovery; operators must set it accurately for a
    horizontally scaled restricted/LIVE deployment.
    """

    candidate: object
    if value is None:
        candidate = os.getenv(_REPLICA_COUNT_ENV, "1")
    else:
        candidate = value

    if type(candidate) is int:
        replicas = candidate
    elif type(candidate) is str:
        if not candidate or candidate != candidate.strip() or not candidate.isascii():
            raise DisclosureStateTopologyError("invalid disclosure deployment replica count")
        if not candidate.isdigit():
            raise DisclosureStateTopologyError("invalid disclosure deployment replica count")
        replicas = int(candidate, 10)
    else:
        raise DisclosureStateTopologyError("invalid disclosure deployment replica count")

    if replicas < 1 or replicas > _MAX_DECLARED_REPLICAS:
        raise DisclosureStateTopologyError("invalid disclosure deployment replica count")
    return replicas


def require_disclosure_state_topology(
    *,
    topology: DisclosureStateTopology,
    replica_count: int,
) -> None:
    """Reject a deployment whose replica topology exceeds backend consistency guarantees."""

    if type(topology) is not DisclosureStateTopology:
        raise DisclosureStateTopologyError("invalid disclosure state topology declaration")
    replicas = resolve_declared_replica_count(replica_count)
    if replicas > 1 and topology is not DisclosureStateTopology.SHARED_AUTHORITATIVE:
        raise DisclosureStateTopologyError(
            "multi-replica stateful privacy requires a shared authoritative disclosure backend"
        )
