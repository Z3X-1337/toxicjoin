from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from toxicjoin.disclosure import (
    DisclosureLedger,
    DisclosureStateTopology,
    DisclosureStateTopologyError,
)


def canonical_sha256(payload: dict[str, object]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def build_evidence(*, source_sha: str, output: Path) -> dict[str, object]:
    if len(source_sha) != 40 or any(ch not in "0123456789abcdef" for ch in source_sha):
        raise ValueError("source_sha must be a full lowercase Git SHA")
    state_topology = DisclosureLedger.state_topology
    if state_topology is not DisclosureStateTopology.SINGLE_NODE:
        raise RuntimeError("canonical disclosure topology unexpectedly changed")
    fail_closed = False
    try:
        DisclosureLedger(
            output.parent / "multi-replica-probe.sqlite3",
            deployment_replica_count=2,
        )
    except DisclosureStateTopologyError as error:
        fail_closed = "shared authoritative disclosure backend" in str(error)
    if not fail_closed:
        raise RuntimeError("multi-replica disclosure topology did not fail closed")
    payload: dict[str, object] = {
        "schema_version": "1.0",
        "source_sha": source_sha,
        "state_topology": state_topology.value,
        "multi_replica_supported": False,
        "multi_replica_fail_closed": True,
        "shared_authoritative_backend": False,
        "postgresql_canonical": False,
        "phase12_required_for_shared_backend": True,
    }
    payload["report_sha256"] = canonical_sha256(payload)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return payload


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate exact-source disclosure topology evidence."
    )
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build_evidence(source_sha=args.source_sha, output=args.output)


if __name__ == "__main__":
    main()
