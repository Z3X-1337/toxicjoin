from __future__ import annotations

import argparse
from pathlib import Path

from phase8_evidence_catalog import verify_catalog
from phase8_evidence_common import VerifiedCatalog, VerifiedObject, canonical_json_bytes, sha256_bytes
from phase8_evidence_report import build_proof_report, write_json_atomic
from phase8_evidence_retrieval import retrieve_object

__all__ = [
    "VerifiedCatalog", "VerifiedObject", "build_proof_report",
    "canonical_json_bytes", "retrieve_object", "sha256_bytes", "verify_catalog",
]


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify and retrieve ToxicJoin durable content-addressed evidence."
    )
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--catalog", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--checked-out-sha", required=True)
    parser.add_argument("--retrieve-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    catalog = verify_catalog(root=args.root, catalog_path=args.catalog)
    primary = str(catalog.payload["primary_retrieval_sha256"])
    retrieved_path = args.retrieve_dir / f"{primary}.json"
    retrieved = retrieve_object(catalog=catalog, digest=primary, destination=retrieved_path)
    command = (
        "python scripts/phase8_durable_evidence.py --root . "
        "--catalog evidence/retained/catalog.json --source-sha $PHASE8_SOURCE_SHA "
        "--checked-out-sha $(git rev-parse HEAD) --retrieve-dir artifacts/phase8/retrieved "
        "--output artifacts/phase8/phase8-retention-proof.json"
    )
    report = build_proof_report(
        source_sha=args.source_sha, checked_out_sha=args.checked_out_sha,
        catalog=catalog, retrieved=retrieved, retrieved_path=retrieved_path, command=command,
    )
    write_json_atomic(args.output, report)


if __name__ == "__main__":
    main()
