"""Command-line verifier for HMAC-authenticated pre-execution privacy proofs."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Sequence

from toxicjoin.proofs.preexec import verify_preexecution_privacy_proof

_PROOF_HMAC_ENV = "TOXICJOIN_PRIVACY_PROOF_HMAC_KEY"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="toxicjoin-proof-verify",
        description="Verify one ToxicJoin pre-execution privacy proof JSON artifact.",
    )
    parser.add_argument("proof", type=Path, help="path to the proof JSON file")
    parser.add_argument(
        "--now",
        help="optional timezone-aware ISO-8601 verification time for deterministic replay",
    )
    args = parser.parse_args(argv)

    configured = os.getenv(_PROOF_HMAC_ENV)
    if configured is None or not configured:
        return _emit_cli_error("PROOF_VERIFIER_KEY_UNAVAILABLE")
    integrity_key = configured.encode("utf-8")
    if len(integrity_key) < 32:
        return _emit_cli_error("PROOF_VERIFIER_KEY_TOO_SHORT")

    try:
        raw = json.loads(args.proof.read_text(encoding="utf-8"))
    except OSError:
        return _emit_cli_error("PROOF_FILE_UNREADABLE")
    except json.JSONDecodeError:
        return _emit_cli_error("PROOF_JSON_INVALID")
    if not isinstance(raw, dict):
        return _emit_cli_error("PROOF_JSON_ROOT_INVALID")

    now: datetime | None = None
    if args.now is not None:
        try:
            now = datetime.fromisoformat(args.now.replace("Z", "+00:00"))
        except ValueError:
            return _emit_cli_error("PROOF_VERIFICATION_TIME_INVALID")
        if now.tzinfo is None:
            return _emit_cli_error("PROOF_VERIFICATION_TIME_INVALID")

    result = verify_preexecution_privacy_proof(
        raw,
        integrity_key=integrity_key,
        now=now,
    )
    print(
        json.dumps(
            result.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )
    )
    return 0 if result.valid else 1


def _emit_cli_error(code: str) -> int:
    print(
        json.dumps(
            {"valid": False, "error": code},
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 2


if __name__ == "__main__":  # pragma: no cover - exercised through the console entry point.
    sys.exit(main())
