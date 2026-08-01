from __future__ import annotations

import sys
from typing import Any

from phase8_release_manifest import (
    decorate_phase8_claim_boundaries,
    install_phase8_gate,
)
from phase9_release_supply_chain_manifest import (
    decorate_phase9_supply_chain_claim,
    install_phase9_supply_chain_gate,
)

install_phase8_gate()

import generate_release_manifest_v2 as phase7_generator  # noqa: E402

_original_build_release_manifest = phase7_generator.build_release_manifest


def _manifest_mode(argv: list[str]) -> str:
    for index, argument in enumerate(argv):
        if argument == "--mode":
            if index + 1 >= len(argv):
                raise ValueError("--mode requires a value")
            return argv[index + 1]
        if argument.startswith("--mode="):
            return argument.partition("=")[2]
    raise ValueError("--mode is required")


def build_release_manifest_with_phase8(**kwargs: Any) -> dict[str, Any]:
    manifest = _original_build_release_manifest(**kwargs)
    manifest = decorate_phase8_claim_boundaries(manifest)
    return decorate_phase9_supply_chain_claim(
        manifest,
        mode=str(kwargs["mode"]),
    )


def main() -> None:
    mode = _manifest_mode(sys.argv[1:])
    install_phase9_supply_chain_gate(mode=mode)
    phase7_generator.build_release_manifest = build_release_manifest_with_phase8
    phase7_generator.main()


if __name__ == "__main__":
    main()
