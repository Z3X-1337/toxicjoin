from __future__ import annotations

from typing import Any

from phase8_release_manifest import (
    decorate_phase8_claim_boundaries,
    install_phase8_gate,
)

install_phase8_gate()

import generate_release_manifest_v2 as phase7_generator  # noqa: E402

_original_build_release_manifest = phase7_generator.build_release_manifest


def build_release_manifest_with_phase8(**kwargs: Any) -> dict[str, Any]:
    manifest = _original_build_release_manifest(**kwargs)
    return decorate_phase8_claim_boundaries(manifest)


def main() -> None:
    phase7_generator.build_release_manifest = build_release_manifest_with_phase8
    phase7_generator.main()


if __name__ == "__main__":
    main()
