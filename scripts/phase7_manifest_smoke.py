"""Import smoke for the Phase 7 release-manifest implementation."""

from release_manifest_gate import REQUIRED_WORKFLOWS


def main() -> None:
    if len(REQUIRED_WORKFLOWS) != 11:
        raise SystemExit("unexpected Phase 7 workflow count")


if __name__ == "__main__":
    main()
