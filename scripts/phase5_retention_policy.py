from __future__ import annotations

from typing import Final

PHASE5_ARTIFACT_NAME: Final = "phase5-exact-sha-live-datahub-evidence"
PHASE5_RETENTION_MODE: Final = "digest-indexed-release-asset-in-phase9"
PHASE5_CREDENTIAL_REFLECTION_LIMIT: Final = 0


def phase5_retention_claim() -> dict[str, object]:
    """Return the non-secret retention boundary for Live DataHub evidence."""
    return {
        "artifact_name": PHASE5_ARTIFACT_NAME,
        "retention_mode": PHASE5_RETENTION_MODE,
        "credential_reflection_limit": PHASE5_CREDENTIAL_REFLECTION_LIMIT,
        "raw_credentials_retained": False,
    }
