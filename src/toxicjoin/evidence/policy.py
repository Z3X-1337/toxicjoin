"""Versioned default trust policy for evidence-aware context."""

from __future__ import annotations

from toxicjoin.evidence.models import (
    DerivationKind,
    EvidencePolicy,
    EvidenceRule,
    EvidenceSource,
)


_DEFAULT_POLICY_VERSION = "0.1.0"


def default_evidence_policy() -> EvidencePolicy:
    """Return the conservative P0 evidence policy.

    This policy establishes trust only for explicit security-owned mappings,
    deterministic SQL derivation, runtime-observed DataHub/warehouse facts, and
    explicit human-governance assertions. Agent and fuzzy inference are excluded.
    """

    rules = (
        EvidenceRule(
            source=EvidenceSource.DATAHUB_MCP,
            derivation=DerivationKind.RUNTIME_OBSERVED,
        ),
        EvidenceRule(
            source=EvidenceSource.HUMAN_GOVERNANCE,
            derivation=DerivationKind.HUMAN_ASSERTED,
        ),
        EvidenceRule(
            source=EvidenceSource.SQL_ANALYZER,
            derivation=DerivationKind.SQL_DERIVED,
        ),
        EvidenceRule(
            source=EvidenceSource.STATIC_MANIFEST,
            derivation=DerivationKind.EXPLICIT_MAPPING,
        ),
        EvidenceRule(
            source=EvidenceSource.WAREHOUSE_RUNTIME,
            derivation=DerivationKind.RUNTIME_OBSERVED,
        ),
    )
    return EvidencePolicy(
        version=_DEFAULT_POLICY_VERSION,
        trusted_rules=tuple(sorted(rules, key=lambda rule: rule.key)),
    )
