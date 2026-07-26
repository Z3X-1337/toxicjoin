"""Versioned security-owned trust policies for evidence-aware context."""

from __future__ import annotations

from toxicjoin.evidence.models import (
    DerivationKind,
    EvidencePolicy,
    EvidenceRule,
    EvidenceSource,
)


_DEFAULT_POLICY_VERSION = "0.1.0"
_DATAHUB_GOVERNANCE_POLICY_VERSION = "datahub-governance-v1"


def default_evidence_policy() -> EvidencePolicy:
    """Return the conservative general P0 evidence policy.

    This policy establishes trust only for explicit security-owned mappings,
    deterministic SQL derivation, runtime-observed DataHub/warehouse facts, and
    explicit human-governance assertions. Agent and fuzzy inference are excluded.
    DataHub explicit mappings are deliberately *not* trusted by this general policy.
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


def datahub_governance_evidence_policy() -> EvidencePolicy:
    """Return the narrow security-owned policy for validated DataHub governance bundles.

    The caller must still use a canonical ``DataHubEvidenceBundle`` that is bound to the
    exact trusted snapshot/source and replay-validated. This policy only declares which
    source/derivation pairs are eligible to establish authority inside that already-bound
    bundle. It does not make DataHub metadata objectively true and it never admits Agent
    or fuzzy evidence.
    """

    rules = (
        EvidenceRule(
            source=EvidenceSource.DATAHUB_MCP,
            derivation=DerivationKind.EXPLICIT_MAPPING,
        ),
        EvidenceRule(
            source=EvidenceSource.DATAHUB_MCP,
            derivation=DerivationKind.RUNTIME_OBSERVED,
        ),
    )
    return EvidencePolicy(
        version=_DATAHUB_GOVERNANCE_POLICY_VERSION,
        trusted_rules=tuple(sorted(rules, key=lambda rule: rule.key)),
    )
