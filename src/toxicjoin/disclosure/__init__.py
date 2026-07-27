"""Stateful disclosure-history primitives for cumulative privacy enforcement."""

from toxicjoin.disclosure.composition import (
    DisclosureCompositionError,
    build_composition_metadata,
    canonicalize_cohort_sql,
    evaluate_composition_history,
    is_protected_release,
)
from toxicjoin.disclosure.ledger import (
    DisclosureCommitmentReplay,
    DisclosureLedgerConflict,
    DisclosureLedgerError,
    DisclosureLedgerIntegrityError,
)
from toxicjoin.disclosure.models import (
    CompositionRule,
    DisclosureAuditIdentity,
    DisclosureCommitment,
    DisclosureComposition,
    DisclosureCompositionDecision,
    DisclosureEvent,
    DisclosureRecord,
    DisclosureScope,
    DisclosureSemanticRelease,
    GovernedColumn,
    GovernedSubjectDomain,
    SemanticOutput,
)
from toxicjoin.disclosure.runtime_ledger import DisclosureLedger
from toxicjoin.disclosure.semantic import (
    DisclosureSemanticError,
    build_disclosure_event,
    build_disclosure_event_from_resolver,
    build_disclosure_scope,
    build_semantic_release,
    build_semantic_release_from_resolution,
    resolve_governed_subject_domain,
    resolve_governed_subject_domain_from_resolver,
)
from toxicjoin.disclosure.topology import (
    DisclosureStateTopology,
    DisclosureStateTopologyError,
    require_disclosure_state_topology,
    resolve_declared_replica_count,
)

__all__ = [
    "CompositionRule",
    "DisclosureAuditIdentity",
    "DisclosureCommitment",
    "DisclosureCommitmentReplay",
    "DisclosureComposition",
    "DisclosureCompositionDecision",
    "DisclosureCompositionError",
    "DisclosureEvent",
    "DisclosureLedger",
    "DisclosureLedgerConflict",
    "DisclosureLedgerError",
    "DisclosureLedgerIntegrityError",
    "DisclosureRecord",
    "DisclosureScope",
    "DisclosureSemanticError",
    "DisclosureSemanticRelease",
    "DisclosureStateTopology",
    "DisclosureStateTopologyError",
    "GovernedColumn",
    "GovernedSubjectDomain",
    "SemanticOutput",
    "build_composition_metadata",
    "build_disclosure_event",
    "build_disclosure_event_from_resolver",
    "build_disclosure_scope",
    "build_semantic_release",
    "build_semantic_release_from_resolution",
    "canonicalize_cohort_sql",
    "evaluate_composition_history",
    "is_protected_release",
    "require_disclosure_state_topology",
    "resolve_declared_replica_count",
    "resolve_governed_subject_domain",
    "resolve_governed_subject_domain_from_resolver",
]
