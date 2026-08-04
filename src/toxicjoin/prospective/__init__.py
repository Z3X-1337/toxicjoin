"""Prospective privacy-model primitives for ToxicJoin vNext.

EXPERIMENTAL — not wired into the HTTP runtime.

Prospective Privacy Model Checking explores what an agent could disclose across *future*
queries using bounded BFS over a Future Action Grammar. It is real code with exact-revision
tests and CI evidence, but no request path invokes it: the shipped pipeline decides on the
query in front of it, not on a search over hypothetical successors.

It stays in-tree because the benchmark hard-gate evidence depends on it and because the
search is the intended next step for the product. `tests/security/test_runtime_module_boundary.py`
enforces this status so it cannot drift silently in either direction.
"""

from toxicjoin.prospective.twin import (
    ColumnExposureRole,
    DisclosureAtom,
    DisclosureAtomKind,
    DisclosureHistoryEntry,
    DisclosureHistoryLifecycle,
    DisclosureInferenceRule,
    DisclosureInferenceRuleFamily,
    DisclosureState,
    DisclosureTwinError,
    build_disclosure_state,
    compute_disclosure_atom_sha256,
    compute_disclosure_inference_rule_sha256,
    compute_disclosure_state_sha256,
    compute_inference_rules_sha256,
    direct_atoms_for_release,
    instantiate_disclosure_inference_rules,
    least_fixed_point,
)

__all__ = [
    "ColumnExposureRole",
    "DisclosureAtom",
    "DisclosureAtomKind",
    "DisclosureHistoryEntry",
    "DisclosureHistoryLifecycle",
    "DisclosureInferenceRule",
    "DisclosureInferenceRuleFamily",
    "DisclosureState",
    "DisclosureTwinError",
    "build_disclosure_state",
    "compute_disclosure_atom_sha256",
    "compute_disclosure_inference_rule_sha256",
    "compute_disclosure_state_sha256",
    "compute_inference_rules_sha256",
    "direct_atoms_for_release",
    "instantiate_disclosure_inference_rules",
    "least_fixed_point",
]
