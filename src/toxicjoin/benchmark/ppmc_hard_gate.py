"""Deterministic Day-8 hard-gate evidence for PolicyEngine + PPMC composition.

The fixture intentionally demonstrates a narrow claim: the existing local PolicyEngine
allows a thresholded sensitive aggregate at the current snapshot, the same local kernel
allows an identical replay, and PPMC still finds an F5 temporal-differencing counterexample
after one declared snapshot advance. This is bounded model evidence, not global privacy proof.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Literal

from pydantic import Field, model_validator

from toxicjoin.context.fixture import (
    FixtureCatalog,
    FixtureContextResolver,
    FixtureDataset,
    FixtureField,
)
from toxicjoin.disclosure.composition import is_protected_release
from toxicjoin.disclosure.models import (
    DisclosureComposition,
    DisclosureScope,
    compute_scope_sha256,
)
from toxicjoin.disclosure.semantic import (
    build_semantic_release_from_resolution,
    resolve_governed_subject_domain,
)
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.models import ColumnRef, Decision, SensitivityCategory, StrictModel
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.prospective.forbidden import (
    ForbiddenPredicateId,
    build_forbidden_predicate_policy,
    build_governance_trust_binding,
)
from toxicjoin.prospective.grammar import (
    DeclaredSnapshotTransition,
    FutureActionKind,
    apply_future_action,
    build_future_action_grammar_context,
    instantiate_future_action_grammar,
)
from toxicjoin.prospective.policy_oracle import (
    PolicyEngineLocalOracle,
    build_policy_oracle_governance_context,
    policy_decision_sha256,
    policy_input_sha256,
)
from toxicjoin.prospective.ppmc import (
    PpmcStatus,
    build_ppmc_search_config,
    check_prospective_privacy,
)
from toxicjoin.prospective.twin import build_disclosure_state
from toxicjoin.sql import analyze_sql

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_GATE_ID = "day8-local-allow-bounded-counterexample-v1"
_SQL = (
    "SELECT COUNT(diagnosis) AS diagnosis_count "
    "FROM patients "
    "HAVING COUNT(DISTINCT customer_id) >= 20"
)
_DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.ppmc_gate,PROD)"
_SNAPSHOT_A = canonical_json_sha256({"snapshot": "ppmc-gate-a"})
_SNAPSHOT_B = canonical_json_sha256({"snapshot": "ppmc-gate-b"})
_PURPOSE = canonical_json_sha256({"purpose": "ppmc-day8-hard-gate"})
_GOVERNANCE = canonical_json_sha256({"governance": "ppmc-day8-hard-gate"})
_EVIDENCE = canonical_json_sha256({"evidence": "ppmc-day8-hard-gate"})
_TRUST_EVIDENCE = canonical_json_sha256({"governance_trust": "ppmc-day8-hard-gate"})
_COHORT = canonical_json_sha256({"cohort": "ppmc-day8-hard-gate"})


class PpmcHardGateError(RuntimeError):
    """Raised when the preregistered Day-8 evidence condition is not demonstrated."""


class PolicyPpmcHardGateEvidence(StrictModel):
    """Canonical machine-readable evidence for the Day-8 PPMC hard gate."""

    schema_version: Literal["1.0"] = "1.0"
    gate_id: Literal["day8-local-allow-bounded-counterexample-v1"] = _GATE_ID
    policy_version: str = Field(min_length=1, max_length=128)
    policy_config_sha256: str = Field(pattern=_HASH_PATTERN)
    governance_context_sha256: str = Field(pattern=_HASH_PATTERN)
    query_plan_sha256: str = Field(pattern=_HASH_PATTERN)
    semantic_sha256: str = Field(pattern=_HASH_PATTERN)
    initial_pipeline_policy_input_sha256: str = Field(pattern=_HASH_PATTERN)
    initial_pipeline_policy_decision_sha256: str = Field(pattern=_HASH_PATTERN)
    initial_policy_decision: Literal["ALLOW"] = "ALLOW"
    initial_policy_reason_codes: tuple[str, ...] = Field(min_length=1, max_length=16)
    adapter_initial_policy_input_sha256: str = Field(pattern=_HASH_PATTERN)
    adapter_initial_policy_decision_sha256: str = Field(pattern=_HASH_PATTERN)
    adapter_initial_local_oracle_sha256: str = Field(pattern=_HASH_PATTERN)
    adapter_initial_reason_codes: tuple[str, ...] = Field(min_length=1, max_length=16)
    future_replay_policy_input_sha256: str = Field(pattern=_HASH_PATTERN)
    future_replay_policy_decision_sha256: str = Field(pattern=_HASH_PATTERN)
    future_replay_local_oracle_sha256: str = Field(pattern=_HASH_PATTERN)
    future_replay_reason_codes: tuple[str, ...] = Field(min_length=1, max_length=16)
    ppmc_result_sha256: str = Field(pattern=_HASH_PATTERN)
    counterexample_trace_sha256: str = Field(pattern=_HASH_PATTERN)
    counterexample_depth: Literal[2] = 2
    counterexample_action_kinds: tuple[FutureActionKind, FutureActionKind]
    matched_predicates: tuple[ForbiddenPredicateId, ...] = Field(min_length=1, max_length=6)
    gate_passed: Literal[True] = True
    evidence_sha256: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_gate_evidence(self) -> "PolicyPpmcHardGateEvidence":
        if self.initial_policy_reason_codes != self.adapter_initial_reason_codes:
            raise ValueError("adapter initial policy reasons differ from the pipeline-style decision")
        if self.initial_policy_reason_codes != self.future_replay_reason_codes:
            raise ValueError("future replay policy reasons differ from the current local decision")
        if self.counterexample_action_kinds != (
            FutureActionKind.SNAPSHOT_ADVANCE,
            FutureActionKind.REPLAY,
        ):
            raise ValueError("Day-8 counterexample must be SNAPSHOT_ADVANCE -> REPLAY")
        if ForbiddenPredicateId.F5_TEMPORAL_DIFFERENCING not in self.matched_predicates:
            raise ValueError("Day-8 counterexample must demonstrate F5 temporal differencing")
        if self.evidence_sha256 != compute_hard_gate_evidence_sha256(self):
            raise ValueError("Day-8 hard-gate evidence hash mismatch")
        return self


def build_ppmc_hard_gate_evidence() -> PolicyPpmcHardGateEvidence:
    """Run the deterministic local-ALLOW / bounded-counterexample experiment."""

    policy = load_policy()
    engine = PolicyEngine(policy)
    if policy.minimum_group_size != 20:
        raise PpmcHardGateError(
            "hard-gate fixture is pinned to the canonical policy minimum_group_size=20"
        )

    catalog = _catalog()
    resolver = FixtureContextResolver(catalog)
    subject_key = ColumnRef(dataset="patients", field_path="customer_id")
    query_plan = analyze_sql(_SQL)
    resolution = resolver.resolve(query_plan)
    if resolution.failures:
        raise PpmcHardGateError(f"hard-gate governance resolution failed: {resolution.failures}")

    pipeline_policy_input = resolution.to_policy_input(
        task_purpose="ppmc-day8-hard-gate",
        query_plan=query_plan,
        subject_key=subject_key,
    )
    initial_decision = engine.evaluate(pipeline_policy_input)
    if initial_decision.decision != Decision.ALLOW:
        raise PpmcHardGateError(
            f"existing local PolicyEngine did not ALLOW the current candidate: "
            f"{initial_decision.decision.value}"
        )

    semantic = build_semantic_release_from_resolution(query_plan, resolution)
    subject = resolve_governed_subject_domain(
        catalog,
        subject_key=subject_key,
        source_datasets=query_plan.source_datasets,
    )
    scope = DisclosureScope(
        principal_id="principal-ppmc-gate",
        agent_id="agent-ppmc-gate",
        subject=subject,
        scope_sha256=compute_scope_sha256(
            principal_id="principal-ppmc-gate",
            agent_id="agent-ppmc-gate",
            subject_namespace_sha256=subject.namespace_sha256,
        ),
    )
    composition = DisclosureComposition(
        protected_release=is_protected_release(semantic),
        release_family_sha256=semantic.semantic_sha256,
        cohort_hmac_sha256=_COHORT,
    )
    if not composition.protected_release:
        raise PpmcHardGateError("hard-gate candidate must be a protected release")

    state = build_disclosure_state(
        scope=scope,
        audit_history=(),
        candidate_semantic=semantic,
        candidate_composition=composition,
        purpose_commitment_sha256=_PURPOSE,
        governance_commitment_sha256=_GOVERNANCE,
        evidence_root_sha256=_EVIDENCE,
        warehouse_snapshot_sha256=_SNAPSHOT_A,
    )
    grammar = instantiate_future_action_grammar(
        build_future_action_grammar_context(
            base_state=state,
            base_semantic=semantic,
            base_composition=composition,
            snapshot_transitions=(
                DeclaredSnapshotTransition(
                    from_snapshot_sha256=_SNAPSHOT_A,
                    to_snapshot_sha256=_SNAPSHOT_B,
                ),
            ),
        )
    )
    governance = build_policy_oracle_governance_context(
        resolution.projected_context + resolution.all_referenced_context
    )
    oracle = PolicyEngineLocalOracle(engine, grammar, governance)
    replay = _single_action(grammar, FutureActionKind.REPLAY)
    snapshot_advance = _single_action(grammar, FutureActionKind.SNAPSHOT_ADVANCE)

    adapter_initial_input, adapter_initial_decision, adapter_initial_local = (
        oracle.evaluate_release_action(state, replay)
    )
    _require_same_local_decision(initial_decision, adapter_initial_decision, "initial adapter")
    if not adapter_initial_local.admissible:
        raise PpmcHardGateError("PolicyEngine adapter rejected the current replay")

    snapshot_state = apply_future_action(state, snapshot_advance, grammar)
    future_input, future_decision, future_local = oracle.evaluate_release_action(
        snapshot_state,
        replay,
    )
    _require_same_local_decision(initial_decision, future_decision, "future replay")
    if not future_local.admissible:
        raise PpmcHardGateError("existing PolicyEngine rejected the future identical replay")

    forbidden_policy = build_forbidden_predicate_policy(
        minimum_group_size=policy.minimum_group_size
    )
    governance_binding = build_governance_trust_binding(
        governance_commitment_sha256=_GOVERNANCE,
        trusted=True,
        trust_evidence_sha256=_TRUST_EVIDENCE,
    )
    ppmc = check_prospective_privacy(
        initial_state=state,
        grammar=grammar,
        forbidden_policy=forbidden_policy,
        governance_binding=governance_binding,
        local_oracle=oracle,
        config=build_ppmc_search_config(bound=3, max_states=100),
    )
    if ppmc.status != PpmcStatus.PROSPECTIVE_UNSAFE or ppmc.counterexample is None:
        raise PpmcHardGateError(
            f"PPMC did not produce the required bounded counterexample: {ppmc.status.value}"
        )
    trace = ppmc.counterexample
    action_by_sha = {action.action_sha256: action for action in grammar.actions}
    action_kinds = tuple(action_by_sha[step.action_sha256].kind for step in trace.steps)
    if len(trace.steps) != 2:
        raise PpmcHardGateError(
            f"Day-8 counterexample depth drifted from 2 to {len(trace.steps)}"
        )
    if trace.steps[1].local_oracle_commitment_sha256 != future_local.decision_sha256:
        raise PpmcHardGateError(
            "counterexample replay step is not bound to the independently checked PolicyEngine ALLOW"
        )

    initial_reasons = tuple(reason.value for reason in initial_decision.reason_codes)
    adapter_reasons = tuple(reason.value for reason in adapter_initial_decision.reason_codes)
    future_reasons = tuple(reason.value for reason in future_decision.reason_codes)
    payload = {
        "policy_version": policy.version,
        "policy_config_sha256": oracle.policy_config_sha256,
        "governance_context_sha256": oracle.governance_context_sha256,
        "query_plan_sha256": canonical_json_sha256(query_plan.model_dump(mode="json")),
        "semantic_sha256": semantic.semantic_sha256,
        "initial_pipeline_policy_input_sha256": policy_input_sha256(pipeline_policy_input),
        "initial_pipeline_policy_decision_sha256": policy_decision_sha256(initial_decision),
        "initial_policy_decision": "ALLOW",
        "initial_policy_reason_codes": initial_reasons,
        "adapter_initial_policy_input_sha256": policy_input_sha256(adapter_initial_input),
        "adapter_initial_policy_decision_sha256": policy_decision_sha256(adapter_initial_decision),
        "adapter_initial_local_oracle_sha256": adapter_initial_local.decision_sha256,
        "adapter_initial_reason_codes": adapter_reasons,
        "future_replay_policy_input_sha256": policy_input_sha256(future_input),
        "future_replay_policy_decision_sha256": policy_decision_sha256(future_decision),
        "future_replay_local_oracle_sha256": future_local.decision_sha256,
        "future_replay_reason_codes": future_reasons,
        "ppmc_result_sha256": ppmc.result_sha256,
        "counterexample_trace_sha256": trace.trace_sha256,
        "counterexample_depth": 2,
        "counterexample_action_kinds": action_kinds,
        "matched_predicates": trace.terminal_matched_predicates,
        "gate_passed": True,
    }
    provisional = PolicyPpmcHardGateEvidence.model_construct(
        **payload,
        evidence_sha256="0" * 64,
    )
    return PolicyPpmcHardGateEvidence(
        **payload,
        evidence_sha256=compute_hard_gate_evidence_sha256(provisional),
    )


def compute_hard_gate_evidence_sha256(evidence: PolicyPpmcHardGateEvidence) -> str:
    return canonical_json_sha256(evidence.model_dump(mode="json", exclude={"evidence_sha256"}))


def write_ppmc_hard_gate_evidence(output_dir: Path) -> PolicyPpmcHardGateEvidence:
    evidence = build_ppmc_hard_gate_evidence()
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "ppmc-hard-gate.json"
    sha_path = output_dir / "ppmc-hard-gate.sha256"
    json_path.write_text(
        json.dumps(evidence.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    sha_path.write_text(evidence.evidence_sha256 + "\n", encoding="utf-8")
    return evidence


def _catalog() -> FixtureCatalog:
    return FixtureCatalog(
        version="ppmc-hard-gate-v1",
        datasets={
            "patients": FixtureDataset(
                urn=_DATASET_URN,
                domain="urn:li:domain:privacy",
                fields={
                    "customer_id": FixtureField(
                        category=SensitivityCategory.STABLE_PSEUDONYM,
                    ),
                    "diagnosis": FixtureField(
                        category=SensitivityCategory.SENSITIVE_ATTRIBUTE,
                    ),
                },
            )
        },
    )


def _single_action(grammar, kind: FutureActionKind):
    matches = [action for action in grammar.actions if action.kind == kind]
    if len(matches) != 1:
        raise PpmcHardGateError(
            f"hard-gate grammar expected one {kind.value} action, received {len(matches)}"
        )
    return matches[0]


def _require_same_local_decision(reference, candidate, label: str) -> None:
    if (
        candidate.decision != reference.decision
        or candidate.reason_codes != reference.reason_codes
        or candidate.policy_version != reference.policy_version
    ):
        raise PpmcHardGateError(f"{label} does not match the existing PolicyEngine decision")
    if candidate.decision != Decision.ALLOW:
        raise PpmcHardGateError(f"{label} is not ALLOW")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate ToxicJoin PPMC Day-8 hard-gate evidence")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("artifacts/ppmc-hard-gate"),
    )
    args = parser.parse_args()
    evidence = write_ppmc_hard_gate_evidence(args.output_dir)
    print(
        json.dumps(
            {
                "gate_id": evidence.gate_id,
                "gate_passed": evidence.gate_passed,
                "policy_version": evidence.policy_version,
                "counterexample_depth": evidence.counterexample_depth,
                "matched_predicates": [item.value for item in evidence.matched_predicates],
                "evidence_sha256": evidence.evidence_sha256,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
