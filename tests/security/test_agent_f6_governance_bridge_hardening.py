from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from toxicjoin.agent import (
    DataHubAgentProposalAuthority,
    DataHubGovernanceTrustAuthority,
    GovernedAgent,
    TrustedAgentProposalEvaluation,
    build_agent_data_context_from_snapshot,
    build_agent_goal,
    compute_trusted_agent_proposal_evaluation_sha256,
)
from toxicjoin.agent.f6_governance import (
    DataHubF6GovernanceAuthority,
    F6GovernanceClearanceError,
)
from toxicjoin.agent.governance_trust import (
    GovernanceTrustBinding,
    compute_governance_trust_binding_sha256,
)
from toxicjoin.context.datahub import DataHubSnapshot
from toxicjoin.context.fixture import FixtureCatalog, FixtureDataset, FixtureField
from toxicjoin.disclosure.composition import is_protected_release
from toxicjoin.disclosure.models import DisclosureComposition, DisclosureScope, compute_scope_sha256
from toxicjoin.disclosure.semantic import (
    build_semantic_release_from_resolution,
    resolve_governed_subject_domain,
)
from toxicjoin.evidence import (
    DataHubDerivationValidation,
    DataHubEvidenceBundle,
    DerivationKind,
    build_evidence_claim,
    compute_datahub_derivation_validation_sha256,
    compute_datahub_evidence_root,
)
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.integrations.datahub_authority import read_only_settings_from_env
from toxicjoin.models import ColumnRef, SensitivityCategory
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.prospective.twin import (
    DisclosureState,
    build_disclosure_state,
    compute_disclosure_state_sha256,
)


NOW = datetime(2026, 7, 27, 3, 30, tzinfo=timezone.utc)
DATASET_URN = "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.day13_f6_hardening,PROD)"
PURPOSE = "Count diagnoses with the approved subject threshold"
SQL = (
    "SELECT COUNT(diagnosis) AS diagnosis_count "
    "FROM patients "
    "HAVING COUNT(DISTINCT customer_id) >= 20"
)
SUBJECT_KEY = ColumnRef(dataset="patients", field_path="customer_id")


class _Planner:
    def propose(self, *, goal, context):
        return {"task_purpose": PURPOSE, "sql": SQL}

    def adapt(self, *, goal, context, previous, feedback):
        return self.propose(goal=goal, context=context)


def _snapshot() -> DataHubSnapshot:
    return DataHubSnapshot(
        catalog=FixtureCatalog(
            version="datahub-mcp:day13-f6-hardening-v1",
            datasets={
                "patients": FixtureDataset(
                    urn=DATASET_URN,
                    owner="urn:li:corpuser:unused-owner",
                    fields={
                        "customer_id": FixtureField(
                            category=SensitivityCategory.STABLE_PSEUDONYM,
                            tags=("stable-customer-identifier",),
                        ),
                        "diagnosis": FixtureField(
                            category=SensitivityCategory.SENSITIVE_ATTRIBUTE,
                            tags=("toxicjoin-sensitive-attribute",),
                        ),
                    },
                )
            },
        ),
        verified_entities=(DATASET_URN,),
        field_counts={"patients": 2},
        lineage_sample={"relationships": []},
        discovered_tools=("get_entities", "get_lineage", "list_schema_fields"),
        observed_at=NOW,
    )


def _artifacts(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("DATAHUB_GMS_URL", "https://day13-f6-hardening.example")
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", "day13-f6-hardening-token")
    monkeypatch.setenv("DATAHUB_MCP_COMMAND", "uvx")
    monkeypatch.setenv("DATAHUB_MCP_ARGS", "mcp-server-datahub")
    monkeypatch.setenv("DATAHUB_MCP_TIMEOUT_SECONDS", "30")

    snapshot = _snapshot()
    planning_context = build_agent_data_context_from_snapshot(snapshot)
    goal = build_agent_goal("Count diagnoses without releasing individual records")
    proposal = GovernedAgent(_Planner()).propose(goal=goal, context=planning_context)
    evaluation = DataHubAgentProposalAuthority(
        snapshot=snapshot,
        read_settings=read_only_settings_from_env(),
        policy_engine=PolicyEngine(load_policy()),
        clock=lambda: NOW + timedelta(seconds=1),
        datahub_max_age_seconds=300,
    ).evaluate(
        proposal=proposal,
        goal=goal,
        planning_context=planning_context,
        authorized_task_purpose=PURPOSE,
        subject_key=SUBJECT_KEY,
    )
    binding = DataHubGovernanceTrustAuthority(
        clock=lambda: NOW + timedelta(seconds=2)
    ).bind(evaluation)

    semantic = build_semantic_release_from_resolution(
        evaluation.query_plan,
        evaluation.resolution,
    )
    subject = resolve_governed_subject_domain(
        snapshot.catalog,
        subject_key=SUBJECT_KEY,
        source_datasets=evaluation.query_plan.source_datasets,
    )
    scope = DisclosureScope(
        principal_id="principal-day13-f6-hardening",
        agent_id="agent-day13-f6-hardening",
        subject=subject,
        scope_sha256=compute_scope_sha256(
            principal_id="principal-day13-f6-hardening",
            agent_id="agent-day13-f6-hardening",
            subject_namespace_sha256=subject.namespace_sha256,
        ),
    )
    composition = DisclosureComposition(
        protected_release=is_protected_release(semantic),
        release_family_sha256=semantic.semantic_sha256,
        cohort_hmac_sha256=canonical_json_sha256({"cohort": "day13-f6-hardening"}),
    )
    state = build_disclosure_state(
        scope=scope,
        audit_history=(),
        candidate_semantic=semantic,
        candidate_composition=composition,
        purpose_commitment_sha256=evaluation.authorized_task_purpose_sha256,
        governance_commitment_sha256=canonical_json_sha256(
            evaluation.governance_binding.model_dump(mode="json")
        ),
        evidence_root_sha256=evaluation.evidence_bundle.evidence_root_sha256,
        warehouse_snapshot_sha256=canonical_json_sha256({"warehouse": "day13-f6-hardening"}),
    )
    return evaluation, binding, state


def _rebuild_state_for_evaluation(state: DisclosureState, evaluation) -> DisclosureState:
    provisional = state.model_copy(
        update={
            "governance_commitment_sha256": canonical_json_sha256(
                evaluation.governance_binding.model_dump(mode="json")
            ),
            "evidence_root_sha256": evaluation.evidence_bundle.evidence_root_sha256,
            "state_sha256": "0" * 64,
        }
    )
    return DisclosureState.model_validate(
        provisional.model_copy(
            update={"state_sha256": compute_disclosure_state_sha256(provisional)}
        ).model_dump(mode="json")
    )


def test_self_consistent_governance_catalog_rebinding_is_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluation, binding, state = _artifacts(monkeypatch)
    forged_governance_binding = evaluation.governance_binding.model_copy(
        update={"catalog_version": "datahub-mcp:forged-catalog-v1"}
    )
    forged_governance_sha256 = canonical_json_sha256(
        {
            "resolution": evaluation.resolution.model_dump(mode="json"),
            "binding": forged_governance_binding.model_dump(mode="json"),
        }
    )
    provisional_evaluation = evaluation.model_copy(
        update={
            "governance_binding": forged_governance_binding,
            "governance_sha256": forged_governance_sha256,
            "evaluation_sha256": "0" * 64,
        }
    )
    forged_evaluation = TrustedAgentProposalEvaluation.model_validate(
        provisional_evaluation.model_copy(
            update={
                "evaluation_sha256": compute_trusted_agent_proposal_evaluation_sha256(
                    provisional_evaluation
                )
            }
        ).model_dump(mode="json")
    )
    provisional_binding = binding.model_copy(
        update={
            "evaluation_sha256": forged_evaluation.evaluation_sha256,
            "governance_sha256": forged_evaluation.governance_sha256,
            "binding_sha256": "0" * 64,
        }
    )
    forged_binding = GovernanceTrustBinding.model_validate(
        provisional_binding.model_copy(
            update={
                "binding_sha256": compute_governance_trust_binding_sha256(
                    provisional_binding
                )
            }
        ).model_dump(mode="json")
    )
    forged_state = _rebuild_state_for_evaluation(state, forged_evaluation)

    with pytest.raises(
        F6GovernanceClearanceError,
        match="F6_GOVERNANCE_EVIDENCE_BINDING_MISMATCH",
    ):
        DataHubF6GovernanceAuthority(clock=lambda: NOW + timedelta(seconds=3)).clear(
            evaluation=forged_evaluation,
            governance_trust=forged_binding,
            state=forged_state,
        )


def test_expiry_after_clearance_construction_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluation, binding, state = _artifacts(monkeypatch)
    samples = iter((NOW + timedelta(seconds=299), NOW + timedelta(seconds=301)))

    with pytest.raises(
        F6GovernanceClearanceError,
        match="F6_GOVERNANCE_STALE_AT_ISSUE",
    ):
        DataHubF6GovernanceAuthority(clock=lambda: next(samples)).clear(
            evaluation=evaluation,
            governance_trust=binding,
            state=state,
        )


def test_evaluation_subclass_is_rejected_before_virtual_serialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluation, binding, state = _artifacts(monkeypatch)
    calls: list[str] = []

    class _MaliciousEvaluation(TrustedAgentProposalEvaluation):
        def model_dump(self, *args, **kwargs):
            calls.append("model_dump")
            return super().model_dump(*args, **kwargs)

    attacker = _MaliciousEvaluation.model_validate(evaluation.model_dump(mode="json"))
    calls.clear()

    with pytest.raises(F6GovernanceClearanceError, match="F6_GOVERNANCE_INPUT_INVALID"):
        DataHubF6GovernanceAuthority(clock=lambda: NOW + timedelta(seconds=3)).clear(
            evaluation=attacker,
            governance_trust=binding,
            state=state,
        )

    assert calls == []


def test_dangling_evidence_support_cannot_clear_f6(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evaluation, binding, state = _artifacts(monkeypatch)
    bundle = evaluation.evidence_bundle
    original = next(claim for claim in bundle.claims if claim.predicate == "datahub.owner")
    dangling_support = "evc_" + "f" * 32
    assert dangling_support not in {claim.claim_id for claim in bundle.claims}

    forged_claim = build_evidence_claim(
        subject=original.subject,
        predicate=original.predicate,
        value=original.value,
        source=original.source,
        derivation=original.derivation,
        source_identity=original.source_identity,
        observed_at=original.observed_at,
        expires_at=original.expires_at,
        effective_from=original.effective_from,
        effective_until=original.effective_until,
        complete=original.complete,
        supporting_claim_ids=tuple(
            sorted((*original.supporting_claim_ids, dangling_support))
        ),
    )
    claims = tuple(
        sorted(
            (forged_claim if claim.claim_id == original.claim_id else claim for claim in bundle.claims),
            key=lambda claim: claim.claim_id,
        )
    )
    provisional_bundle = bundle.model_copy(
        update={"claims": claims, "evidence_root_sha256": "0" * 64}
    )
    forged_bundle = DataHubEvidenceBundle.model_validate(
        provisional_bundle.model_copy(
            update={"evidence_root_sha256": compute_datahub_evidence_root(provisional_bundle)}
        ).model_dump(mode="json")
    )

    validation = evaluation.evidence_validation
    provisional_validation = validation.model_copy(
        update={
            "evidence_root_sha256": forged_bundle.evidence_root_sha256,
            "observed_claim_ids": tuple(
                sorted(
                    claim.claim_id
                    for claim in forged_bundle.claims
                    if claim.derivation == DerivationKind.RUNTIME_OBSERVED
                )
            ),
            "mapped_claim_ids": tuple(
                sorted(
                    claim.claim_id
                    for claim in forged_bundle.claims
                    if claim.derivation == DerivationKind.EXPLICIT_MAPPING
                )
            ),
            "validation_sha256": "0" * 64,
        }
    )
    forged_validation = DataHubDerivationValidation.model_validate(
        provisional_validation.model_copy(
            update={
                "validation_sha256": compute_datahub_derivation_validation_sha256(
                    provisional_validation
                )
            }
        ).model_dump(mode="json")
    )

    provisional_evaluation = evaluation.model_copy(
        update={
            "evidence_bundle": forged_bundle,
            "evidence_validation": forged_validation,
            "evaluation_sha256": "0" * 64,
        }
    )
    forged_evaluation = TrustedAgentProposalEvaluation.model_validate(
        provisional_evaluation.model_copy(
            update={
                "evaluation_sha256": compute_trusted_agent_proposal_evaluation_sha256(
                    provisional_evaluation
                )
            }
        ).model_dump(mode="json")
    )
    provisional_binding = binding.model_copy(
        update={
            "evaluation_sha256": forged_evaluation.evaluation_sha256,
            "evidence_root_sha256": forged_bundle.evidence_root_sha256,
            "binding_sha256": "0" * 64,
        }
    )
    forged_binding = GovernanceTrustBinding.model_validate(
        provisional_binding.model_copy(
            update={
                "binding_sha256": compute_governance_trust_binding_sha256(
                    provisional_binding
                )
            }
        ).model_dump(mode="json")
    )
    forged_state = _rebuild_state_for_evaluation(state, forged_evaluation)

    with pytest.raises(
        F6GovernanceClearanceError,
        match="F6_GOVERNANCE_EVIDENCE_SUPPORT_MISSING",
    ):
        DataHubF6GovernanceAuthority(clock=lambda: NOW + timedelta(seconds=3)).clear(
            evaluation=forged_evaluation,
            governance_trust=forged_binding,
            state=forged_state,
        )
