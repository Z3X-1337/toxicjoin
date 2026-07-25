"""Real full-chain CPCC candidate validation over DataHub, PolicyEngine, Twin, and PPMC."""

from __future__ import annotations

from datetime import datetime, timezone

from toxicjoin.context.datahub import DataHubSnapshot, DataHubSnapshotContextResolver
from toxicjoin.context.models import ContextResolution
from toxicjoin.disclosure.composition import is_protected_release
from toxicjoin.disclosure.models import DisclosureComposition, DisclosureScope
from toxicjoin.disclosure.semantic import (
    build_semantic_release_from_resolution,
    resolve_governed_subject_domain,
)
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.evidence.datahub import DataHubEvidenceError, build_datahub_evidence_bundle
from toxicjoin.evidence.derivation import (
    DataHubDerivationValidationError,
    validate_datahub_evidence_derivations,
)
from toxicjoin.integrations.datahub_mcp import DataHubMcpSettings
from toxicjoin.models import (
    ColumnContext,
    ColumnRef,
    Decision,
    SensitivityCategory,
)
from toxicjoin.policy import PolicyEngine
from toxicjoin.prospective.forbidden import (
    build_forbidden_predicate_policy,
    build_governance_trust_binding,
)
from toxicjoin.prospective.grammar import (
    DeclaredSnapshotTransition,
    FutureActionKind,
    FutureActionGrammarError,
    build_future_action_grammar_context,
    instantiate_future_action_grammar,
)
from toxicjoin.prospective.policy_oracle import (
    PolicyEngineLocalOracle,
    PolicyOracleSemanticError,
    build_policy_oracle_governance_context,
    policy_decision_sha256,
)
from toxicjoin.prospective.ppmc import (
    PpmcSearchConfig,
    PpmcStatus,
    build_ppmc_search_config,
    check_prospective_privacy,
)
from toxicjoin.prospective.twin import (
    DisclosureHistoryEntry,
    DisclosureTwinError,
    build_disclosure_state,
)
from toxicjoin.repair.compiler import CpccCompileError, compile_cpcc_candidate
from toxicjoin.repair.cpcc import build_cpcc_candidate_validation
from toxicjoin.repair.models import (
    CpccCandidate,
    CpccCandidateValidation,
    CpccValidationOutcome,
    CpccValidationStage,
)
from toxicjoin.sql import SqlAnalysisError, analyze_sql


class CpccFullValidationError(RuntimeError):
    """Raised only when the trusted validator cannot even establish its base contract."""


class DataHubCpccCandidateValidator:
    """Security-side candidate validator implementing the complete frozen CPCC chain.

    The validator is bound to one exact DataHub snapshot, PolicyEngine configuration,
    disclosure-history snapshot, future-action declaration, and warehouse snapshot. It never
    accepts evidence, governance, policy decisions, Twin state, or PPMC results from a candidate.
    """

    def __init__(
        self,
        *,
        original_sql: str,
        task_purpose: str,
        subject_key: ColumnRef,
        snapshot: DataHubSnapshot,
        datahub_settings: DataHubMcpSettings,
        policy_engine: PolicyEngine,
        principal_id: str,
        agent_id: str,
        cohort_hmac_sha256: str,
        warehouse_snapshot_sha256: str,
        audit_history: tuple[DisclosureHistoryEntry, ...] = (),
        relevant_projection_fields=(),
        group_key_fields=(),
        aggregate_allowlist: tuple[str, ...] = (),
        cohort_variant_hmacs: tuple[str, ...] = (),
        snapshot_transitions: tuple[DeclaredSnapshotTransition, ...] = (),
        validation_time: datetime | None = None,
        datahub_max_age_seconds: float = 300.0,
        governance_trusted: bool,
        ppmc_config: PpmcSearchConfig | None = None,
        dialect: str = "duckdb",
    ) -> None:
        self.original_sql = original_sql
        self.task_purpose = task_purpose
        self.subject_key = subject_key
        self.snapshot = DataHubSnapshot.model_validate(snapshot.model_dump(mode="json"))
        self.datahub_settings = datahub_settings
        self.policy_engine = policy_engine
        self.principal_id = principal_id
        self.agent_id = agent_id
        self.cohort_hmac_sha256 = cohort_hmac_sha256
        self.warehouse_snapshot_sha256 = warehouse_snapshot_sha256
        self.audit_history = audit_history
        self.relevant_projection_fields = tuple(relevant_projection_fields)
        self.group_key_fields = tuple(group_key_fields)
        self.aggregate_allowlist = tuple(aggregate_allowlist)
        self.cohort_variant_hmacs = tuple(cohort_variant_hmacs)
        self.snapshot_transitions = tuple(snapshot_transitions)
        self.validation_time = _utc(validation_time or datetime.now(timezone.utc))
        self.datahub_max_age_seconds = float(datahub_max_age_seconds)
        self.governance_trusted = governance_trusted
        self.ppmc_config = ppmc_config or build_ppmc_search_config()
        self.dialect = dialect
        self._resolver = DataHubSnapshotContextResolver(
            self.snapshot,
            max_age_seconds=self.datahub_max_age_seconds,
            clock=lambda: self.validation_time,
        )

        try:
            self._original_plan = analyze_sql(original_sql, dialect=dialect)
            self._original_resolution, _ = self._resolver.resolve_with_governance_binding(
                self._original_plan
            )
        except Exception as exc:
            raise CpccFullValidationError(
                "unable to establish original CPCC query/governance binding"
            ) from exc
        if self._original_resolution.failures:
            raise CpccFullValidationError(
                "original CPCC query does not have complete trusted governance"
            )

    def __call__(self, candidate: CpccCandidate) -> CpccCandidateValidation:
        generated_sql_sha256: str | None = None
        reparsed_plan_sha256: str | None = None
        reground_governance_sha256: str | None = None
        evidence_root_sha256: str | None = None
        local_policy_decision_sha256: str | None = None
        disclosure_state_sha256: str | None = None

        try:
            compiled = compile_cpcc_candidate(
                self.original_sql,
                candidate,
                original_resolution=self._original_resolution,
                subject_key=self.subject_key,
                dialect=self.dialect,
            )
        except CpccCompileError:
            return self._failed(
                candidate,
                CpccValidationOutcome.INELIGIBLE,
                CpccValidationStage.GENERATE,
            )
        except Exception:
            return self._failed(
                candidate,
                CpccValidationOutcome.FAIL_CLOSED,
                CpccValidationStage.GENERATE,
            )
        generated_sql_sha256 = compiled.generated_sql_sha256

        try:
            plan = analyze_sql(compiled.generated_sql, dialect=self.dialect)
            reparsed_plan_sha256 = canonical_json_sha256(plan.model_dump(mode="json"))
        except SqlAnalysisError:
            return self._failed(
                candidate,
                CpccValidationOutcome.FAIL_CLOSED,
                CpccValidationStage.REPARSE,
                generated_sql_sha256=generated_sql_sha256,
            )
        except Exception:
            return self._failed(
                candidate,
                CpccValidationOutcome.FAIL_CLOSED,
                CpccValidationStage.REPARSE,
                generated_sql_sha256=generated_sql_sha256,
            )

        try:
            resolution, governance_binding = self._resolver.resolve_with_governance_binding(plan)
            if resolution.failures:
                return self._failed(
                    candidate,
                    CpccValidationOutcome.FAIL_CLOSED,
                    CpccValidationStage.REGROUND,
                    generated_sql_sha256=generated_sql_sha256,
                    reparsed_plan_sha256=reparsed_plan_sha256,
                )
            reground_governance_sha256 = canonical_json_sha256(
                {
                    "resolution": resolution.model_dump(mode="json"),
                    "governance_binding": governance_binding.model_dump(mode="json"),
                }
            )
        except Exception:
            return self._failed(
                candidate,
                CpccValidationOutcome.FAIL_CLOSED,
                CpccValidationStage.REGROUND,
                generated_sql_sha256=generated_sql_sha256,
                reparsed_plan_sha256=reparsed_plan_sha256,
            )

        try:
            evidence_bundle = build_datahub_evidence_bundle(
                self.snapshot,
                self.datahub_settings,
                max_age_seconds=self.datahub_max_age_seconds,
            )
            derivation = validate_datahub_evidence_derivations(
                evidence_bundle,
                self.snapshot,
                self.datahub_settings,
                max_age_seconds=self.datahub_max_age_seconds,
                now=self.validation_time,
            )
            if derivation.evidence_root_sha256 != evidence_bundle.evidence_root_sha256:
                raise DataHubDerivationValidationError("validated evidence root mismatch")
            evidence_root_sha256 = evidence_bundle.evidence_root_sha256
        except (DataHubEvidenceError, DataHubDerivationValidationError, ValueError):
            return self._failed(
                candidate,
                CpccValidationOutcome.FAIL_CLOSED,
                CpccValidationStage.REBUILD_EVIDENCE,
                generated_sql_sha256=generated_sql_sha256,
                reparsed_plan_sha256=reparsed_plan_sha256,
                reground_governance_sha256=reground_governance_sha256,
            )
        except Exception:
            return self._failed(
                candidate,
                CpccValidationOutcome.FAIL_CLOSED,
                CpccValidationStage.REBUILD_EVIDENCE,
                generated_sql_sha256=generated_sql_sha256,
                reparsed_plan_sha256=reparsed_plan_sha256,
                reground_governance_sha256=reground_governance_sha256,
            )

        try:
            policy_input = resolution.to_policy_input(
                task_purpose=self.task_purpose,
                query_plan=plan,
                subject_key=self.subject_key,
            )
            policy_decision = self.policy_engine.evaluate(policy_input)
            local_policy_decision_sha256 = policy_decision_sha256(policy_decision)
        except Exception:
            return self._failed(
                candidate,
                CpccValidationOutcome.FAIL_CLOSED,
                CpccValidationStage.LOCAL_POLICY,
                generated_sql_sha256=generated_sql_sha256,
                reparsed_plan_sha256=reparsed_plan_sha256,
                reground_governance_sha256=reground_governance_sha256,
                evidence_root_sha256=evidence_root_sha256,
            )
        if policy_decision.decision != Decision.ALLOW:
            return self._failed(
                candidate,
                CpccValidationOutcome.INELIGIBLE,
                CpccValidationStage.LOCAL_POLICY,
                generated_sql_sha256=generated_sql_sha256,
                reparsed_plan_sha256=reparsed_plan_sha256,
                reground_governance_sha256=reground_governance_sha256,
                evidence_root_sha256=evidence_root_sha256,
                local_policy_decision_sha256=local_policy_decision_sha256,
                local_policy_allowed=False,
            )

        governance_commitment_sha256 = canonical_json_sha256(
            governance_binding.model_dump(mode="json")
        )
        purpose_commitment_sha256 = canonical_json_sha256(
            {"task_purpose": self.task_purpose}
        )
        try:
            semantic = build_semantic_release_from_resolution(plan, resolution)
            subject = resolve_governed_subject_domain(
                self.snapshot.catalog,
                subject_key=self.subject_key,
                source_datasets=plan.source_datasets,
            )
            scope = DisclosureScope(
                principal_id=self.principal_id,
                agent_id=self.agent_id,
                subject=subject,
                scope_sha256=canonical_json_sha256(
                    {
                        "principal_id": self.principal_id,
                        "agent_id": self.agent_id,
                        "subject_namespace_sha256": subject.namespace_sha256,
                    }
                ),
            )
            composition = DisclosureComposition(
                protected_release=is_protected_release(semantic),
                release_family_sha256=semantic.semantic_sha256,
                cohort_hmac_sha256=self.cohort_hmac_sha256,
            )
            state = build_disclosure_state(
                scope=scope,
                audit_history=self.audit_history,
                candidate_semantic=semantic,
                candidate_composition=composition,
                purpose_commitment_sha256=purpose_commitment_sha256,
                governance_commitment_sha256=governance_commitment_sha256,
                evidence_root_sha256=evidence_root_sha256,
                warehouse_snapshot_sha256=self.warehouse_snapshot_sha256,
            )
            disclosure_state_sha256 = state.state_sha256
        except Exception:
            return self._failed(
                candidate,
                CpccValidationOutcome.FAIL_CLOSED,
                CpccValidationStage.REBUILD_DISCLOSURE_STATE,
                generated_sql_sha256=generated_sql_sha256,
                reparsed_plan_sha256=reparsed_plan_sha256,
                reground_governance_sha256=reground_governance_sha256,
                evidence_root_sha256=evidence_root_sha256,
                local_policy_decision_sha256=local_policy_decision_sha256,
                local_policy_allowed=True,
            )

        try:
            oracle_governance = self._build_oracle_governance(resolution)
            grammar = instantiate_future_action_grammar(
                build_future_action_grammar_context(
                    base_state=state,
                    base_semantic=semantic,
                    base_composition=composition,
                    relevant_projection_fields=self.relevant_projection_fields,
                    group_key_fields=self.group_key_fields,
                    aggregate_allowlist=self.aggregate_allowlist,
                    cohort_variant_hmacs=self.cohort_variant_hmacs,
                    snapshot_transitions=self.snapshot_transitions,
                )
            )
            oracle = PolicyEngineLocalOracle(
                self.policy_engine,
                grammar,
                oracle_governance,
            )
            replay = next(
                action for action in grammar.actions if action.kind == FutureActionKind.REPLAY
            )
            _, replay_policy_decision, replay_local = oracle.evaluate_release_action(
                state,
                replay,
            )
            if (
                replay_policy_decision.decision != policy_decision.decision
                or replay_policy_decision.reason_codes != policy_decision.reason_codes
                or not replay_local.admissible
            ):
                raise CpccFullValidationError(
                    "direct PolicyEngine and PPMC local-oracle replay decisions diverged"
                )
            trust_binding = build_governance_trust_binding(
                governance_commitment_sha256=governance_commitment_sha256,
                trusted=self.governance_trusted,
                trust_evidence_sha256=canonical_json_sha256(
                    {
                        "policy": "cpcc-datahub-governance-trust-v1",
                        "derivation_validation_sha256": derivation.validation_sha256,
                    }
                ),
            )
            forbidden_policy = build_forbidden_predicate_policy(
                minimum_group_size=self.policy_engine.config.minimum_group_size
            )
            ppmc = check_prospective_privacy(
                initial_state=state,
                grammar=grammar,
                forbidden_policy=forbidden_policy,
                governance_binding=trust_binding,
                local_oracle=oracle,
                config=self.ppmc_config,
            )
        except (FutureActionGrammarError, PolicyOracleSemanticError):
            return self._failed(
                candidate,
                CpccValidationOutcome.FAIL_CLOSED,
                CpccValidationStage.PPMC,
                generated_sql_sha256=generated_sql_sha256,
                reparsed_plan_sha256=reparsed_plan_sha256,
                reground_governance_sha256=reground_governance_sha256,
                evidence_root_sha256=evidence_root_sha256,
                local_policy_decision_sha256=local_policy_decision_sha256,
                local_policy_allowed=True,
                disclosure_state_sha256=disclosure_state_sha256,
            )
        except Exception:
            return self._failed(
                candidate,
                CpccValidationOutcome.FAIL_CLOSED,
                CpccValidationStage.PPMC,
                generated_sql_sha256=generated_sql_sha256,
                reparsed_plan_sha256=reparsed_plan_sha256,
                reground_governance_sha256=reground_governance_sha256,
                evidence_root_sha256=evidence_root_sha256,
                local_policy_decision_sha256=local_policy_decision_sha256,
                local_policy_allowed=True,
                disclosure_state_sha256=disclosure_state_sha256,
            )

        common = {
            "generated_sql_sha256": generated_sql_sha256,
            "reparsed_plan_sha256": reparsed_plan_sha256,
            "reground_governance_sha256": reground_governance_sha256,
            "evidence_root_sha256": evidence_root_sha256,
            "local_policy_decision_sha256": local_policy_decision_sha256,
            "local_policy_allowed": True,
            "disclosure_state_sha256": disclosure_state_sha256,
            "ppmc_result_sha256": ppmc.result_sha256,
            "ppmc_status": ppmc.status,
        }
        if ppmc.status == PpmcStatus.NO_COUNTEREXAMPLE_WITHIN_BOUND:
            return build_cpcc_candidate_validation(
                candidate_sha256=candidate.candidate_sha256,
                outcome=CpccValidationOutcome.ELIGIBLE_SAFE,
                **common,
            )
        if ppmc.status == PpmcStatus.PROSPECTIVE_UNSAFE:
            return build_cpcc_candidate_validation(
                candidate_sha256=candidate.candidate_sha256,
                outcome=CpccValidationOutcome.INELIGIBLE,
                failure_stage=CpccValidationStage.PPMC,
                **common,
            )
        return build_cpcc_candidate_validation(
            candidate_sha256=candidate.candidate_sha256,
            outcome=CpccValidationOutcome.FAIL_CLOSED,
            failure_stage=CpccValidationStage.PPMC,
            **common,
        )

    def _build_oracle_governance(
        self,
        resolution: ContextResolution,
    ):
        contexts: list[ColumnContext] = list(resolution.all_referenced_context)
        needed = (*self.relevant_projection_fields, *self.group_key_fields)
        urn_to_logical = {
            dataset.urn: logical
            for logical, dataset in self.snapshot.catalog.datasets.items()
        }
        for column in needed:
            logical = urn_to_logical.get(column.dataset_urn)
            if logical is None:
                raise PolicyOracleSemanticError(
                    f"declared future field has unknown DataHub dataset: {column.key}"
                )
            dataset = self.snapshot.catalog.datasets[logical]
            field = dataset.fields.get(column.field_path)
            if field is None:
                raise PolicyOracleSemanticError(
                    f"declared future field is absent from DataHub snapshot: {column.key}"
                )
            if field.category != column.category:
                raise PolicyOracleSemanticError(
                    f"declared future field category drift: {column.key}"
                )
            contexts.append(
                ColumnContext(
                    ref=ColumnRef(dataset=logical, field_path=column.field_path),
                    category=field.category,
                    datahub_urn=dataset.urn,
                    tags=field.tags,
                    glossary_terms=field.glossary_terms,
                    lineage_sources=field.lineage_sources,
                    resolved=True,
                )
            )
        return build_policy_oracle_governance_context(tuple(contexts))

    @staticmethod
    def _failed(
        candidate: CpccCandidate,
        outcome: CpccValidationOutcome,
        failure_stage: CpccValidationStage,
        **kwargs,
    ) -> CpccCandidateValidation:
        return build_cpcc_candidate_validation(
            candidate_sha256=candidate.candidate_sha256,
            outcome=outcome,
            failure_stage=failure_stage,
            **kwargs,
        )


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise CpccFullValidationError("CPCC validation time must be timezone-aware")
    return value.astimezone(timezone.utc)
