"""Security-owned intake that re-establishes authority for one Agent proposal.

The planning Agent is intentionally non-authoritative. This module binds one proposal back to the
exact trusted DataHub snapshot and trusted request scope, independently reparses/regrounds the SQL,
consumes replay-validated DataHub evidence, and runs the unchanged deterministic PolicyEngine.
It is the Day-13 bridge into the later evidence-resolution / Disclosure Twin / PPMC / CPCC /
proof-bound execution chain.
"""

from __future__ import annotations

import math
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import Field, model_validator

from toxicjoin.agent.datahub_discovery import _AgentMetadataSecretGuard
from toxicjoin.agent.models import AgentDataContext, AgentGoal, AgentProposal
from toxicjoin.context.datahub import DataHubSnapshot, DataHubSnapshotContextResolver
from toxicjoin.context.governance import GovernanceContextBinding
from toxicjoin.context.models import ContextResolution
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.evidence.datahub import (
    DataHubEvidenceBundle,
    build_datahub_evidence_bundle,
    datahub_source_identity,
)
from toxicjoin.evidence.derivation import (
    DataHubDerivationValidation,
    validate_datahub_evidence_derivations,
)
from toxicjoin.evidence.models import DerivationKind
from toxicjoin.integrations.datahub_authority import (
    ReadOnlyDataHubMcpSettings,
    read_only_credential_provenance_valid,
)
from toxicjoin.models import (
    ColumnRef,
    PolicyDecision,
    PolicyInput,
    QueryPlan,
    StrictModel,
)
from toxicjoin.policy import PolicyConfig, PolicyEngine
from toxicjoin.sql import analyze_sql

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class AgentProposalAuthorityError(RuntimeError):
    """Stable fail-closed error for security-side Agent proposal intake."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def _detach_exception(error: BaseException) -> None:
    """Remove internal exception chains/tracebacks before crossing the public authority boundary."""

    error.__traceback__ = None
    error.__context__ = None
    error.__cause__ = None
    error.__suppress_context__ = True


class TrustedAgentProposalEvaluation(StrictModel):
    """Canonical security-owned local evaluation of one non-authoritative Agent proposal.

    ``security_authoritative`` means the bindings and local PolicyEngine result were produced by
    security-owned code. It does **not** mean every evidence claim has authorization-facing trust,
    that prospective privacy has been checked, or that execution is authorized. Those states are
    fixed false here and can only be established by later dedicated security-owned stages.
    """

    schema_version: Literal["1.0"] = "1.0"
    proposal_sha256: str = Field(pattern=_HASH_PATTERN)
    goal_sha256: str = Field(pattern=_HASH_PATTERN)
    planning_context_sha256: str = Field(pattern=_HASH_PATTERN)
    source_snapshot_sha256: str = Field(pattern=_HASH_PATTERN)
    authorized_task_purpose: str = Field(min_length=1, max_length=4096)
    authorized_task_purpose_sha256: str = Field(pattern=_HASH_PATTERN)
    subject_key: ColumnRef
    subject_key_sha256: str = Field(pattern=_HASH_PATTERN)
    query_plan: QueryPlan
    query_plan_sha256: str = Field(pattern=_HASH_PATTERN)
    resolution: ContextResolution
    governance_binding: GovernanceContextBinding
    governance_sha256: str = Field(pattern=_HASH_PATTERN)
    evidence_bundle: DataHubEvidenceBundle
    evidence_validation: DataHubDerivationValidation
    policy_input: PolicyInput
    policy_input_sha256: str = Field(pattern=_HASH_PATTERN)
    policy_version: str = Field(min_length=1, max_length=128)
    policy_config_sha256: str = Field(pattern=_HASH_PATTERN)
    policy_decision: PolicyDecision
    policy_decision_sha256: str = Field(pattern=_HASH_PATTERN)
    security_authoritative: Literal[True] = True
    evidence_trust_resolved: Literal[False] = False
    prospective_privacy_checked: Literal[False] = False
    execution_authorized: Literal[False] = False
    evaluation_sha256: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_evaluation(self) -> "TrustedAgentProposalEvaluation":
        if self.authorized_task_purpose != self.authorized_task_purpose.strip():
            raise ValueError("trusted Agent task purpose must be normalized")
        if self.authorized_task_purpose_sha256 != canonical_json_sha256(
            {"task_purpose": self.authorized_task_purpose}
        ):
            raise ValueError("trusted Agent purpose commitment mismatch")
        if self.subject_key_sha256 != canonical_json_sha256(
            self.subject_key.model_dump(mode="json")
        ):
            raise ValueError("trusted Agent subject-key commitment mismatch")
        if self.query_plan_sha256 != canonical_json_sha256(
            self.query_plan.model_dump(mode="json")
        ):
            raise ValueError("trusted Agent query-plan commitment mismatch")
        if self.governance_sha256 != canonical_json_sha256(
            {
                "resolution": self.resolution.model_dump(mode="json"),
                "binding": self.governance_binding.model_dump(mode="json"),
            }
        ):
            raise ValueError("trusted Agent governance commitment mismatch")
        if self.governance_binding.snapshot_sha256 != self.source_snapshot_sha256:
            raise ValueError("trusted Agent governance snapshot mismatch")
        if self.evidence_bundle.snapshot_sha256 != self.source_snapshot_sha256:
            raise ValueError("trusted Agent evidence snapshot mismatch")
        _require_evidence_validation_alignment(
            self.evidence_bundle,
            self.evidence_validation,
        )

        expected_policy_input = self.resolution.to_policy_input(
            task_purpose=self.authorized_task_purpose,
            query_plan=self.query_plan,
            subject_key=self.subject_key,
        )
        if self.policy_input != expected_policy_input:
            raise ValueError("trusted Agent policy input does not match grounded request")
        if self.policy_input_sha256 != canonical_json_sha256(
            self.policy_input.model_dump(mode="json")
        ):
            raise ValueError("trusted Agent policy-input commitment mismatch")
        if self.policy_decision.policy_version != self.policy_version:
            raise ValueError("trusted Agent policy version mismatch")
        if self.policy_decision_sha256 != canonical_json_sha256(
            self.policy_decision.model_dump(mode="json")
        ):
            raise ValueError("trusted Agent policy commitment mismatch")
        if self.evaluation_sha256 != compute_trusted_agent_proposal_evaluation_sha256(self):
            raise ValueError("trusted Agent evaluation hash mismatch")
        return self


class DataHubAgentProposalAuthority:
    """Re-establish local security authority after the planning Agent proposes SQL.

    The constructor accepts a provenance-valid dedicated read credential only while it constructs
    and independently replay-validates the canonical DataHub evidence bundle. It then retains only
    the already-redacted DataHub source identity plus immutable evidence artifacts. Raw endpoint,
    launcher arguments, settings objects, and the live bearer are not retained.

    ``authorized_task_purpose`` is supplied separately to :meth:`evaluate` by the trusted request
    authority. The Agent's planner-authored ``task_purpose`` is never accepted as an authorization
    fact and must exactly match that trusted scope before PolicyEngine evaluation can occur.

    Freshness time is sampled at evaluation start, immediately before artifact construction, and
    once more after the complete artifact has been constructed. Clock samples are monotonic across
    the lifetime of the authority, so rollback between evaluations fails closed instead of extending
    the effective evidence lifetime.

    Evidence replay validation proves derivation/snapshot/source/freshness alignment only. It does
    not resolve authorization-facing EvidenceTrustState. This intake therefore cannot authorize
    execution and cannot claim prospective privacy safety.
    """

    def __init__(
        self,
        *,
        snapshot: DataHubSnapshot,
        read_settings: ReadOnlyDataHubMcpSettings,
        policy_engine: PolicyEngine,
        clock: Callable[[], datetime] | None = None,
        datahub_max_age_seconds: float = 300.0,
        dialect: str = "duckdb",
    ) -> None:
        try:
            if type(datahub_max_age_seconds) not in (int, float):
                raise TypeError("freshness lifetime must be numeric")
            normalized_max_age_seconds = float(datahub_max_age_seconds)
            if (
                not math.isfinite(normalized_max_age_seconds)
                or normalized_max_age_seconds <= 0
                or normalized_max_age_seconds > 3600
            ):
                raise ValueError("freshness lifetime is outside the allowed range")
        except Exception:
            read_settings = None  # type: ignore[assignment]
            snapshot = None  # type: ignore[assignment]
            self = None  # type: ignore[assignment]
            raise AgentProposalAuthorityError("AGENT_AUTHORITY_FRESHNESS_INVALID") from None

        try:
            normalized_dialect = _normalized_nonempty_text(dialect)
        except Exception:
            read_settings = None  # type: ignore[assignment]
            snapshot = None  # type: ignore[assignment]
            self = None  # type: ignore[assignment]
            raise AgentProposalAuthorityError("AGENT_AUTHORITY_DIALECT_INVALID") from None
        if normalized_dialect != "duckdb":
            read_settings = None  # type: ignore[assignment]
            snapshot = None  # type: ignore[assignment]
            self = None  # type: ignore[assignment]
            raise AgentProposalAuthorityError("AGENT_AUTHORITY_DIALECT_INVALID")

        trusted_snapshot = None
        source_identity = None
        evidence_bundle = None
        evidence_validation = None
        secret_guard = None
        source_invalid = False
        try:
            trusted_snapshot = DataHubSnapshot.model_validate(snapshot.model_dump(mode="json"))
            if not read_only_credential_provenance_valid(read_settings):
                raise ValueError("read credential is not an unchanged factory issuance")
            secret_guard = _AgentMetadataSecretGuard.from_runtime_settings(read_settings)
            if not secret_guard.context_is_safe(trusted_snapshot):  # type: ignore[arg-type]
                raise ValueError("DataHub snapshot reflects runtime launch material")
            source_identity = datahub_source_identity(read_settings)
            evidence_bundle = build_datahub_evidence_bundle(
                trusted_snapshot,
                read_settings,
                max_age_seconds=normalized_max_age_seconds,
            )
            if not secret_guard.context_is_safe(evidence_bundle):  # type: ignore[arg-type]
                raise ValueError("DataHub evidence reflects runtime launch material")
            evidence_validation = validate_datahub_evidence_derivations(
                evidence_bundle,
                trusted_snapshot,
                read_settings,
                max_age_seconds=normalized_max_age_seconds,
                now=trusted_snapshot.observed_at,
            )
            _require_evidence_validation_alignment(evidence_bundle, evidence_validation)
        except Exception:
            source_invalid = True

        if source_invalid:
            read_settings = None  # type: ignore[assignment]
            snapshot = None  # type: ignore[assignment]
            trusted_snapshot = None
            source_identity = None
            evidence_bundle = None
            evidence_validation = None
            secret_guard = None
            self = None  # type: ignore[assignment]
            raise AgentProposalAuthorityError("AGENT_AUTHORITY_SOURCE_INVALID") from None

        read_settings = None  # type: ignore[assignment]
        snapshot = None  # type: ignore[assignment]
        secret_guard = None

        try:
            initial_policy_config = PolicyConfig.model_validate(
                policy_engine.config.model_dump(mode="json")
            )
            policy_config_sha256 = canonical_json_sha256(
                initial_policy_config.model_dump(mode="json")
            )
            policy_version = _exact_text(initial_policy_config.version)
        except Exception:
            raise AgentProposalAuthorityError("AGENT_AUTHORITY_POLICY_INVALID") from None

        self._snapshot = trusted_snapshot
        self._source_identity = source_identity
        self._evidence_bundle = evidence_bundle
        self._evidence_validation = evidence_validation
        self._policy_engine_source = policy_engine
        self._policy_config_sha256 = policy_config_sha256
        self._policy_version = policy_version
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._clock_lock = threading.Lock()
        self._last_clock_sample: datetime | None = None
        self._datahub_max_age_seconds = normalized_max_age_seconds
        self._dialect = normalized_dialect

    def evaluate(
        self,
        *,
        proposal: AgentProposal,
        goal: AgentGoal,
        planning_context: AgentDataContext,
        authorized_task_purpose: str,
        subject_key: ColumnRef,
    ) -> TrustedAgentProposalEvaluation:
        """Evaluate one proposal and expose only a stable, sanitized error boundary."""

        stable_code = "AGENT_AUTHORITY_INTERNAL_FAILED"
        try:
            return self._evaluate_impl(
                proposal=proposal,
                goal=goal,
                planning_context=planning_context,
                authorized_task_purpose=authorized_task_purpose,
                subject_key=subject_key,
            )
        except AgentProposalAuthorityError as error:
            stable_code = error.code
            _detach_exception(error)
        except Exception as error:
            _detach_exception(error)

        proposal = None  # type: ignore[assignment]
        goal = None  # type: ignore[assignment]
        planning_context = None  # type: ignore[assignment]
        authorized_task_purpose = None  # type: ignore[assignment]
        subject_key = None  # type: ignore[assignment]
        self = None  # type: ignore[assignment]
        raise AgentProposalAuthorityError(stable_code) from None

    def _evaluate_impl(
        self,
        *,
        proposal: AgentProposal,
        goal: AgentGoal,
        planning_context: AgentDataContext,
        authorized_task_purpose: str,
        subject_key: ColumnRef,
    ) -> TrustedAgentProposalEvaluation:
        current = self._sample_clock()
        self._require_fresh_at(current)

        try:
            current_policy_config = PolicyConfig.model_validate(
                self._policy_engine_source.config.model_dump(mode="json")
            )
            current_policy_sha256 = canonical_json_sha256(
                current_policy_config.model_dump(mode="json")
            )
            current_policy_version = _exact_text(current_policy_config.version)
        except Exception:
            raise AgentProposalAuthorityError("AGENT_AUTHORITY_POLICY_FAILED") from None
        if (
            current_policy_sha256 != self._policy_config_sha256
            or current_policy_version != self._policy_version
        ):
            raise AgentProposalAuthorityError("AGENT_AUTHORITY_POLICY_CHANGED")
        local_policy_engine = PolicyEngine(current_policy_config)

        try:
            trusted_proposal = AgentProposal.model_validate(proposal.model_dump(mode="json"))
            trusted_goal = AgentGoal.model_validate(goal.model_dump(mode="json"))
            trusted_context = AgentDataContext.model_validate(
                planning_context.model_dump(mode="json")
            )
            trusted_subject = ColumnRef.model_validate(subject_key.model_dump(mode="json"))
        except Exception:
            raise AgentProposalAuthorityError("AGENT_AUTHORITY_INPUT_INVALID") from None

        try:
            exact_purpose = _exact_text(authorized_task_purpose)
            normalized_purpose = exact_purpose.strip()
        except Exception:
            raise AgentProposalAuthorityError("AGENT_AUTHORITY_PURPOSE_INVALID") from None
        if (
            not normalized_purpose
            or normalized_purpose != exact_purpose
            or len(normalized_purpose) > 4096
        ):
            raise AgentProposalAuthorityError("AGENT_AUTHORITY_PURPOSE_INVALID")
        if trusted_proposal.goal_sha256 != trusted_goal.goal_sha256:
            raise AgentProposalAuthorityError("AGENT_AUTHORITY_GOAL_BINDING_MISMATCH")
        if trusted_proposal.task_purpose != normalized_purpose:
            raise AgentProposalAuthorityError("AGENT_AUTHORITY_PURPOSE_BINDING_MISMATCH")
        if trusted_proposal.data_context_sha256 != trusted_context.context_sha256:
            raise AgentProposalAuthorityError("AGENT_AUTHORITY_CONTEXT_BINDING_MISMATCH")
        if trusted_context.source_snapshot_sha256 != self._snapshot.snapshot_sha256:
            raise AgentProposalAuthorityError("AGENT_AUTHORITY_SNAPSHOT_BINDING_MISMATCH")

        try:
            query_plan = analyze_sql(trusted_proposal.sql, dialect=self._dialect)
            query_plan_sha256 = canonical_json_sha256(query_plan.model_dump(mode="json"))
        except Exception:
            raise AgentProposalAuthorityError("AGENT_AUTHORITY_SQL_REPARSE_FAILED") from None
        if query_plan_sha256 != trusted_proposal.query_plan_sha256:
            raise AgentProposalAuthorityError("AGENT_AUTHORITY_PLAN_BINDING_MISMATCH")

        try:
            resolver = DataHubSnapshotContextResolver(
                self._snapshot,
                max_age_seconds=self._datahub_max_age_seconds,
                clock=lambda: current,
            )
            resolution, governance_binding = resolver.resolve_with_governance_binding(query_plan)
            if resolution.failures:
                raise ValueError("governance resolution is incomplete")
            if governance_binding.snapshot_sha256 != self._snapshot.snapshot_sha256:
                raise ValueError("governance resolver returned another snapshot")
            governance_sha256 = canonical_json_sha256(
                {
                    "resolution": resolution.model_dump(mode="json"),
                    "binding": governance_binding.model_dump(mode="json"),
                }
            )
        except Exception:
            raise AgentProposalAuthorityError("AGENT_AUTHORITY_GOVERNANCE_FAILED") from None

        try:
            policy_input = resolution.to_policy_input(
                task_purpose=normalized_purpose,
                query_plan=query_plan,
                subject_key=trusted_subject,
            )
            policy_input_sha256 = canonical_json_sha256(policy_input.model_dump(mode="json"))
            policy_decision = local_policy_engine.evaluate(policy_input)
            policy_decision_sha256 = canonical_json_sha256(
                policy_decision.model_dump(mode="json")
            )
        except Exception:
            raise AgentProposalAuthorityError("AGENT_AUTHORITY_POLICY_FAILED") from None

        pre_issue_at = self._sample_clock()
        try:
            governance_binding.assert_fresh(pre_issue_at)
            self._require_fresh_at(pre_issue_at)
        except Exception:
            raise AgentProposalAuthorityError("AGENT_AUTHORITY_STALE_AT_ISSUE") from None

        payload = {
            "proposal_sha256": trusted_proposal.proposal_sha256,
            "goal_sha256": trusted_goal.goal_sha256,
            "planning_context_sha256": trusted_context.context_sha256,
            "source_snapshot_sha256": self._snapshot.snapshot_sha256,
            "authorized_task_purpose": normalized_purpose,
            "authorized_task_purpose_sha256": canonical_json_sha256(
                {"task_purpose": normalized_purpose}
            ),
            "subject_key": trusted_subject,
            "subject_key_sha256": canonical_json_sha256(
                trusted_subject.model_dump(mode="json")
            ),
            "query_plan": query_plan,
            "query_plan_sha256": query_plan_sha256,
            "resolution": resolution,
            "governance_binding": governance_binding,
            "governance_sha256": governance_sha256,
            "evidence_bundle": self._evidence_bundle,
            "evidence_validation": self._evidence_validation,
            "policy_input": policy_input,
            "policy_input_sha256": policy_input_sha256,
            "policy_version": self._policy_version,
            "policy_config_sha256": self._policy_config_sha256,
            "policy_decision": policy_decision,
            "policy_decision_sha256": policy_decision_sha256,
            "security_authoritative": True,
            "evidence_trust_resolved": False,
            "prospective_privacy_checked": False,
            "execution_authorized": False,
        }
        provisional = TrustedAgentProposalEvaluation.model_construct(
            **payload,
            evaluation_sha256="0" * 64,
        )
        result = TrustedAgentProposalEvaluation(
            **payload,
            evaluation_sha256=compute_trusted_agent_proposal_evaluation_sha256(provisional),
        )

        returned_at = self._sample_clock()
        try:
            governance_binding.assert_fresh(returned_at)
            self._require_fresh_at(returned_at)
        except Exception:
            raise AgentProposalAuthorityError("AGENT_AUTHORITY_STALE_AT_ISSUE") from None
        return result

    def _sample_clock(self) -> datetime:
        with self._clock_lock:
            try:
                current = self._clock()
                if current.tzinfo is None:
                    raise ValueError("authority clock must be timezone-aware")
                normalized = current.astimezone(timezone.utc)
            except Exception:
                raise AgentProposalAuthorityError("AGENT_AUTHORITY_TIME_INVALID") from None

            if self._last_clock_sample is not None and normalized < self._last_clock_sample:
                raise AgentProposalAuthorityError("AGENT_AUTHORITY_TIME_ROLLBACK")
            self._last_clock_sample = normalized
            return normalized

    def _require_fresh_at(self, current: datetime) -> None:
        bundle = self._evidence_bundle
        validation = self._evidence_validation
        if current < bundle.observed_at:
            raise AgentProposalAuthorityError("AGENT_AUTHORITY_EVIDENCE_FROM_FUTURE")
        if current >= bundle.expires_at:
            raise AgentProposalAuthorityError("AGENT_AUTHORITY_EVIDENCE_STALE")
        if current < validation.validated_at:
            raise AgentProposalAuthorityError("AGENT_AUTHORITY_VALIDATION_FROM_FUTURE")
        if current >= validation.evidence_expires_at:
            raise AgentProposalAuthorityError("AGENT_AUTHORITY_VALIDATION_STALE")


def compute_trusted_agent_proposal_evaluation_sha256(
    evaluation: TrustedAgentProposalEvaluation,
) -> str:
    return canonical_json_sha256(
        evaluation.model_dump(mode="json", exclude={"evaluation_sha256"})
    )


def _require_evidence_validation_alignment(
    bundle: DataHubEvidenceBundle,
    validation: DataHubDerivationValidation,
) -> None:
    if validation.evidence_root_sha256 != bundle.evidence_root_sha256:
        raise ValueError("trusted Agent evidence validation root mismatch")
    if validation.snapshot_sha256 != bundle.snapshot_sha256:
        raise ValueError("trusted Agent evidence validation snapshot mismatch")
    if validation.source_identity != bundle.source_identity:
        raise ValueError("trusted Agent evidence validation source mismatch")
    if validation.evidence_observed_at != bundle.observed_at:
        raise ValueError("trusted Agent evidence validation observation mismatch")
    if validation.evidence_expires_at != bundle.expires_at:
        raise ValueError("trusted Agent evidence validation expiry mismatch")
    lifetime = (bundle.expires_at - bundle.observed_at).total_seconds()
    if round(validation.freshness_policy_seconds, 6) != round(lifetime, 6):
        raise ValueError("trusted Agent evidence freshness-policy mismatch")

    observed = tuple(
        sorted(
            claim.claim_id
            for claim in bundle.claims
            if claim.derivation == DerivationKind.RUNTIME_OBSERVED
        )
    )
    mapped = tuple(
        sorted(
            claim.claim_id
            for claim in bundle.claims
            if claim.derivation == DerivationKind.EXPLICIT_MAPPING
        )
    )
    if validation.observed_claim_ids != observed:
        raise ValueError("trusted Agent observed-claim partition mismatch")
    if validation.mapped_claim_ids != mapped:
        raise ValueError("trusted Agent mapped-claim partition mismatch")
    if len(observed) + len(mapped) != len(bundle.claims):
        raise ValueError("trusted Agent evidence contains an unvalidated derivation kind")


def _normalized_nonempty_text(value: Any) -> str:
    exact = _exact_text(value)
    normalized = exact.strip()
    if not normalized:
        raise ValueError("text must not be empty")
    return normalized


def _exact_text(value: Any) -> str:
    if not isinstance(value, str):
        raise TypeError("text value must be a string")
    exact = str.__str__(value)
    if type(exact) is not str:
        raise TypeError("text normalization failed")
    return exact
