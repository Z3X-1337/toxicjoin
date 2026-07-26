"""Strict planning-only models for the Governed Agent boundary."""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.models import Decision, ReasonCode, SensitivityCategory, StrictModel
from toxicjoin.prospective.ppmc import PpmcStatus

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_AGENT_MODEL_VERSION = "0.1.0"
_MAX_AGENT_ITERATIONS = 8
_MAX_METADATA_LABEL_LENGTH = 512
Sha256 = Annotated[str, Field(pattern=_HASH_PATTERN)]
MetadataLabel = Annotated[
    str,
    Field(min_length=1, max_length=_MAX_METADATA_LABEL_LENGTH),
]


class AgentCapability(StrEnum):
    """The complete P0 Governed Agent authority surface."""

    DISCOVER = "DISCOVER"
    PROPOSE = "PROPOSE"
    ADAPT = "ADAPT"


class AgentLineageView(StrictModel):
    """Planning-only upstream lineage view; never an EvidenceClaim or trust decision."""

    source_dataset_urn: str = Field(min_length=1, max_length=2048)
    source_field_path: str = Field(min_length=1, max_length=512)
    category: SensitivityCategory
    security_authoritative: Literal[False] = False

    @property
    def key(self) -> str:
        return f"{self.source_dataset_urn}#{self.source_field_path}"


class AgentFieldView(StrictModel):
    """Sanitized planning view of one governed field."""

    field_path: str = Field(min_length=1, max_length=512)
    category: SensitivityCategory
    tags: tuple[MetadataLabel, ...] = Field(default=(), max_length=128)
    glossary_terms: tuple[MetadataLabel, ...] = Field(default=(), max_length=128)
    lineage: tuple[AgentLineageView, ...] = Field(default=(), max_length=128)
    security_authoritative: Literal[False] = False

    @model_validator(mode="after")
    def validate_canonical_field(self) -> "AgentFieldView":
        if self.tags != tuple(sorted(set(self.tags))):
            raise ValueError("agent field tags must be sorted and unique")
        if self.glossary_terms != tuple(sorted(set(self.glossary_terms))):
            raise ValueError("agent field glossary terms must be sorted and unique")
        lineage_keys = tuple(item.key for item in self.lineage)
        if lineage_keys != tuple(sorted(set(lineage_keys))):
            raise ValueError("agent field lineage must be sorted and unique")
        return self


class AgentDatasetView(StrictModel):
    """Sanitized planning view of one DataHub-backed dataset."""

    logical_name: str = Field(min_length=1, max_length=256)
    dataset_urn: str = Field(min_length=1, max_length=2048)
    owner: str | None = Field(default=None, max_length=2048)
    domain: str | None = Field(default=None, max_length=2048)
    fields: tuple[AgentFieldView, ...] = Field(min_length=1, max_length=4096)
    security_authoritative: Literal[False] = False

    @model_validator(mode="after")
    def validate_canonical_dataset(self) -> "AgentDatasetView":
        field_paths = tuple(field.field_path for field in self.fields)
        if field_paths != tuple(sorted(set(field_paths))):
            raise ValueError("agent dataset fields must be sorted and unique")
        return self


class AgentDataContext(StrictModel):
    """Immutable read-only planning context produced by a security-owned discoverer."""

    schema_version: Literal["1.0"] = "1.0"
    model_version: Literal["0.1.0"] = _AGENT_MODEL_VERSION
    capability: Literal[AgentCapability.DISCOVER] = AgentCapability.DISCOVER
    source: Literal["DATAHUB"] = "DATAHUB"
    source_snapshot_sha256: Sha256
    catalog_version: str = Field(min_length=1, max_length=512)
    datasets: tuple[AgentDatasetView, ...] = Field(min_length=1, max_length=256)
    security_authoritative: Literal[False] = False
    context_sha256: Sha256

    @model_validator(mode="after")
    def validate_context(self) -> "AgentDataContext":
        names = tuple(dataset.logical_name for dataset in self.datasets)
        urns = tuple(dataset.dataset_urn for dataset in self.datasets)
        if names != tuple(sorted(set(names))):
            raise ValueError("agent datasets must be sorted and unique by logical name")
        if len(set(urns)) != len(urns):
            raise ValueError("agent datasets must use unique dataset URNs")
        if self.context_sha256 != compute_agent_data_context_sha256(self):
            raise ValueError("agent data context hash mismatch")
        return self


class AgentGoal(StrictModel):
    """Untrusted natural-language goal commitment."""

    schema_version: Literal["1.0"] = "1.0"
    goal: str = Field(min_length=1, max_length=8192)
    goal_sha256: Sha256

    @field_validator("goal")
    @classmethod
    def normalize_goal(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("agent goal must not be blank")
        return normalized

    @model_validator(mode="after")
    def validate_goal_hash(self) -> "AgentGoal":
        if self.goal_sha256 != hashlib.sha256(self.goal.encode("utf-8")).hexdigest():
            raise ValueError("agent goal hash mismatch")
        return self


class AgentDraft(StrictModel):
    """The only planner-authored payload accepted by the security-owned agent wrapper."""

    task_purpose: str = Field(min_length=1, max_length=4096)
    sql: str = Field(min_length=1, max_length=100_000)

    @field_validator("task_purpose", "sql")
    @classmethod
    def reject_blank(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("agent draft values must not be blank")
        return value


class AgentFeedback(StrictModel):
    """Structured ToxicJoin feedback that the untrusted planner may use only to adapt."""

    schema_version: Literal["1.0"] = "1.0"
    model_version: Literal["0.1.0"] = _AGENT_MODEL_VERSION
    previous_proposal_sha256: Sha256
    decision: Decision
    reason_codes: tuple[ReasonCode, ...]
    ppmc_status: PpmcStatus | None = None
    counterexample_trace_sha256: Sha256 | None = None
    cpcc_result_sha256: Sha256 | None = None
    security_authoritative: Literal[False] = False
    feedback_sha256: Sha256

    @model_validator(mode="after")
    def validate_feedback(self) -> "AgentFeedback":
        canonical_reasons = tuple(
            reason for reason in ReasonCode if reason in set(self.reason_codes)
        )
        if self.reason_codes != canonical_reasons:
            raise ValueError("agent feedback reason codes must be canonical and unique")
        if self.ppmc_status == PpmcStatus.PROSPECTIVE_UNSAFE:
            if self.counterexample_trace_sha256 is None:
                raise ValueError("unsafe PPMC feedback requires a counterexample trace")
        elif self.counterexample_trace_sha256 is not None:
            raise ValueError("counterexample trace is valid only for unsafe PPMC feedback")
        if self.feedback_sha256 != compute_agent_feedback_sha256(self):
            raise ValueError("agent feedback hash mismatch")
        return self


class AgentProposal(StrictModel):
    """Canonical, explicitly non-authoritative output of GovernedAgent."""

    schema_version: Literal["1.0"] = "1.0"
    model_version: Literal["0.1.0"] = _AGENT_MODEL_VERSION
    capability: AgentCapability
    iteration: int = Field(ge=0, le=_MAX_AGENT_ITERATIONS)
    goal_sha256: Sha256
    data_context_sha256: Sha256
    prior_proposal_sha256: Sha256 | None = None
    feedback_sha256: Sha256 | None = None
    task_purpose: str = Field(min_length=1, max_length=4096)
    sql: str = Field(min_length=1, max_length=100_000)
    sql_sha256: Sha256
    query_plan_sha256: Sha256
    security_authoritative: Literal[False] = False
    proposal_sha256: Sha256

    @model_validator(mode="after")
    def validate_proposal(self) -> "AgentProposal":
        if self.capability == AgentCapability.PROPOSE:
            if self.iteration != 0:
                raise ValueError("initial agent proposal must use iteration zero")
            if self.prior_proposal_sha256 is not None or self.feedback_sha256 is not None:
                raise ValueError("initial agent proposal cannot bind prior feedback")
        elif self.capability == AgentCapability.ADAPT:
            if self.iteration < 1:
                raise ValueError("agent adaptation requires a positive iteration")
            if self.prior_proposal_sha256 is None or self.feedback_sha256 is None:
                raise ValueError("agent adaptation requires prior proposal and feedback bindings")
        else:
            raise ValueError("DISCOVER is a context capability, not a SQL proposal")
        if self.sql_sha256 != hashlib.sha256(self.sql.encode("utf-8")).hexdigest():
            raise ValueError("agent proposal SQL hash mismatch")
        if self.proposal_sha256 != compute_agent_proposal_sha256(self):
            raise ValueError("agent proposal hash mismatch")
        return self


def build_agent_goal(goal: str) -> AgentGoal:
    normalized = goal.strip()
    return AgentGoal(
        goal=normalized,
        goal_sha256=hashlib.sha256(normalized.encode("utf-8")).hexdigest(),
    )


def build_agent_data_context(
    *,
    source_snapshot_sha256: str,
    catalog_version: str,
    datasets: tuple[AgentDatasetView, ...],
) -> AgentDataContext:
    ordered = tuple(sorted(datasets, key=lambda dataset: dataset.logical_name))
    provisional = AgentDataContext.model_construct(
        source_snapshot_sha256=source_snapshot_sha256,
        catalog_version=catalog_version,
        datasets=ordered,
        security_authoritative=False,
        context_sha256="0" * 64,
    )
    return AgentDataContext(
        source_snapshot_sha256=source_snapshot_sha256,
        catalog_version=catalog_version,
        datasets=ordered,
        security_authoritative=False,
        context_sha256=compute_agent_data_context_sha256(provisional),
    )


def build_agent_feedback(
    *,
    previous_proposal_sha256: str,
    decision: Decision,
    reason_codes: tuple[ReasonCode, ...],
    ppmc_status: PpmcStatus | None = None,
    counterexample_trace_sha256: str | None = None,
    cpcc_result_sha256: str | None = None,
) -> AgentFeedback:
    canonical_reasons = tuple(
        reason for reason in ReasonCode if reason in set(reason_codes)
    )
    provisional = AgentFeedback.model_construct(
        previous_proposal_sha256=previous_proposal_sha256,
        decision=decision,
        reason_codes=canonical_reasons,
        ppmc_status=ppmc_status,
        counterexample_trace_sha256=counterexample_trace_sha256,
        cpcc_result_sha256=cpcc_result_sha256,
        security_authoritative=False,
        feedback_sha256="0" * 64,
    )
    return AgentFeedback(
        previous_proposal_sha256=previous_proposal_sha256,
        decision=decision,
        reason_codes=canonical_reasons,
        ppmc_status=ppmc_status,
        counterexample_trace_sha256=counterexample_trace_sha256,
        cpcc_result_sha256=cpcc_result_sha256,
        security_authoritative=False,
        feedback_sha256=compute_agent_feedback_sha256(provisional),
    )


def compute_agent_data_context_sha256(context: AgentDataContext) -> str:
    return canonical_json_sha256(
        context.model_dump(mode="json", exclude={"context_sha256"})
    )


def compute_agent_feedback_sha256(feedback: AgentFeedback) -> str:
    return canonical_json_sha256(
        feedback.model_dump(mode="json", exclude={"feedback_sha256"})
    )


def compute_agent_proposal_sha256(proposal: AgentProposal) -> str:
    return canonical_json_sha256(
        proposal.model_dump(mode="json", exclude={"proposal_sha256"})
    )
