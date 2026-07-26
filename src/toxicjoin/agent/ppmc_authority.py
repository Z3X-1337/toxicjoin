"""Security-owned Governed-Agent entry point into prospective privacy checking.

The generic PPMC API deliberately remains a rollback-safe primitive that accepts a legacy
prospective ``GovernanceTrustBinding`` as trusted caller input.  The Governed-Agent path must
not expose that parameter.  Instead, this authority consumes the exact ``F6GovernanceClearance``
issued by the Day-13 governance bridge, rebinds it to the exact DisclosureState and grammar
context, runs PPMC, and emits a canonical artifact that commits the clearance and PPMC result.

A successful call means only that PPMC produced a canonical bounded-search result under the
clearance-owned F6 binding.  The result status still determines whether the search found a
counterexample, completed without one inside the declared bound, or failed closed.  Nothing in
this module authorizes execution.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from typing import Literal

from pydantic import Field, ValidationError, field_validator, model_validator

from toxicjoin.agent.f6_governance import F6GovernanceClearance
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.models import StrictModel
from toxicjoin.prospective.forbidden import ForbiddenPredicatePolicy
from toxicjoin.prospective.grammar import FutureActionGrammar
from toxicjoin.prospective.ppmc import (
    LocalAdmissibilityOracle,
    PpmcError,
    PpmcSearchConfig,
    PpmcSearchResult,
    build_ppmc_search_config,
    check_prospective_privacy,
)
from toxicjoin.prospective.twin import DisclosureState

_HASH_PATTERN = r"^[0-9a-f]{64}$"


class AgentPpmcAuthorityError(RuntimeError):
    """Stable fail-closed error for the Governed-Agent PPMC authority boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class TrustedAgentPpmcEvaluation(StrictModel):
    """Canonical binding between one F6 clearance and one exact PPMC result.

    ``prospective_privacy_checked=True`` means that the bounded checker returned a canonical
    result.  It does not mean the result is safe; callers must inspect ``ppmc_result.status``.
    """

    schema_version: Literal["1.0"] = "1.0"
    f6_clearance_sha256: str = Field(pattern=_HASH_PATTERN)
    disclosure_state_sha256: str = Field(pattern=_HASH_PATTERN)
    governance_binding_sha256: str = Field(pattern=_HASH_PATTERN)
    ppmc_result: PpmcSearchResult
    ppmc_result_sha256: str = Field(pattern=_HASH_PATTERN)
    ppmc_started_at: datetime
    evidence_expires_at: datetime
    prospective_privacy_checked: Literal[True] = True
    execution_authorized: Literal[False] = False
    evaluation_sha256: str = Field(pattern=_HASH_PATTERN)

    @field_validator("ppmc_started_at", "evidence_expires_at")
    @classmethod
    def timestamps_must_be_utc(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("Agent PPMC timestamps must be timezone-aware")
        return value.astimezone(timezone.utc)

    @model_validator(mode="after")
    def validate_evaluation(self) -> "TrustedAgentPpmcEvaluation":
        if self.ppmc_started_at >= self.evidence_expires_at:
            raise ValueError("Agent PPMC evaluation cannot start from expired evidence")
        if self.ppmc_result_sha256 != self.ppmc_result.result_sha256:
            raise ValueError("Agent PPMC result commitment mismatch")
        if self.ppmc_result.initial_state_sha256 != self.disclosure_state_sha256:
            raise ValueError("Agent PPMC result state commitment mismatch")
        if self.ppmc_result.governance_binding_sha256 != self.governance_binding_sha256:
            raise ValueError("Agent PPMC result governance commitment mismatch")
        if self.evaluation_sha256 != compute_trusted_agent_ppmc_evaluation_sha256(self):
            raise ValueError("Agent PPMC evaluation hash mismatch")
        return self


class DataHubAgentPpmcAuthority:
    """Run PPMC only through an exact state-bound F6 governance clearance."""

    def __init__(self, *, clock=None) -> None:
        self._clock = (lambda: datetime.now(timezone.utc)) if clock is None else clock
        self._clock_lock = threading.Lock()
        self._last_clock_sample: datetime | None = None

    def check(
        self,
        *,
        initial_state: DisclosureState,
        f6_clearance: F6GovernanceClearance,
        grammar: FutureActionGrammar,
        forbidden_policy: ForbiddenPredicatePolicy,
        local_oracle: LocalAdmissibilityOracle,
        config: PpmcSearchConfig | None = None,
    ) -> TrustedAgentPpmcEvaluation:
        """Return one clearance-bound PPMC evaluation or a stable fail-closed error code."""

        stable_code = "AGENT_PPMC_INTERNAL_FAILED"
        try:
            return self._check_impl(
                initial_state=initial_state,
                f6_clearance=f6_clearance,
                grammar=grammar,
                forbidden_policy=forbidden_policy,
                local_oracle=local_oracle,
                config=config,
            )
        except AgentPpmcAuthorityError as error:
            stable_code = error.code
            _detach_exception(error)
        except Exception as error:
            _detach_exception(error)

        initial_state = None  # type: ignore[assignment]
        f6_clearance = None  # type: ignore[assignment]
        grammar = None  # type: ignore[assignment]
        forbidden_policy = None  # type: ignore[assignment]
        local_oracle = None  # type: ignore[assignment]
        config = None
        self = None  # type: ignore[assignment]
        raise AgentPpmcAuthorityError(stable_code) from None

    def _check_impl(
        self,
        *,
        initial_state: DisclosureState,
        f6_clearance: F6GovernanceClearance,
        grammar: FutureActionGrammar,
        forbidden_policy: ForbiddenPredicatePolicy,
        local_oracle: LocalAdmissibilityOracle,
        config: PpmcSearchConfig | None,
    ) -> TrustedAgentPpmcEvaluation:
        if (
            type(initial_state) is not DisclosureState
            or type(f6_clearance) is not F6GovernanceClearance
            or type(grammar) is not FutureActionGrammar
            or type(forbidden_policy) is not ForbiddenPredicatePolicy
            or (config is not None and type(config) is not PpmcSearchConfig)
            or not callable(local_oracle)
        ):
            raise AgentPpmcAuthorityError("AGENT_PPMC_INPUT_INVALID")

        try:
            trusted_state = DisclosureState.model_validate(initial_state.model_dump(mode="json"))
            trusted_clearance = F6GovernanceClearance.model_validate(
                f6_clearance.model_dump(mode="json")
            )
            trusted_grammar = FutureActionGrammar.model_validate(grammar.model_dump(mode="json"))
            trusted_policy = ForbiddenPredicatePolicy.model_validate(
                forbidden_policy.model_dump(mode="json")
            )
            trusted_config = (
                build_ppmc_search_config()
                if config is None
                else PpmcSearchConfig.model_validate(config.model_dump(mode="json"))
            )
        except (ValidationError, ValueError):
            raise AgentPpmcAuthorityError("AGENT_PPMC_INPUT_INVALID") from None

        if trusted_clearance.disclosure_state_sha256 != trusted_state.state_sha256:
            raise AgentPpmcAuthorityError("AGENT_PPMC_STATE_MISMATCH")
        if trusted_clearance.purpose_commitment_sha256 != trusted_state.purpose_commitment_sha256:
            raise AgentPpmcAuthorityError("AGENT_PPMC_PURPOSE_MISMATCH")
        if trusted_clearance.governance_commitment_sha256 != trusted_state.governance_commitment_sha256:
            raise AgentPpmcAuthorityError("AGENT_PPMC_GOVERNANCE_MISMATCH")
        if trusted_clearance.evidence_root_sha256 != trusted_state.evidence_root_sha256:
            raise AgentPpmcAuthorityError("AGENT_PPMC_EVIDENCE_MISMATCH")

        context = trusted_grammar.context
        if context.initial_state_sha256 != trusted_state.state_sha256:
            raise AgentPpmcAuthorityError("AGENT_PPMC_GRAMMAR_STATE_MISMATCH")
        if context.scope_sha256 != trusted_state.scope.scope_sha256:
            raise AgentPpmcAuthorityError("AGENT_PPMC_GRAMMAR_SCOPE_MISMATCH")
        if context.purpose_commitment_sha256 != trusted_state.purpose_commitment_sha256:
            raise AgentPpmcAuthorityError("AGENT_PPMC_GRAMMAR_PURPOSE_MISMATCH")
        if context.governance_commitment_sha256 != trusted_state.governance_commitment_sha256:
            raise AgentPpmcAuthorityError("AGENT_PPMC_GRAMMAR_GOVERNANCE_MISMATCH")
        if context.evidence_root_sha256 != trusted_state.evidence_root_sha256:
            raise AgentPpmcAuthorityError("AGENT_PPMC_GRAMMAR_EVIDENCE_MISMATCH")
        if context.base_warehouse_snapshot_sha256 != trusted_state.warehouse_snapshot_sha256:
            raise AgentPpmcAuthorityError("AGENT_PPMC_GRAMMAR_SNAPSHOT_MISMATCH")
        state_atom_sha256s = {atom.atom_sha256 for atom in trusted_state.released_atoms}
        if not set(context.base_release_atom_sha256s).issubset(state_atom_sha256s):
            raise AgentPpmcAuthorityError("AGENT_PPMC_GRAMMAR_RELEASE_MISMATCH")

        started_at = self._sample_clock()
        if started_at < trusted_clearance.verified_at:
            raise AgentPpmcAuthorityError("AGENT_PPMC_CLEARANCE_FROM_FUTURE")
        if started_at >= trusted_clearance.evidence_expires_at:
            raise AgentPpmcAuthorityError("AGENT_PPMC_CLEARANCE_STALE")

        try:
            ppmc_result = check_prospective_privacy(
                initial_state=trusted_state,
                grammar=trusted_grammar,
                forbidden_policy=trusted_policy,
                governance_binding=trusted_clearance.f6_binding,
                local_oracle=local_oracle,
                config=trusted_config,
            )
            trusted_result = PpmcSearchResult.model_validate(ppmc_result.model_dump(mode="json"))
        except PpmcError:
            raise AgentPpmcAuthorityError("AGENT_PPMC_CHECK_FAILED") from None
        except (ValidationError, ValueError):
            raise AgentPpmcAuthorityError("AGENT_PPMC_RESULT_INVALID") from None

        if trusted_result.initial_state_sha256 != trusted_state.state_sha256:
            raise AgentPpmcAuthorityError("AGENT_PPMC_RESULT_STATE_MISMATCH")
        if trusted_result.grammar_sha256 != trusted_grammar.grammar_sha256:
            raise AgentPpmcAuthorityError("AGENT_PPMC_RESULT_GRAMMAR_MISMATCH")
        if trusted_result.config_sha256 != trusted_config.config_sha256:
            raise AgentPpmcAuthorityError("AGENT_PPMC_RESULT_CONFIG_MISMATCH")
        if trusted_result.forbidden_policy_sha256 != trusted_policy.policy_sha256:
            raise AgentPpmcAuthorityError("AGENT_PPMC_RESULT_POLICY_MISMATCH")
        if trusted_result.governance_binding_sha256 != trusted_clearance.f6_binding.binding_sha256:
            raise AgentPpmcAuthorityError("AGENT_PPMC_RESULT_GOVERNANCE_MISMATCH")

        payload = {
            "f6_clearance_sha256": trusted_clearance.clearance_sha256,
            "disclosure_state_sha256": trusted_state.state_sha256,
            "governance_binding_sha256": trusted_clearance.f6_binding.binding_sha256,
            "ppmc_result": trusted_result,
            "ppmc_result_sha256": trusted_result.result_sha256,
            "ppmc_started_at": started_at,
            "evidence_expires_at": trusted_clearance.evidence_expires_at,
            "prospective_privacy_checked": True,
            "execution_authorized": False,
        }
        provisional = TrustedAgentPpmcEvaluation.model_construct(
            **payload,
            evaluation_sha256="0" * 64,
        )
        result = TrustedAgentPpmcEvaluation(
            **payload,
            evaluation_sha256=compute_trusted_agent_ppmc_evaluation_sha256(provisional),
        )

        returned_at = self._sample_clock()
        if returned_at >= trusted_clearance.evidence_expires_at:
            raise AgentPpmcAuthorityError("AGENT_PPMC_CLEARANCE_STALE_AT_ISSUE")
        return result

    def _sample_clock(self) -> datetime:
        with self._clock_lock:
            try:
                current = self._clock()
                if not isinstance(current, datetime) or current.tzinfo is None:
                    raise ValueError("Agent PPMC clock must be timezone-aware")
                normalized = current.astimezone(timezone.utc)
            except Exception:
                raise AgentPpmcAuthorityError("AGENT_PPMC_TIME_INVALID") from None
            if self._last_clock_sample is not None and normalized < self._last_clock_sample:
                raise AgentPpmcAuthorityError("AGENT_PPMC_TIME_ROLLBACK")
            self._last_clock_sample = normalized
            return normalized


def compute_trusted_agent_ppmc_evaluation_sha256(
    evaluation: TrustedAgentPpmcEvaluation,
) -> str:
    return canonical_json_sha256(
        evaluation.model_dump(mode="json", exclude={"evaluation_sha256"})
    )


def _detach_exception(error: BaseException) -> None:
    error.__traceback__ = None
    error.__context__ = None
    error.__cause__ = None
    error.__suppress_context__ = True
