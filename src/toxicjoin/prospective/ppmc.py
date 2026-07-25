"""Prospective Privacy Model Checker (PPMC) public API.

P0 uses deterministic bounded BFS over a finite security-owned Future Action Grammar.
It is intentionally separate from PolicyEngine and does not authorize execution.
"""

from toxicjoin.prospective.ppmc_models import (
    LocalAdmissibilityOracle,
    LocalOracleDecision,
    PpmcError,
    PpmcFailureReason,
    PpmcSearchConfig,
    PpmcSearchResult,
    PpmcStatus,
    build_local_oracle_decision,
    build_ppmc_search_config,
    compute_local_oracle_decision_sha256,
    compute_ppmc_config_sha256,
    compute_ppmc_result_sha256,
)
from toxicjoin.prospective.ppmc_search import check_prospective_privacy

__all__ = [
    "LocalAdmissibilityOracle",
    "LocalOracleDecision",
    "PpmcError",
    "PpmcFailureReason",
    "PpmcSearchConfig",
    "PpmcSearchResult",
    "PpmcStatus",
    "build_local_oracle_decision",
    "build_ppmc_search_config",
    "check_prospective_privacy",
    "compute_local_oracle_decision_sha256",
    "compute_ppmc_config_sha256",
    "compute_ppmc_result_sha256",
]
