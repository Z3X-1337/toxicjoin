"""Counterfactual Privacy Cut Compiler (CPCC) primitives.

EXPERIMENTAL — not wired into the HTTP runtime.

CPCC searches a committed finite remediation space for a minimum-cost repair of an unsafe
query. The shipped rewriter deliberately supports exactly one narrow transformation instead,
because a rewriter that can restructure arbitrary SQL is far harder to argue is safe than one
that can only add a subject threshold.

Kept in-tree as the intended successor to that rewriter. `tests/security/test_runtime_module_boundary.py`
enforces this status.
"""

from toxicjoin.repair.compiler import (
    CompiledCpccRepair,
    CpccCompileError,
    compile_cpcc_candidate,
    compute_compiled_repair_sha256,
)
from toxicjoin.repair.cpcc import (
    CpccCandidateValidator,
    CpccError,
    build_cpcc_candidate_validation,
    build_remediation_action,
    build_remediation_space,
    enumerate_cpcc_candidates,
    run_cpcc,
)
from toxicjoin.repair.models import (
    CpccCandidate,
    CpccCandidateValidation,
    CpccRemediationSpace,
    CpccResult,
    CpccStatus,
    CpccValidationOutcome,
    CpccValidationStage,
    RemediationAction,
    RemediationCost,
    RemediationOperator,
    TrustedQiTransformation,
    TrustedSensitiveAggregate,
)
from toxicjoin.repair.validator import (
    CpccFullValidationError,
    DataHubCpccCandidateValidator,
)

__all__ = [
    "CompiledCpccRepair",
    "CpccCandidate",
    "CpccCandidateValidation",
    "CpccCandidateValidator",
    "CpccCompileError",
    "CpccError",
    "CpccFullValidationError",
    "CpccRemediationSpace",
    "CpccResult",
    "CpccStatus",
    "CpccValidationOutcome",
    "CpccValidationStage",
    "DataHubCpccCandidateValidator",
    "RemediationAction",
    "RemediationCost",
    "RemediationOperator",
    "TrustedQiTransformation",
    "TrustedSensitiveAggregate",
    "build_cpcc_candidate_validation",
    "build_remediation_action",
    "build_remediation_space",
    "compile_cpcc_candidate",
    "compute_compiled_repair_sha256",
    "enumerate_cpcc_candidates",
    "run_cpcc",
]
