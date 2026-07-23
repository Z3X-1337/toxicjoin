"""Package-owned summary of the last committed CI benchmark evidence.

The full corpus remains executable through ``toxicjoin-benchmark``. This compact
summary is served to the judge interface without rerunning 30 database scenarios on
every page load. A repository test keeps it synchronized with the committed evidence
file and report hash.
"""

from __future__ import annotations

from pydantic import Field

from toxicjoin.models import StrictModel


class BenchmarkCorpusSummary(StrictModel):
    total: int = Field(ge=1)
    expected_allow: int = Field(ge=0)
    expected_rewrite: int = Field(ge=0)
    expected_block: int = Field(ge=0)


class BenchmarkMetricsSummary(StrictModel):
    initial_accuracy: float = Field(ge=0, le=1)
    effective_accuracy: float = Field(ge=0, le=1)
    reason_accuracy: float = Field(ge=0, le=1)
    full_case_accuracy: float = Field(ge=0, le=1)
    false_allow_count: int = Field(ge=0)
    unsafe_effective_allow_count: int = Field(ge=0)
    rewrite_remediated_count: int = Field(ge=0)
    rewrite_fail_closed_count: int = Field(ge=0)
    verified_execution_count: int = Field(ge=0)


class BenchmarkEvidenceSummary(StrictModel):
    schema_version: str = "1.0"
    benchmark_version: str = "1.0"
    policy_version: str
    corpus: BenchmarkCorpusSummary
    metrics: BenchmarkMetricsSummary
    data_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    full_report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    gate_failures: tuple[str, ...] = ()
    scope_note: str


BENCHMARK_EVIDENCE = BenchmarkEvidenceSummary(
    policy_version="0.1.0",
    corpus=BenchmarkCorpusSummary(
        total=30,
        expected_allow=10,
        expected_rewrite=10,
        expected_block=10,
    ),
    metrics=BenchmarkMetricsSummary(
        initial_accuracy=1.0,
        effective_accuracy=1.0,
        reason_accuracy=1.0,
        full_case_accuracy=1.0,
        false_allow_count=0,
        unsafe_effective_allow_count=0,
        rewrite_remediated_count=6,
        rewrite_fail_closed_count=4,
        verified_execution_count=16,
    ),
    data_fingerprint=(
        "bfeae85c4b238e38012aadc6f4c95d24c7a28bcb1da1c35e8eeef5be28be7d16"
    ),
    full_report_sha256=(
        "4a1b7630012ffd54eba698b6bf1fd66a9dc3b6167d2513ef1c4c5519a8483987"
    ),
    scope_note=(
        "Deterministic regression corpus for the declared ToxicJoin SQL and policy "
        "profile; not a claim of universal privacy detection."
    ),
)
