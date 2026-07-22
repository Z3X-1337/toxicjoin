"""Run the balanced ToxicJoin corpus through the real safety pipeline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

from pydantic import Field, model_validator

from toxicjoin.benchmark.cases import BENCHMARK_CASES, BenchmarkCase
from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog, seed_database
from toxicjoin.execute import DuckDBExecutor
from toxicjoin.models import Decision, ReasonCode, StrictModel
from toxicjoin.pipeline import PipelineRequest, ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import ReceiptMode, ReceiptStore


_DECISIONS = (Decision.ALLOW, Decision.REWRITE, Decision.BLOCK)


class BenchmarkCaseResult(StrictModel):
    case_id: str
    title: str
    attack_class: str
    sql_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_initial: Decision
    predicted_initial: Decision
    expected_effective: Decision
    predicted_effective: Decision
    expected_reason: ReasonCode
    predicted_initial_reasons: tuple[ReasonCode, ...]
    predicted_final_reasons: tuple[ReasonCode, ...] = ()
    initial_match: bool
    effective_match: bool
    reason_match: bool
    safe_sql_expected: bool
    safe_sql_created: bool
    safe_sql_match: bool
    verification_passed: bool | None = None
    receipt_content_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    passed: bool


class BenchmarkMetrics(StrictModel):
    total_cases: int = Field(ge=1)
    initial_correct: int = Field(ge=0)
    effective_correct: int = Field(ge=0)
    reason_correct: int = Field(ge=0)
    fully_passed: int = Field(ge=0)
    initial_accuracy: float = Field(ge=0, le=1)
    effective_accuracy: float = Field(ge=0, le=1)
    reason_accuracy: float = Field(ge=0, le=1)
    full_case_accuracy: float = Field(ge=0, le=1)
    false_allow_count: int = Field(ge=0)
    unsafe_effective_allow_count: int = Field(ge=0)
    rewrite_remediated_count: int = Field(ge=0)
    rewrite_fail_closed_count: int = Field(ge=0)
    verified_execution_count: int = Field(ge=0)


class BenchmarkReport(StrictModel):
    schema_version: str = "1.0"
    benchmark_version: str = "1.0"
    policy_version: str
    seed: int
    data_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_distribution: dict[Decision, int]
    initial_confusion_matrix: dict[Decision, dict[Decision, int]]
    effective_confusion_matrix: dict[Decision, dict[Decision, int]]
    metrics: BenchmarkMetrics
    cases: tuple[BenchmarkCaseResult, ...]
    gate_failures: tuple[str, ...] = ()
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def validate_report_totals(self) -> "BenchmarkReport":
        if len(self.cases) != self.metrics.total_cases:
            raise ValueError("metrics total_cases does not match case count")
        if sum(self.expected_distribution.values()) != self.metrics.total_cases:
            raise ValueError("expected distribution does not match total cases")
        return self

    @property
    def passed(self) -> bool:
        return not self.gate_failures


def run_benchmark(
    *,
    cases: tuple[BenchmarkCase, ...] = BENCHMARK_CASES,
    output_dir: str | Path | None = None,
) -> BenchmarkReport:
    """Execute all cases against a fresh deterministic warehouse."""

    _validate_corpus(cases)
    with tempfile.TemporaryDirectory(prefix="toxicjoin-benchmark-") as temporary:
        root = Path(temporary)
        seed_summary = seed_database(root / "benchmark.duckdb")
        policy = load_policy()
        pipeline = ToxicJoinPipeline(
            context_resolver=FixtureContextResolver(default_fixture_catalog()),
            policy_engine=PolicyEngine(policy),
            receipt_store=ReceiptStore(root / "receipts"),
            mode=ReceiptMode.FIXTURE,
            executor=DuckDBExecutor(
                root / "benchmark.duckdb",
                max_preview_rows=100,
                timeout_seconds=5.0,
            ),
            include_sanitized_sql=False,
        )

        results = tuple(_run_case(pipeline, case) for case in cases)

    report_payload: dict[str, Any] = {
        "schema_version": "1.0",
        "benchmark_version": "1.0",
        "policy_version": policy.version,
        "seed": seed_summary.seed,
        "data_fingerprint": seed_summary.data_fingerprint,
        "expected_distribution": _expected_distribution(cases),
        "initial_confusion_matrix": _confusion_matrix(
            expected=(result.expected_initial for result in results),
            predicted=(result.predicted_initial for result in results),
        ),
        "effective_confusion_matrix": _confusion_matrix(
            expected=(result.expected_effective for result in results),
            predicted=(result.predicted_effective for result in results),
        ),
        "metrics": _metrics(results),
        "cases": results,
        "gate_failures": _gate_failures(cases, results),
        "report_sha256": "0" * 64,
    }
    report_payload["report_sha256"] = _report_hash(report_payload)
    report = BenchmarkReport.model_validate(report_payload)

    if output_dir is not None:
        destination = Path(output_dir)
        destination.mkdir(parents=True, exist_ok=True)
        _write_atomic(
            destination / "benchmark.json",
            report.model_dump_json(indent=2) + "\n",
        )
        _write_atomic(destination / "benchmark.md", _markdown(report))
    return report


def _run_case(
    pipeline: ToxicJoinPipeline,
    case: BenchmarkCase,
) -> BenchmarkCaseResult:
    result = pipeline.execute_safe(
        PipelineRequest(
            task_purpose=case.task_purpose,
            sql=case.sql,
            subject_key=case.subject_key,
        )
    )
    predicted_initial = result.initial_decision.decision
    predicted_effective = result.effective_decision
    initial_match = predicted_initial == case.expected_initial
    effective_match = predicted_effective == case.expected_effective
    reason_match = case.expected_reason in result.initial_decision.reason_codes
    safe_sql_created = result.safe_sql is not None
    safe_sql_match = safe_sql_created == case.expect_safe_sql
    passed = initial_match and effective_match and reason_match and safe_sql_match

    return BenchmarkCaseResult(
        case_id=case.case_id,
        title=case.title,
        attack_class=case.attack_class,
        sql_sha256=hashlib.sha256(case.sql.encode("utf-8")).hexdigest(),
        expected_initial=case.expected_initial,
        predicted_initial=predicted_initial,
        expected_effective=case.expected_effective,
        predicted_effective=predicted_effective,
        expected_reason=case.expected_reason,
        predicted_initial_reasons=result.initial_decision.reason_codes,
        predicted_final_reasons=(
            result.final_decision.reason_codes
            if result.final_decision is not None
            else ()
        ),
        initial_match=initial_match,
        effective_match=effective_match,
        reason_match=reason_match,
        safe_sql_expected=case.expect_safe_sql,
        safe_sql_created=safe_sql_created,
        safe_sql_match=safe_sql_match,
        verification_passed=(
            result.verification.passed
            if result.verification is not None
            else None
        ),
        receipt_content_sha256=result.receipt.content_sha256,
        passed=passed,
    )


def _validate_corpus(cases: tuple[BenchmarkCase, ...]) -> None:
    if len(cases) != 30:
        raise ValueError(f"benchmark must contain exactly 30 cases, received {len(cases)}")
    identifiers = [case.case_id for case in cases]
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("benchmark case IDs must be unique")
    distribution = Counter(case.expected_initial for case in cases)
    expected = {decision: 10 for decision in _DECISIONS}
    if distribution != expected:
        raise ValueError(
            "benchmark must contain ten ALLOW, ten REWRITE, and ten BLOCK cases"
        )


def _expected_distribution(
    cases: tuple[BenchmarkCase, ...],
) -> dict[Decision, int]:
    counts = Counter(case.expected_initial for case in cases)
    return {decision: counts[decision] for decision in _DECISIONS}


def _confusion_matrix(
    *,
    expected: Any,
    predicted: Any,
) -> dict[Decision, dict[Decision, int]]:
    matrix = {
        expected_decision: {predicted_decision: 0 for predicted_decision in _DECISIONS}
        for expected_decision in _DECISIONS
    }
    for expected_decision, predicted_decision in zip(
        expected,
        predicted,
        strict=True,
    ):
        matrix[expected_decision][predicted_decision] += 1
    return matrix


def _metrics(results: tuple[BenchmarkCaseResult, ...]) -> BenchmarkMetrics:
    total = len(results)
    initial_correct = sum(result.initial_match for result in results)
    effective_correct = sum(result.effective_match for result in results)
    reason_correct = sum(result.reason_match for result in results)
    fully_passed = sum(result.passed for result in results)
    false_allow_count = sum(
        result.expected_initial != Decision.ALLOW
        and result.predicted_initial == Decision.ALLOW
        for result in results
    )
    unsafe_effective_allow_count = sum(
        result.expected_effective == Decision.BLOCK
        and result.predicted_effective == Decision.ALLOW
        for result in results
    )
    rewrite_remediated_count = sum(
        result.expected_initial == Decision.REWRITE
        and result.predicted_effective == Decision.ALLOW
        for result in results
    )
    rewrite_fail_closed_count = sum(
        result.expected_initial == Decision.REWRITE
        and result.predicted_effective == Decision.BLOCK
        for result in results
    )
    verified_execution_count = sum(
        result.verification_passed is True for result in results
    )
    return BenchmarkMetrics(
        total_cases=total,
        initial_correct=initial_correct,
        effective_correct=effective_correct,
        reason_correct=reason_correct,
        fully_passed=fully_passed,
        initial_accuracy=initial_correct / total,
        effective_accuracy=effective_correct / total,
        reason_accuracy=reason_correct / total,
        full_case_accuracy=fully_passed / total,
        false_allow_count=false_allow_count,
        unsafe_effective_allow_count=unsafe_effective_allow_count,
        rewrite_remediated_count=rewrite_remediated_count,
        rewrite_fail_closed_count=rewrite_fail_closed_count,
        verified_execution_count=verified_execution_count,
    )


def _gate_failures(
    cases: tuple[BenchmarkCase, ...],
    results: tuple[BenchmarkCaseResult, ...],
) -> tuple[str, ...]:
    metrics = _metrics(results)
    failures: list[str] = []
    if len(cases) != 30:
        failures.append("corpus_size_not_30")
    if metrics.initial_accuracy != 1.0:
        failures.append("initial_decision_accuracy_below_100_percent")
    if metrics.effective_accuracy != 1.0:
        failures.append("effective_decision_accuracy_below_100_percent")
    if metrics.reason_accuracy != 1.0:
        failures.append("reason_accuracy_below_100_percent")
    if metrics.full_case_accuracy != 1.0:
        failures.append("full_case_accuracy_below_100_percent")
    if metrics.false_allow_count:
        failures.append("false_allow_detected")
    if metrics.unsafe_effective_allow_count:
        failures.append("unsafe_effective_allow_detected")
    return tuple(failures)


def _report_hash(payload: dict[str, Any]) -> str:
    canonical_payload = {
        key: _json_compatible(value)
        for key, value in payload.items()
        if key != "report_sha256"
    }
    canonical = json.dumps(
        canonical_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _json_compatible(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_compatible(item) for item in value]
    if hasattr(value, "value") and isinstance(value.value, str):
        return value.value
    return value


def _markdown(report: BenchmarkReport) -> str:
    metrics = report.metrics
    status = "PASS" if report.passed else "FAIL"
    lines = [
        "# ToxicJoin Benchmark",
        "",
        f"**Gate:** {status}",
        f"**Policy version:** `{report.policy_version}`",
        f"**Cases:** {metrics.total_cases} (10 ALLOW / 10 REWRITE / 10 BLOCK)",
        f"**Initial decision accuracy:** {metrics.initial_accuracy:.1%}",
        f"**Effective outcome accuracy:** {metrics.effective_accuracy:.1%}",
        f"**Reason-code accuracy:** {metrics.reason_accuracy:.1%}",
        f"**False allows:** {metrics.false_allow_count}",
        f"**Unsafe effective allows:** {metrics.unsafe_effective_allow_count}",
        f"**Rewrites remediated to ALLOW:** {metrics.rewrite_remediated_count}",
        f"**Rewrites failed closed:** {metrics.rewrite_fail_closed_count}",
        f"**Verified executions:** {metrics.verified_execution_count}",
        f"**Data fingerprint:** `{report.data_fingerprint}`",
        f"**Report SHA-256:** `{report.report_sha256}`",
        "",
        "## Initial decision confusion matrix",
        "",
        "| Expected \\ Predicted | ALLOW | REWRITE | BLOCK |",
        "|---|---:|---:|---:|",
    ]
    for expected in _DECISIONS:
        row = report.initial_confusion_matrix[expected]
        lines.append(
            f"| {expected.value} | {row[Decision.ALLOW]} | "
            f"{row[Decision.REWRITE]} | {row[Decision.BLOCK]} |"
        )

    lines.extend(
        [
            "",
            "## Case results",
            "",
            "| ID | Class | Initial | Effective | Reason | Safe SQL | Result |",
            "|---|---|---|---|---|---:|---:|",
        ]
    )
    for result in report.cases:
        lines.append(
            f"| {result.case_id} | `{result.attack_class}` | "
            f"{result.predicted_initial.value} | {result.predicted_effective.value} | "
            f"{result.expected_reason.value} | "
            f"{'yes' if result.safe_sql_created else 'no'} | "
            f"{'PASS' if result.passed else 'FAIL'} |"
        )

    lines.extend(
        [
            "",
            "## Interpretation",
            "",
            "This benchmark is a deterministic regression corpus for the supported SQL "
            "and policy profile. It is not a claim of universal privacy detection, and "
            "it does not replace evaluation on an organization's real schemas and policies.",
            "",
        ]
    )
    if report.gate_failures:
        lines.extend(
            [
                "## Gate failures",
                "",
                *[f"- `{failure}`" for failure in report.gate_failures],
                "",
            ]
        )
    return "\n".join(lines)


def _write_atomic(path: Path, content: str) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
        text=True,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run the 30-query ToxicJoin deterministic benchmark"
    )
    parser.add_argument(
        "--output-dir",
        default="artifacts/benchmark",
        help="Directory for benchmark.json and benchmark.md",
    )
    parser.add_argument(
        "--allow-regressions",
        action="store_true",
        help="Exit zero even when a benchmark quality gate fails",
    )
    args = parser.parse_args()

    report = run_benchmark(output_dir=args.output_dir)
    print(report.model_dump_json(indent=2))
    if not report.passed and not args.allow_regressions:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
