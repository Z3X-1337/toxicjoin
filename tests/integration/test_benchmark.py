from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from toxicjoin.benchmark import BENCHMARK_CASES, run_benchmark
from toxicjoin.models import Decision


def test_benchmark_corpus_is_unique_and_balanced() -> None:
    assert len(BENCHMARK_CASES) == 30
    assert len({case.case_id for case in BENCHMARK_CASES}) == 30
    assert Counter(case.expected_initial for case in BENCHMARK_CASES) == {
        Decision.ALLOW: 10,
        Decision.REWRITE: 10,
        Decision.BLOCK: 10,
    }
    assert all(case.sql.strip() for case in BENCHMARK_CASES)
    assert all(case.task_purpose.strip() for case in BENCHMARK_CASES)


def test_full_benchmark_passes_all_security_gates(tmp_path: Path) -> None:
    report = run_benchmark(output_dir=tmp_path)
    mismatches = [
        {
            "case_id": case.case_id,
            "expected_initial": case.expected_initial.value,
            "predicted_initial": case.predicted_initial.value,
            "expected_effective": case.expected_effective.value,
            "predicted_effective": case.predicted_effective.value,
            "expected_reason": case.expected_reason.value,
            "predicted_initial_reasons": [
                reason.value for reason in case.predicted_initial_reasons
            ],
            "safe_sql_expected": case.safe_sql_expected,
            "safe_sql_created": case.safe_sql_created,
            "verification_passed": case.verification_passed,
        }
        for case in report.cases
        if not case.passed
    ]

    assert report.passed is True, json.dumps(
        {
            "gate_failures": report.gate_failures,
            "metrics": report.metrics.model_dump(mode="json"),
            "mismatches": mismatches,
        },
        indent=2,
        sort_keys=True,
    )
    assert report.gate_failures == ()
    assert report.metrics.total_cases == 30
    assert report.metrics.initial_accuracy == 1.0
    assert report.metrics.effective_accuracy == 1.0
    assert report.metrics.reason_accuracy == 1.0
    assert report.metrics.full_case_accuracy == 1.0
    assert report.metrics.false_allow_count == 0
    assert report.metrics.unsafe_effective_allow_count == 0
    assert report.expected_distribution == {
        Decision.ALLOW: 10,
        Decision.REWRITE: 10,
        Decision.BLOCK: 10,
    }
    assert all(case.passed for case in report.cases)

    json_path = tmp_path / "benchmark.json"
    markdown_path = tmp_path / "benchmark.md"
    assert json_path.is_file()
    assert markdown_path.is_file()
    persisted = json.loads(json_path.read_text(encoding="utf-8"))
    assert persisted["report_sha256"] == report.report_sha256
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "**Gate:** PASS" in markdown
    assert "**False allows:** 0" in markdown
    assert "Initial decision confusion matrix" in markdown


def test_benchmark_report_is_semantically_deterministic(tmp_path: Path) -> None:
    first = run_benchmark(output_dir=tmp_path / "first")
    second = run_benchmark(output_dir=tmp_path / "second")

    assert first == second
    assert first.report_sha256 == second.report_sha256
    assert first.data_fingerprint == second.data_fingerprint
    assert [case.receipt_content_sha256 for case in first.cases] == [
        case.receipt_content_sha256 for case in second.cases
    ]
