from __future__ import annotations

import json

from toxicjoin.benchmark.adversarial import run_adversarial_mutation_suite


def test_adversarial_mutations_never_execute_or_allow(tmp_path) -> None:
    output_dir = tmp_path / "adversarial-evidence"
    report = run_adversarial_mutation_suite(output_dir=output_dir)

    assert report.passed is True
    assert report.total_cases == 144
    assert report.family_counts == {
        "churn-profile": 48,
        "financial-profile": 48,
        "support-profile": 48,
    }
    assert report.initial_block_count == 144
    assert report.effective_block_count == 144
    assert report.intended_reason_count == 144
    assert report.unexpected_execution_count == 0
    assert report.unsafe_initial_allow_count == 0
    assert report.unsafe_effective_allow_count == 0
    assert all(case.passed for case in report.cases)

    json_path = output_dir / "adversarial-mutations.json"
    markdown_path = output_dir / "adversarial-mutations.md"
    assert json_path.is_file()
    assert markdown_path.is_file()

    persisted = json.loads(json_path.read_text(encoding="utf-8"))
    assert persisted["report_sha256"] == report.report_sha256
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "**Gate:** PASS" in markdown
    assert "**Cases:** 144" in markdown
    assert "**Unexpected database executions:** 0" in markdown
