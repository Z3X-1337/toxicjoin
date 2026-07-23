from __future__ import annotations

import json

from toxicjoin.benchmark.governance_dependency import (
    run_governance_dependency_evaluation,
)
from toxicjoin.models import Decision, ReasonCode


def test_governance_dependency_evaluation_fails_closed_on_metadata_gaps(tmp_path) -> None:
    output_dir = tmp_path / "governance-evidence"
    report = run_governance_dependency_evaluation(output_dir=output_dir)

    assert report.passed is True
    assert report.unsafe_effective_allow_count == 0
    assert report.gate_failures == ()
    assert len(report.cases) == 4

    cases = {case.case_id: case for case in report.cases}
    complete = cases["complete-governance"]
    assert complete.initial_decision == Decision.REWRITE
    assert complete.effective_decision == Decision.ALLOW
    assert complete.executed is True
    assert complete.verification_passed is True
    assert complete.output_group_count == 3
    assert complete.observed_subject_counts == (40, 40, 40)

    unclassified = cases["unclassified-sensitive-field"]
    assert unclassified.effective_decision == Decision.BLOCK
    assert ReasonCode.UNCLASSIFIED_COLUMN in unclassified.initial_reason_codes
    assert unclassified.executed is False

    missing_field = cases["missing-sensitive-field"]
    assert missing_field.effective_decision == Decision.BLOCK
    assert ReasonCode.UNRESOLVED_COLUMN in missing_field.initial_reason_codes
    assert missing_field.executed is False

    missing_dataset = cases["missing-governed-dataset"]
    assert missing_dataset.effective_decision == Decision.BLOCK
    assert ReasonCode.UNRESOLVED_DATASET in missing_dataset.initial_reason_codes
    assert missing_dataset.executed is False

    json_path = output_dir / "governance-dependency.json"
    markdown_path = output_dir / "governance-dependency.md"
    assert json_path.is_file()
    assert markdown_path.is_file()

    persisted = json.loads(json_path.read_text(encoding="utf-8"))
    assert persisted["report_sha256"] == report.report_sha256
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "**Gate:** PASS" in markdown
    assert "Unsafe effective allows under degraded governance:** 0" in markdown
