from __future__ import annotations

import json

from toxicjoin.benchmark.ablation import run_compositional_ablation


def test_compositional_interaction_isolated_by_ablation(tmp_path) -> None:
    output_dir = tmp_path / "ablation-evidence"
    report = run_compositional_ablation(output_dir=output_dir)

    assert report.passed is True
    assert report.unsafe_cases == 144
    assert report.control_cases == 20
    assert report.full_policy_unsafe_blocks == 144
    assert report.ablated_policy_unsafe_allows == 144
    assert report.unsafe_decision_changes == 144
    assert report.controls_preserved == 20
    assert report.gate_failures == ()
    assert all(result.passed for result in report.unsafe_results)
    assert all(result.control_preserved for result in report.control_results)

    json_path = output_dir / "compositional-ablation.json"
    markdown_path = output_dir / "compositional-ablation.md"
    assert json_path.is_file()
    assert markdown_path.is_file()

    persisted = json.loads(json_path.read_text(encoding="utf-8"))
    assert persisted["report_sha256"] == report.report_sha256
    markdown = markdown_path.read_text(encoding="utf-8")
    assert "**Gate:** PASS" in markdown
    assert "**Unsafe mutation cases:** 144" in markdown
    assert "**Benign/remediable controls:** 20" in markdown
