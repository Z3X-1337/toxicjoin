from __future__ import annotations

import json
from pathlib import Path

from toxicjoin.benchmark.evidence import BENCHMARK_EVIDENCE


ROOT = Path(__file__).parents[2]


def test_package_benchmark_summary_matches_committed_evidence() -> None:
    committed = json.loads(
        (ROOT / "docs" / "evidence" / "benchmark-summary.json").read_text(
            encoding="utf-8"
        )
    )
    packaged = BENCHMARK_EVIDENCE.model_dump(mode="json")

    assert packaged["schema_version"] == committed["schema_version"]
    assert packaged["benchmark_version"] == committed["benchmark_version"]
    assert packaged["policy_version"] == committed["policy_version"]
    assert packaged["corpus"] == committed["corpus"]
    assert packaged["metrics"] == committed["metrics"]
    assert packaged["data_fingerprint"] == committed["data_fingerprint"]
    assert packaged["full_report_sha256"] == committed["full_report_sha256"]
    assert packaged["gate_failures"] == committed["gate_failures"]
    assert packaged["scope_note"] == committed["scope_note"]
