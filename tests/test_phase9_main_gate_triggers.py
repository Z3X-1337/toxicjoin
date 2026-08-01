from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

RELEASE_CRITICAL_MAIN_GATES = {
    ".github/workflows/disclosure-sequence-evidence.yml": "Disclosure Sequence Evidence",
    ".github/workflows/phase5-live-datahub.yml": "Phase 5 Exact-SHA Live DataHub Evidence",
    ".github/workflows/phase6-browser-e2e.yml": "Phase 6 Production Browser E2E",
}


def _trigger_block(workflow: Path) -> str:
    lines = workflow.read_text(encoding="utf-8").splitlines()
    start = lines.index("on:")
    block: list[str] = []
    for line in lines[start + 1 :]:
        if line and not line.startswith((" ", "\t")):
            break
        block.append(line)
    return "\n".join(block)


def test_release_critical_gates_run_automatically_on_exact_main() -> None:
    for relative_path, expected_name in RELEASE_CRITICAL_MAIN_GATES.items():
        workflow = ROOT / relative_path
        content = workflow.read_text(encoding="utf-8")
        trigger_block = _trigger_block(workflow)

        assert content.startswith(f"name: {expected_name}\n")
        assert re.search(
            r"(?m)^  push:\n    branches: \[main\]$",
            trigger_block,
        ), f"{expected_name} must run automatically on push to main"
        assert "  pull_request:" in trigger_block
        assert "  workflow_dispatch:" in trigger_block
        assert "github.event.pull_request.head.sha || github.sha" in content
