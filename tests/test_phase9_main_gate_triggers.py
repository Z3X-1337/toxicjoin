from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_RELEASE_GATES = {
    ".github/workflows/ci.yml": "CI",
    ".github/workflows/ground-truth-baseline.yml": "Ground Truth Baseline",
    ".github/workflows/codeql.yml": "CodeQL",
    ".github/workflows/supply-chain.yml": "Supply Chain Security",
    ".github/workflows/governance-dependency.yml": "Governance Dependency Evidence",
    ".github/workflows/adversarial-mutations.yml": "Adversarial Mutation Evidence",
    ".github/workflows/compositional-ablation.yml": "Compositional Ablation Evidence",
    ".github/workflows/disclosure-sequence-evidence.yml": "Disclosure Sequence Evidence",
    ".github/workflows/phase4-portability.yml": "Phase 4 Portability Evidence",
    ".github/workflows/phase5-live-datahub.yml": "Phase 5 Exact-SHA Live DataHub Evidence",
    ".github/workflows/phase6-browser-e2e.yml": "Phase 6 Production Browser E2E",
    ".github/workflows/phase8-durable-evidence.yml": "Phase 8 Durable Evidence Retention",
}

EXACT_SHA_GATES = {
    ".github/workflows/disclosure-sequence-evidence.yml",
    ".github/workflows/phase5-live-datahub.yml",
    ".github/workflows/phase6-browser-e2e.yml",
    ".github/workflows/phase8-durable-evidence.yml",
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


def test_all_release_gates_run_on_every_pr_and_exact_main() -> None:
    for relative_path, expected_name in REQUIRED_RELEASE_GATES.items():
        workflow = ROOT / relative_path
        content = workflow.read_text(encoding="utf-8")
        trigger_block = _trigger_block(workflow)

        assert content.startswith(f"name: {expected_name}\n")
        assert re.search(
            r"(?m)^  push:\n    branches: \[main\]$",
            trigger_block,
        ), f"{expected_name} must run automatically on push to main"
        assert re.search(
            r"(?m)^  pull_request:\s*$",
            trigger_block,
        ), f"{expected_name} must run on every pull-request head"
        assert "    paths:" not in trigger_block
        assert "    paths-ignore:" not in trigger_block


def test_exact_sha_gates_keep_dispatch_and_source_binding() -> None:
    for relative_path in EXACT_SHA_GATES:
        content = (ROOT / relative_path).read_text(encoding="utf-8")
        trigger_block = _trigger_block(ROOT / relative_path)

        assert "  workflow_dispatch:" in trigger_block
        assert "github.event.pull_request.head.sha || github.sha" in content
