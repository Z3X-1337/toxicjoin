from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
PHASE9_WORKFLOW = ROOT / ".github/workflows/phase9-immutable-release.yml"
PHASE9_CONFIG = ROOT / "config/phase9-release.json"

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


def _load_github_actions_yaml(path: Path) -> dict[str, object]:
    """Parse GitHub Actions YAML without YAML 1.1 coercing ``on`` to ``True``."""

    class GitHubActionsLoader(yaml.SafeLoader):
        pass

    GitHubActionsLoader.yaml_implicit_resolvers = {
        key: [
            (tag, pattern)
            for tag, pattern in resolvers
            if tag != "tag:yaml.org,2002:bool"
        ]
        for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
    }
    GitHubActionsLoader.add_implicit_resolver(
        "tag:yaml.org,2002:bool",
        re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
        list("tTfF"),
    )

    parsed = yaml.load(path.read_text(encoding="utf-8"), Loader=GitHubActionsLoader)
    assert isinstance(parsed, dict)
    return parsed


def test_phase9_publish_contract_accepts_only_the_exact_main_manifest_chain() -> None:
    workflow = _load_github_actions_yaml(PHASE9_WORKFLOW)
    triggers = workflow["on"]
    assert isinstance(triggers, dict)
    assert set(triggers) == {"pull_request", "workflow_run"}

    workflow_run = triggers["workflow_run"]
    assert isinstance(workflow_run, dict)
    assert workflow_run == {
        "workflows": ["Generated Release Manifest"],
        "types": ["completed"],
    }

    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    publish = jobs["publish-and-verify-release"]
    assert isinstance(publish, dict)
    condition = " ".join(str(publish["if"]).split())
    assert condition == (
        "github.event_name == 'workflow_run' && "
        "github.event.workflow_run.conclusion == 'success' && "
        "github.event.workflow_run.head_branch == 'main' && "
        "github.event.workflow_run.event == 'workflow_run'"
    )

    environment = publish["env"]
    assert isinstance(environment, dict)
    assert environment["PHASE9_SOURCE_SHA"] == "${{ github.event.workflow_run.head_sha }}"
    assert environment["PHASE9_MANIFEST_RUN_ID"] == "${{ github.event.workflow_run.id }}"

    steps = publish["steps"]
    assert isinstance(steps, list)
    identity = next(step for step in steps if step["name"] == "Verify exact current-main identity")
    assert isinstance(identity, dict)
    identity_run = str(identity["run"])
    assert 'current_main="$(git ls-remote origin refs/heads/main | awk \'{print $1}\')"' in identity_run
    assert 'test "$current_main" = "$PHASE9_SOURCE_SHA"' in identity_run


def _publish_event_is_eligible(
    *,
    event_name: str,
    conclusion: str,
    head_branch: str,
    triggering_event: str,
    source_sha: str,
    current_main_sha: str,
) -> bool:
    """Mirror the trigger clauses plus the checked runtime main-SHA binding."""

    return (
        event_name == "workflow_run"
        and conclusion == "success"
        and head_branch == "main"
        and triggering_event == "workflow_run"
        and source_sha == current_main_sha
    )


@pytest.mark.parametrize(
    (
        "event_name",
        "conclusion",
        "head_branch",
        "triggering_event",
        "source_sha",
        "current_main_sha",
        "expected",
    ),
    [
        ("workflow_run", "success", "main", "workflow_run", "a" * 40, "a" * 40, True),
        ("pull_request", "success", "main", "workflow_run", "a" * 40, "a" * 40, False),
        ("workflow_run", "success", "feature", "workflow_run", "a" * 40, "a" * 40, False),
        ("workflow_run", "failure", "main", "workflow_run", "a" * 40, "a" * 40, False),
        ("workflow_run", "success", "main", "push", "a" * 40, "a" * 40, False),
        ("workflow_run", "success", "main", "workflow_run", "a" * 40, "b" * 40, False),
    ],
)
def test_phase9_publish_event_eligibility_matrix(
    event_name: str,
    conclusion: str,
    head_branch: str,
    triggering_event: str,
    source_sha: str,
    current_main_sha: str,
    expected: bool,
) -> None:
    assert _publish_event_is_eligible(
        event_name=event_name,
        conclusion=conclusion,
        head_branch=head_branch,
        triggering_event=triggering_event,
        source_sha=source_sha,
        current_main_sha=current_main_sha,
    ) is expected



def test_phase9_preview_preserves_preexisting_release_state() -> None:
    workflow = _load_github_actions_yaml(PHASE9_WORKFLOW)
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    preview = jobs["release-preview"]
    assert isinstance(preview, dict)
    steps = preview["steps"]
    assert isinstance(steps, list)

    before = next(
        step
        for step in steps
        if step["name"] == "Snapshot configured tag and Release before preview"
    )
    after = next(
        step
        for step in steps
        if step["name"] == "Verify pull-request run did not mutate tag or Release"
    )
    before_run = str(before["run"])
    after_run = str(after["run"])
    content = PHASE9_WORKFLOW.read_text(encoding="utf-8")

    assert "release-state-before/tag.json" in before_run
    assert "release-state-before/release.json" in before_run
    assert "release-state-after/tag.json" in after_run
    assert "release-state-after/release.json" in after_run
    assert 'if ! cmp -s "$before" "$after"; then' in after_run
    assert "Configured tag and Release state remained unchanged" in after_run
    assert "Refusing preview: tag" not in content
    assert "Refusing preview: Release" not in content

def test_phase9_immutable_release_identity_is_fixed() -> None:
    config = json.loads(PHASE9_CONFIG.read_text(encoding="utf-8"))
    assert config["version"] == "0.2.1"
    assert config["tag"] == "v0.2.1"
    assert config["release_name"] == "ToxicJoin v0.2.1"
    assert config["release_notes_template"] == "docs/releases/v0.2.1.md"
    assert config["draft"] is False
    assert config["prerelease"] is False
    assert config["immutable_identity"] is True


def test_release_identity_docs_distinguish_historical_v020_from_current_v021() -> None:
    notes = (ROOT / "docs/releases/v0.2.0.md").read_text(encoding="utf-8")
    reproducibility = (ROOT / "docs/reproducibility.md").read_text(encoding="utf-8")
    acceptance = (ROOT / "docs/phase9-acceptance.md").read_text(encoding="utf-8")

    assert notes.startswith("# ToxicJoin v0.2.0\n")
    assert reproducibility.startswith("# ToxicJoin v0.2.1 reproducibility\n")
    assert "project version `0.2.1`, tag `v0.2.1`" in acceptance
