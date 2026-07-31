from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "phase6-browser-e2e.yml"
SCRIPT_FILES = (
    ROOT / "scripts" / "phase6_browser_common.mjs",
    ROOT / "scripts" / "phase6_browser_assertions.mjs",
    ROOT / "scripts" / "phase6_browser_paths.mjs",
    ROOT / "scripts" / "phase6_browser_e2e.mjs",
)
ACCEPTANCE = ROOT / "docs" / "phase6-acceptance.md"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_phase6_workflow_uses_exact_source_and_production_container() -> None:
    workflow = _read(WORKFLOW)

    assert 'PHASE6_SOURCE_SHA: ${{ github.event.pull_request.head.sha || github.sha }}' in workflow
    assert "ref: ${{ env.PHASE6_SOURCE_SHA }}" in workflow
    assert "persist-credentials: false" in workflow
    assert "runs-on: ubuntu-24.04" in workflow
    assert 'node-version: "22.16.0"' in workflow
    assert 'python-version: "3.12.13"' in workflow
    assert 'python -m pip install --disable-pip-version-check "uv==0.8.4"' in workflow
    assert "npm ci --no-audit --no-fund" in workflow
    assert (
        "node node_modules/playwright-core/cli.js install --with-deps "
        "chromium firefox webkit"
    ) in workflow

    assert "docker build --tag \"$PHASE6_IMAGE\"" in workflow
    assert "--read-only" in workflow
    assert "--tmpfs /tmp:rw,noexec,nosuid,size=64m" in workflow
    assert "--cap-drop ALL" in workflow
    assert "--security-opt no-new-privileges:true" in workflow
    assert "--mount type=volume,src=toxicjoin-phase6-runtime,dst=/var/lib/toxicjoin" in workflow

    assert "vite --host" not in workflow
    assert "npm run dev" not in workflow
    assert "playwright-real-production-browser" not in workflow
    assert "phase6-browser-e2e-evidence" in workflow
    assert 'scripts/phase6_browser_*.mjs' in workflow


def test_phase6_workflow_verifies_report_hash_with_generator_canonicalization() -> None:
    workflow = _read(WORKFLOW)

    assert 'import { canonicalJson, sha256Bytes } from "./scripts/phase6_browser_common.mjs";' in workflow
    assert 'sha256Bytes(Buffer.from(canonicalJson(report), "utf8"))' in workflow
    assert "report_sha256 mismatch" in workflow
    assert "json.dumps(" not in workflow
    assert "ensure_ascii=" not in workflow


def test_phase6_script_covers_required_browser_and_product_paths() -> None:
    script = "\n".join(_read(path) for path in SCRIPT_FILES)

    for browser in ("chromium", "firefox", "webkit"):
        assert browser in script
    for viewport in ('name: "desktop"', 'name: "mobile"'):
        assert viewport in script

    for scenario in (
        "rewrite-churn-regions",
        "allow-public-order-counts",
        "block-sensitive-export",
    ):
        assert scenario in script

    required_claims = (
        "receipt lookup failed",
        "RECEIPT_NOT_FOUND",
        "Protected execution did not complete",
        "Historical deterministic replay",
        "Replay — no live write claimed",
        "no live execution or DataHub write is being claimed",
        "content-security-policy",
        "x-frame-options",
        "permissions-policy",
        "horizontal_overflow_px",
        "unnamed_interactive",
        "visible_interactive_outside_viewport",
        "fake_or_generated_ui_used: false",
        "playwright-real-production-browser",
        "report_sha256",
        "SHA256SUMS",
    )
    for claim in required_claims:
        assert claim in script

    assert 'page.route("**/api/execute-safe"' in script
    assert 'page.route("**/api/**"' in script
    assert "source_mode: \"api\"" in script
    assert "source_mode: \"replay\"" in script
    assert "git\", [\"diff\", \"--exit-code\"]" in script
    assert "git\", [\"diff\", \"--cached\", \"--exit-code\"]" in script
    assert "waitForFunction" not in script


def test_phase6_acceptance_preserves_future_phase_boundaries() -> None:
    acceptance = _read(ACCEPTANCE)

    for requirement in (
        "Chromium",
        "Firefox",
        "WebKit",
        "desktop",
        "mobile",
        "ALLOW",
        "REWRITE",
        "BLOCK",
        "receipt lookup",
        "failure disclosure",
        "security headers",
        "accessibility",
        "responsive",
        "Replay",
        "exact candidate SHA",
    ):
        assert requirement in acceptance

    for boundary in (
        "Phase 7",
        "PR #118",
        "PostgreSQL",
        "Vercel",
        "Devpost",
        "tag",
        "release",
        "main",
    ):
        assert boundary in acceptance
