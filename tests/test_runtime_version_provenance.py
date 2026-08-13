from __future__ import annotations

import json
import tomllib
from pathlib import Path

from toxicjoin.policy import load_policy


ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"
CI = ROOT / ".github" / "workflows" / "ci.yml"
PHASE9_CONFIG = ROOT / "config" / "phase9-release.json"
RETIRED_HOST = "ver" + "cel"


def test_production_image_installs_the_locked_project_after_dependency_caching() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")

    assert "python scripts/bootstrap.py sync --no-install-project" in dockerfile
    assert "COPY src/ ./src/" in dockerfile
    assert "RUN python scripts/bootstrap.py sync" in dockerfile
    assert "COPY --from=python-deps /app/src/ ./src/" in dockerfile


def test_container_ci_binds_readiness_version_to_project_metadata() -> None:
    workflow = CI.read_text(encoding="utf-8")

    assert 'importlib.metadata as m; print(m.version("toxicjoin"))' in workflow
    assert 'assert ready["version"] == expected_version' in workflow
    assert 'tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))' in workflow


def test_application_release_identity_is_021_while_policy_identity_remains_020() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    config = json.loads(PHASE9_CONFIG.read_text(encoding="utf-8"))
    uv_lock = tomllib.loads((ROOT / "uv.lock").read_text(encoding="utf-8"))
    root_package = json.loads((ROOT / "package.json").read_text(encoding="utf-8"))
    root_lock = json.loads((ROOT / "package-lock.json").read_text(encoding="utf-8"))
    web_package = json.loads((ROOT / "apps/web/package.json").read_text(encoding="utf-8"))
    web_lock = json.loads((ROOT / "apps/web/package-lock.json").read_text(encoding="utf-8"))

    assert project["project"]["version"] == "0.2.1"
    assert next(item for item in uv_lock["package"] if item["name"] == "toxicjoin")["version"] == "0.2.1"
    assert root_package["version"] == root_lock["version"] == "0.2.1"
    assert root_lock["packages"][""]["version"] == "0.2.1"
    assert web_package["version"] == web_lock["version"] == "0.2.1"
    assert web_lock["packages"][""]["version"] == "0.2.1"
    assert config["version"] == "0.2.1"
    assert config["tag"] == "v0.2.1"
    assert config["release_name"] == "ToxicJoin v0.2.1"
    assert config["release_notes_template"] == "docs/releases/v0.2.1.md"
    assert (ROOT / config["release_notes_template"]).is_file()
    assert load_policy().version == "0.2.0"


def test_current_release_sources_have_no_retired_host_reference() -> None:
    current_release_sources = (
        ROOT / "README.md",
        PHASE9_CONFIG,
        ROOT / "docs/releases/v0.2.1.md",
    )

    assert all(
        RETIRED_HOST not in path.read_text(encoding="utf-8").casefold()
        for path in current_release_sources
    )
