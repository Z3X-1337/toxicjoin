from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"
CI = ROOT / ".github" / "workflows" / "ci.yml"


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
