from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "toxicjoin_phase3_bootstrap", ROOT / "scripts" / "bootstrap.py"
)
assert SPEC is not None and SPEC.loader is not None
BOOTSTRAP = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = BOOTSTRAP
SPEC.loader.exec_module(BOOTSTRAP)


def test_toolchain_contract_has_exact_supported_versions() -> None:
    contract = BOOTSTRAP.contract()

    assert contract["baseline_main_sha"] == "bb307a16df6157112531ec67ff635babb784a814"
    assert contract["python"]["supported_by_platform"] == {
        "linux": ["3.11.15", "3.12.13"],
        "windows": ["3.11.9", "3.12.10"],
        "macos": ["3.11.9", "3.12.10"],
    }
    assert contract["python"]["default_by_platform"] == {
        "linux": "3.12.13",
        "windows": "3.12.10",
        "macos": "3.12.10",
    }
    assert contract["uv"]["version"] == "0.8.4"
    assert contract["node"]["version"] == "22.16.0"
    assert contract["node"]["npm_version"] == "10.9.2"
    assert contract["datahub"]["mcp_server_version"] == "0.6.0"
    assert contract["datahub"]["phase3_status"] == "version-record-only-no-live-execution"


def test_manifest_authorities_consume_the_contract() -> None:
    contract = BOOTSTRAP.contract()
    assert BOOTSTRAP.manifest_errors(contract) == []


def test_all_committed_locks_are_present_and_hashable() -> None:
    hashes = BOOTSTRAP.lock_hashes(BOOTSTRAP.contract())

    assert set(hashes) == {
        "uv.lock",
        "package-lock.json",
        "apps/web/package-lock.json",
    }
    assert all(len(value) == 64 for value in hashes.values())


def test_canonical_bootstrap_has_no_lock_bypass() -> None:
    audit = BOOTSTRAP.audit()
    assert audit["violation_count"] == 0, json.dumps(
        audit["violations"], indent=2, sort_keys=True
    )


def test_platform_key_is_explicit(monkeypatch) -> None:
    monkeypatch.setattr(BOOTSTRAP.platform, "system", lambda: "Linux")
    assert BOOTSTRAP.platform_key() == "linux"

    monkeypatch.setattr(BOOTSTRAP.platform, "system", lambda: "Windows")
    assert BOOTSTRAP.platform_key() == "windows"

    monkeypatch.setattr(BOOTSTRAP.platform, "system", lambda: "Darwin")
    assert BOOTSTRAP.platform_key() == "macos"

    monkeypatch.setattr(BOOTSTRAP.platform, "system", lambda: "FreeBSD")
    try:
        BOOTSTRAP.platform_key()
    except BOOTSTRAP.BootstrapError:
        pass
    else:  # pragma: no cover
        raise AssertionError("unsupported platform did not fail closed")


def test_version_parser_rejects_unparseable_output() -> None:
    assert BOOTSTRAP.parse_version("uv 0.8.4", r"uv (\d+\.\d+\.\d+)", "uv") == "0.8.4"

    try:
        BOOTSTRAP.parse_version("not-a-version", r"(\d+\.\d+\.\d+)", "tool")
    except BOOTSTRAP.BootstrapError:
        pass
    else:  # pragma: no cover
        raise AssertionError("unparseable tool version did not fail closed")


def test_docker_verification_accepts_only_approved_buildx_versions(monkeypatch) -> None:
    def fake_run(command: list[str], **_: object) -> SimpleNamespace:
        if command[:2] == ["docker", "version"]:
            return SimpleNamespace(stdout="28.0.4|28.0.4\n")
        if command[:3] == ["docker", "buildx", "version"]:
            return SimpleNamespace(stdout="github.com/docker/buildx v0.35.0\n")
        if command[:3] == ["docker", "compose", "version"]:
            return SimpleNamespace(stdout="2.38.2\n")
        raise AssertionError(command)

    monkeypatch.setattr(
        BOOTSTRAP,
        "git_identity",
        lambda: {"commit_sha": "test", "tree_sha": "test"},
    )
    monkeypatch.setattr(BOOTSTRAP, "run", fake_run)
    assert BOOTSTRAP.verify(["docker"])["docker"]["buildx"] == "0.35.0"

    def unapproved_buildx(command: list[str], **_: object) -> SimpleNamespace:
        result = fake_run(command)
        if command[:3] == ["docker", "buildx", "version"]:
            return SimpleNamespace(stdout="github.com/docker/buildx v0.37.0\n")
        return result

    monkeypatch.setattr(BOOTSTRAP, "run", unapproved_buildx)
    try:
        BOOTSTRAP.verify(["docker"])
    except BOOTSTRAP.BootstrapError:
        pass
    else:  # pragma: no cover
        raise AssertionError("unapproved Docker Buildx version did not fail closed")
