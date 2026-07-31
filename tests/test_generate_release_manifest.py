from __future__ import annotations

import hashlib
import io
import json
import sys
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))

import release_manifest_artifacts as ARTIFACTS  # noqa: E402
import release_manifest_gate as GATE  # noqa: E402


def root(tmp_path: Path) -> Path:
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "toxicjoin"\nversion = "0.1.0"\n',
        encoding="utf-8",
    )
    return tmp_path


def run(
    name: str,
    source_sha: str,
    index: int,
    *,
    branch: str = "feature",
    conclusion: str = "success",
) -> dict[str, Any]:
    return {
        "id": 1000 + index,
        "name": name,
        "run_number": index,
        "run_attempt": 1,
        "event": "pull_request",
        "head_branch": branch,
        "head_sha": source_sha,
        "status": "completed",
        "conclusion": conclusion,
        "html_url": f"https://example.invalid/runs/{1000 + index}",
        "created_at": "2026-07-31T00:00:00Z",
        "updated_at": "2026-07-31T00:01:00Z",
    }


def runs(source_sha: str, *, branch: str = "feature") -> list[dict[str, Any]]:
    return [
        run(name, source_sha, index, branch=branch)
        for index, name in enumerate(GATE.REQUIRED_WORKFLOWS, start=1)
    ]


def zip_bytes(files: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()


def metadata(name: str, data: bytes, *, expired: bool = False) -> dict[str, Any]:
    return {
        "id": 42,
        "name": name,
        "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
        "expired": expired,
        "size_in_bytes": len(data),
        "created_at": "2026-07-31T00:00:00Z",
        "expires_at": "2026-08-30T00:00:00Z",
    }


def bundle(name: str, files: dict[str, bytes]) -> ARTIFACTS.ArtifactBundle:
    data = zip_bytes(files)
    return ARTIFACTS.build_artifact_bundle(metadata(name, data), data)


def test_required_workflows_cover_every_phase7_category() -> None:
    assert GATE.REQUIRED_WORKFLOWS == (
        "CI",
        "Ground Truth Baseline",
        "CodeQL",
        "Supply Chain Security",
        "Governance Dependency Evidence",
        "Adversarial Mutation Evidence",
        "Compositional Ablation Evidence",
        "Phase 4 Portability Evidence",
        "Phase 5 Exact-SHA Live DataHub Evidence",
        "Phase 6 Production Browser E2E",
        "Disclosure Sequence Evidence",
    )
    assert "Secret History Security" not in GATE.REQUIRED_WORKFLOWS


def test_candidate_selection_binds_exact_sha_and_branch() -> None:
    source_sha = "a" * 40
    selected, pending = GATE.select_gate_runs(
        runs=runs(source_sha),
        source_sha=source_sha,
        expected_head_branch="feature",
    )
    assert pending == []
    assert set(selected) == set(GATE.REQUIRED_WORKFLOWS)


def test_selection_rejects_newer_skipped_run() -> None:
    source_sha = "b" * 40
    candidates = runs(source_sha)
    candidates.append(run("CI", source_sha, 999, conclusion="skipped"))
    with pytest.raises(ValueError, match="concluded 'skipped'"):
        GATE.select_gate_runs(
            runs=candidates,
            source_sha=source_sha,
            expected_head_branch="feature",
        )


def test_selection_reports_stale_or_missing_workflow() -> None:
    source_sha = "c" * 40
    candidates = [item for item in runs(source_sha) if item["name"] != "CodeQL"]
    candidates.append(run("CodeQL", "d" * 40, 999))
    selected, pending = GATE.select_gate_runs(
        runs=candidates,
        source_sha=source_sha,
        expected_head_branch="feature",
    )
    assert "CodeQL" not in selected
    assert pending == ["CodeQL:missing"]


def test_artifact_rejects_expiry_digest_mismatch_and_traversal() -> None:
    data = zip_bytes({"evidence.json": b"{}"})
    with pytest.raises(ValueError, match="expired"):
        ARTIFACTS.build_artifact_bundle(metadata("x", data, expired=True), data)
    bad = metadata("x", data)
    bad["digest"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError, match="digest mismatch"):
        ARTIFACTS.build_artifact_bundle(bad, data)
    unsafe = zip_bytes({"../escape.json": b"{}"})
    with pytest.raises(ValueError, match="unsafe path"):
        ARTIFACTS.build_artifact_bundle(metadata("x", unsafe), unsafe)


def test_ci_validator_requires_clean_benchmark_ppmc_and_diagnostics() -> None:
    benchmark = {
        "schema_version": "1.0",
        "metrics": {
            "total_cases": 30,
            "fully_passed": 30,
            "false_allow_count": 0,
            "unsafe_effective_allow_count": 0,
        },
    }
    ppmc = {"schema_version": "1.0", "gate_passed": True}
    ppmc_raw = json.dumps(ppmc).encode()
    bundles = {
        "toxicjoin-benchmark": bundle(
            "toxicjoin-benchmark",
            {"benchmark.json": json.dumps(benchmark).encode()},
        ),
        "toxicjoin-ppmc-hard-gate": bundle(
            "toxicjoin-ppmc-hard-gate",
            {
                "ppmc-hard-gate.json": ppmc_raw,
                "ppmc-hard-gate.sha256": (
                    hashlib.sha256(ppmc_raw).hexdigest()
                    + "  ppmc-hard-gate.json\n"
                ).encode(),
            },
        ),
        "toxicjoin-container-log": bundle(
            "toxicjoin-container-log", {"container.log": b"ready\n"}
        ),
        "pytest-3.11.15": bundle(
            "pytest-3.11.15", {"pytest.log": b"860 passed\n"}
        ),
        "pytest-3.12.13": bundle(
            "pytest-3.12.13", {"pytest.log": b"860 passed\n"}
        ),
    }
    result = ARTIFACTS.validate_ci(bundles, "e" * 40)
    assert result["benchmark_total_cases"] == 30
    assert result["ppmc_gate_passed"] is True


def topology_payload(source_sha: str) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "source_sha": source_sha,
        "state_topology": "SINGLE_NODE",
        "multi_replica_supported": False,
        "multi_replica_fail_closed": True,
        "shared_authoritative_backend": False,
        "postgresql_canonical": False,
        "phase12_required_for_shared_backend": True,
    }
    payload["report_sha256"] = ARTIFACTS.canonical_sha256(payload)
    return payload


def test_topology_validator_rejects_premature_postgresql_claim() -> None:
    source_sha = "f" * 40
    payload = topology_payload(source_sha)
    evidence = bundle(
        "toxicjoin-disclosure-sequence-evidence",
        {"topology-evidence.json": json.dumps(payload).encode()},
    )
    result = ARTIFACTS.validate_topology(
        {"toxicjoin-disclosure-sequence-evidence": evidence},
        source_sha,
    )
    assert result["state_topology"] == "SINGLE_NODE"
    payload["postgresql_canonical"] = True
    payload["report_sha256"] = ARTIFACTS.canonical_sha256(
        {key: value for key, value in payload.items() if key != "report_sha256"}
    )
    invalid = bundle(
        "toxicjoin-disclosure-sequence-evidence",
        {"topology-evidence.json": json.dumps(payload).encode()},
    )
    with pytest.raises(ValueError, match="premature PostgreSQL"):
        ARTIFACTS.validate_topology(
            {"toxicjoin-disclosure-sequence-evidence": invalid},
            source_sha,
        )


def test_candidate_and_release_identity_are_distinct(tmp_path: Path) -> None:
    source_sha = "1" * 40
    base_sha = "2" * 40
    selected = {
        name: run(name, source_sha, index)
        for index, name in enumerate(GATE.REQUIRED_WORKFLOWS, 1)
    }
    empty_specs = {
        name: ARTIFACTS.GateSpec() for name in GATE.REQUIRED_WORKFLOWS
    }
    manifest = GATE.build_release_manifest(
        root=root(tmp_path),
        mode=GATE.MODE_CANDIDATE,
        source_sha=source_sha,
        checked_out_sha=source_sha,
        expected_head_branch="feature",
        current_main_sha=base_sha,
        base_main_sha=base_sha,
        selected_runs=selected,
        bundles_by_workflow={name: {} for name in GATE.REQUIRED_WORKFLOWS},
        jobs_by_workflow={name: [] for name in GATE.REQUIRED_WORKFLOWS},
        environment={},
        gate_specs=empty_specs,
    )
    assert manifest["identity"]["candidate_is_not_release_identity"] is True
    assert manifest["claim_boundaries"]["postgresql_canonical"] is False
    with pytest.raises(ValueError, match="source_sha to be current main"):
        GATE.build_release_manifest(
            root=root(tmp_path),
            mode=GATE.MODE_RELEASE,
            source_sha=source_sha,
            checked_out_sha=source_sha,
            expected_head_branch="main",
            current_main_sha=base_sha,
            base_main_sha=base_sha,
            selected_runs=selected,
            bundles_by_workflow={name: {} for name in GATE.REQUIRED_WORKFLOWS},
            jobs_by_workflow={name: [] for name in GATE.REQUIRED_WORKFLOWS},
            environment={},
            gate_specs=empty_specs,
        )


def test_download_does_not_forward_bearer_to_signed_host(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    signed_url = "https://signed.example/artifact.zip?sig=test"
    authenticated_headers: dict[str, str] = {}
    signed_headers: dict[str, str] = {}

    class RedirectingOpener:
        def open(self, request: urllib.request.Request, timeout: int) -> Any:
            authenticated_headers.update(dict(request.header_items()))
            raise urllib.error.HTTPError(
                request.full_url,
                302,
                "Found",
                {"Location": signed_url},
                None,
            )

    class SignedResponse:
        def __enter__(self) -> "SignedResponse":
            return self

        def __exit__(self, *args: Any) -> None:
            return None

        def read(self, limit: int) -> bytes:
            return b"artifact-zip"

    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *handlers: RedirectingOpener(),
    )

    def fake_urlopen(
        request: urllib.request.Request,
        timeout: int,
    ) -> SignedResponse:
        signed_headers.update(dict(request.header_items()))
        return SignedResponse()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    client = GATE.Phase7GitHubApi(
        repository="Z3X-1337/toxicjoin",
        token="test-token",
    )
    assert client.download_artifact(artifact_id=123) == b"artifact-zip"
    assert authenticated_headers.get("Authorization") == "Bearer test-token"
    assert "Authorization" not in signed_headers


def test_phase5_and_phase6_contract_files_are_present() -> None:
    phase5 = (SCRIPTS / "phase5_manifest_validator.py").read_text(encoding="utf-8")
    phase6 = (SCRIPTS / "phase6_browser_release_manifest_contract.mjs").read_text(
        encoding="utf-8"
    )
    assert "phase5-exact-sha-live-datahub-evidence" in phase5
    assert "requiredMatrixCells: 6" in phase6
    assert "fakeOrGeneratedUiAllowed: false" in phase6
