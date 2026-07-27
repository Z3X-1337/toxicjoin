from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from toxicjoin.proofs.cli import main
from toxicjoin.proofs.models import PreExecutionPrivacyProof
from toxicjoin.proofs.preexec import (
    compute_preexecution_privacy_proof_hmac,
    compute_preexecution_privacy_proof_sha256,
)
from toxicjoin.prospective.ppmc import build_ppmc_search_config

KEY_TEXT = "proof-cli-integrity-key-at-least-32-bytes"
KEY = KEY_TEXT.encode("utf-8")
NOW = datetime(2026, 7, 25, 13, 0, tzinfo=timezone.utc)
H = "a" * 64


def _sealed_proof() -> PreExecutionPrivacyProof:
    proof = PreExecutionPrivacyProof(
        issued_at=NOW,
        expires_at=NOW + timedelta(seconds=30),
        request_identity_sha256=H,
        task_purpose_sha256=H,
        purpose_commitment_sha256=H,
        subject_key_sha256=H,
        sql_sha256=H,
        query_plan_sha256=H,
        governance_context_sha256=H,
        governance_binding_sha256=H,
        evidence_root_sha256=H,
        evidence_validation_sha256=H,
        disclosure_state_sha256=H,
        warehouse_snapshot_sha256=H,
        policy_sha256=H,
        policy_decision_sha256=H,
        grammar_sha256=H,
        ppmc_config_sha256=build_ppmc_search_config(
            bound=3,
            max_states=100,
        ).config_sha256,
        ppmc_forbidden_policy_sha256=H,
        ppmc_governance_binding_sha256=H,
        ppmc_search_transcript_sha256=H,
        ppmc_result_sha256=H,
        ppmc_bound=3,
        ppmc_max_states=100,
        privacy_proof_sha256="0" * 64,
        integrity_hmac_sha256="0" * 64,
    )
    content = compute_preexecution_privacy_proof_sha256(proof)
    proof = proof.model_copy(update={"privacy_proof_sha256": content})
    return proof.model_copy(
        update={
            "integrity_hmac_sha256": compute_preexecution_privacy_proof_hmac(
                proof,
                integrity_key=KEY,
            )
        }
    )


def test_cli_verifies_valid_proof(tmp_path, monkeypatch, capsys) -> None:
    proof = _sealed_proof()
    path = tmp_path / "proof.json"
    path.write_text(
        json.dumps(proof.model_dump(mode="json"), sort_keys=True),
        encoding="utf-8",
    )
    monkeypatch.setenv("TOXICJOIN_PRIVACY_PROOF_HMAC_KEY", KEY_TEXT)

    exit_code = main([str(path), "--now", "2026-07-25T13:00:01Z"])
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert output["valid"] is True
    assert output["failures"] == []
    assert output["privacy_proof_sha256"] == proof.privacy_proof_sha256


def test_cli_reports_missing_key_without_reading_secret_material(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    path = tmp_path / "proof.json"
    path.write_text("{}", encoding="utf-8")
    monkeypatch.delenv("TOXICJOIN_PRIVACY_PROOF_HMAC_KEY", raising=False)

    exit_code = main([str(path)])
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 2
    assert output == {"error": "PROOF_VERIFIER_KEY_UNAVAILABLE", "valid": False}


def test_cli_returns_nonzero_for_tampered_proof(tmp_path, monkeypatch, capsys) -> None:
    proof = _sealed_proof()
    payload = proof.model_dump(mode="json")
    payload["sql_sha256"] = "b" * 64
    path = tmp_path / "tampered.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    monkeypatch.setenv("TOXICJOIN_PRIVACY_PROOF_HMAC_KEY", KEY_TEXT)

    exit_code = main([str(path), "--now", "2026-07-25T13:00:01Z"])
    output = json.loads(capsys.readouterr().out)

    assert exit_code == 1
    assert output["valid"] is False
    assert output["failures"] == [
        "PROOF_CONTENT_HASH_MISMATCH",
        "PROOF_HMAC_MISMATCH",
    ]
