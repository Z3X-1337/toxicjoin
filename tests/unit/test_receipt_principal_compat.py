from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from toxicjoin.context.fixture import ContextResolution
from toxicjoin.models import Decision, PolicyDecision, ReasonCode
from toxicjoin.receipts import (
    DecisionReceipt,
    ReceiptMode,
    ReceiptStore,
    build_receipt,
    compute_content_hash,
)


def _decision() -> PolicyDecision:
    return PolicyDecision(
        decision=Decision.BLOCK,
        reason_codes=(ReasonCode.UNRESOLVED_COLUMN,),
        policy_version="0.2.0",
        evidence={"fail_closed": True},
    )


def _context() -> ContextResolution:
    return ContextResolution(
        projected_context=(),
        all_referenced_context=(),
        failures=(ReasonCode.UNRESOLVED_COLUMN,),
    )


def _receipt(principal_id: str):
    return build_receipt(
        task_purpose="Compatibility test",
        mode=ReceiptMode.FIXTURE,
        principal_id=principal_id,
        original_sql="SELECT 1",
        initial_decision=_decision(),
        context=_context(),
        receipt_id="tj_0123456789abcdef",
        created_at=datetime(2026, 7, 24, 9, 0, tzinfo=timezone.utc),
    )


def test_v11_receipt_hash_binds_principal_identity() -> None:
    alice = _receipt("alice")
    bob = _receipt("bob")

    assert alice.schema_version == "1.1"
    assert alice.principal_id == "alice"
    assert bob.principal_id == "bob"
    assert alice.content_sha256 != bob.content_sha256


def test_v11_receipt_requires_principal_identity() -> None:
    payload = _receipt("alice").model_dump(mode="json")
    payload["principal_id"] = None

    with pytest.raises(ValidationError, match="schema 1.1 receipts require principal_id"):
        DecisionReceipt.model_validate(payload)


def test_receipt_rejects_unknown_schema_version() -> None:
    payload = _receipt("alice").model_dump(mode="json")
    payload["schema_version"] = "1.2"

    with pytest.raises(ValidationError):
        DecisionReceipt.model_validate(payload)


def test_v10_receipt_without_principal_remains_hash_verifiable(tmp_path) -> None:
    payload = _receipt("alice").model_dump(mode="json")
    payload["schema_version"] = "1.0"
    payload.pop("principal_id")
    payload["content_sha256"] = "0" * 64
    payload["content_sha256"] = compute_content_hash(payload)

    store = ReceiptStore(tmp_path)
    tmp_path.mkdir(parents=True, exist_ok=True)
    path = tmp_path / f"{payload['receipt_id']}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    loaded = store.read(payload["receipt_id"])
    assert loaded.schema_version == "1.0"
    assert loaded.principal_id is None
    assert loaded.content_sha256 == payload["content_sha256"]
