from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from toxicjoin.context.fixture import ContextResolution
from toxicjoin.execute import ExecutionResult
from toxicjoin.models import (
    ColumnContext,
    ColumnRef,
    Decision,
    PolicyDecision,
    QueryPlan,
    ReasonCode,
    SensitivityCategory,
)
from toxicjoin.receipts import (
    DecisionReceipt,
    ReceiptMode,
    ReceiptStore,
    build_receipt,
    compute_content_hash,
    sanitize_sql,
)
from toxicjoin.verify import VerificationCheck, VerificationResult


ORIGINAL_SQL = """
SELECT c.coarse_region, AVG(r.churn_score) AS average_churn,
       COUNT(DISTINCT c.customer_id) AS subject_count
FROM customers c
JOIN retention_scores r ON c.customer_id = r.customer_id
WHERE r.churn_score >= 0.9 AND c.coarse_region = 'central'
GROUP BY c.coarse_region
"""

SAFE_SQL = ORIGINAL_SQL + "\nHAVING COUNT(DISTINCT c.customer_id) >= 20"
SUBJECT = ColumnRef(dataset="customers", field_path="customer_id", alias="c")
PLAN = QueryPlan(
    statement_type="SELECT",
    source_datasets=("customers", "retention_scores"),
    projected_columns=(
        ColumnRef(dataset="customers", field_path="coarse_region", alias="c"),
        ColumnRef(dataset="retention_scores", field_path="churn_score", alias="r"),
        SUBJECT,
    ),
    referenced_columns=(
        ColumnRef(dataset="customers", field_path="coarse_region", alias="c"),
        SUBJECT,
        ColumnRef(dataset="retention_scores", field_path="churn_score", alias="r"),
        ColumnRef(dataset="retention_scores", field_path="customer_id", alias="r"),
    ),
    join_columns=(
        SUBJECT,
        ColumnRef(dataset="retention_scores", field_path="customer_id", alias="r"),
    ),
    group_by_columns=(
        ColumnRef(dataset="customers", field_path="coarse_region", alias="c"),
    ),
    aggregate_functions=("AVG", "COUNT"),
    minimum_group_size_present=20,
    minimum_group_size_subject=SUBJECT,
    is_grouped=True,
)


def _context() -> ContextResolution:
    return ContextResolution(
        projected_context=(
            ColumnContext(
                ref=ColumnRef(
                    dataset="customers",
                    field_path="coarse_region",
                    alias="c",
                ),
                category=SensitivityCategory.QUASI_IDENTIFIER,
                datahub_urn=(
                    "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.customers,PROD)"
                ),
                tags=("toxicjoin:coarse-location",),
            ),
            ColumnContext(
                ref=ColumnRef(
                    dataset="retention_scores",
                    field_path="churn_score",
                    alias="r",
                ),
                category=SensitivityCategory.SENSITIVE_ATTRIBUTE,
                datahub_urn=(
                    "urn:li:dataset:(urn:li:dataPlatform:duckdb,"
                    "toxicjoin.retention_scores,PROD)"
                ),
                tags=("toxicjoin:model-output",),
            ),
        ),
        all_referenced_context=(
            ColumnContext(
                ref=ColumnRef(
                    dataset="customers",
                    field_path="coarse_region",
                    alias="c",
                ),
                category=SensitivityCategory.QUASI_IDENTIFIER,
                datahub_urn=(
                    "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.customers,PROD)"
                ),
            ),
            ColumnContext(
                ref=SUBJECT,
                category=SensitivityCategory.STABLE_PSEUDONYM,
                datahub_urn=(
                    "urn:li:dataset:(urn:li:dataPlatform:duckdb,toxicjoin.customers,PROD)"
                ),
            ),
            ColumnContext(
                ref=ColumnRef(
                    dataset="retention_scores",
                    field_path="churn_score",
                    alias="r",
                ),
                category=SensitivityCategory.SENSITIVE_ATTRIBUTE,
                datahub_urn=(
                    "urn:li:dataset:(urn:li:dataPlatform:duckdb,"
                    "toxicjoin.retention_scores,PROD)"
                ),
            ),
            ColumnContext(
                ref=ColumnRef(
                    dataset="retention_scores",
                    field_path="customer_id",
                    alias="r",
                ),
                category=SensitivityCategory.STABLE_PSEUDONYM,
                datahub_urn=(
                    "urn:li:dataset:(urn:li:dataPlatform:duckdb,"
                    "toxicjoin.retention_scores,PROD)"
                ),
            ),
        ),
    )


def _initial_decision() -> PolicyDecision:
    return PolicyDecision(
        decision=Decision.REWRITE,
        reason_codes=(ReasonCode.SMALL_GROUP_RISK,),
        policy_version="0.1.0",
        evidence={"required_minimum_group_size": 20},
        rewrite_required=True,
    )


def _final_decision() -> PolicyDecision:
    return PolicyDecision(
        decision=Decision.ALLOW,
        reason_codes=(ReasonCode.NO_COMPOSITIONAL_RISK,),
        policy_version="0.1.0",
        evidence={"trusted_minimum_group_size": 20},
    )


def _verification(*, include_secret_row: bool = True) -> VerificationResult:
    rows = (("central", 0.8123, 40, "RAW_SECRET_VALUE"),) if include_secret_row else ()
    execution = ExecutionResult(
        authorization_id="tj_auth_" + "0" * 32,
        query_sha256="a" * 64,
        query_plan=PLAN,
        columns=("coarse_region", "average_churn", "subject_count", "internal_debug"),
        rows=rows,
        preview_row_count=len(rows),
        truncated=False,
        elapsed_ms=1.23456789,
    )
    return VerificationResult(
        passed=True,
        query_plan=PLAN,
        policy_decision=_final_decision(),
        checks=(
            VerificationCheck(
                name="policy_allow",
                passed=True,
                detail="final deterministic decision is ALLOW",
            ),
            VerificationCheck(
                name="observed_group_sizes",
                passed=True,
                detail="minimum observed group size is 40",
            ),
        ),
        execution=execution,
    )


def _receipt(
    *,
    receipt_id: str = "tj_0123456789abcdef",
    created_at: datetime = datetime(2026, 7, 22, 20, 0, tzinfo=timezone.utc),
) -> DecisionReceipt:
    return build_receipt(
        task_purpose="Find regions with elevated churn risk",
        mode=ReceiptMode.FIXTURE,
        original_sql=ORIGINAL_SQL,
        safe_sql=SAFE_SQL,
        initial_decision=_initial_decision(),
        final_decision=_final_decision(),
        context=_context(),
        verification=_verification(),
        include_sanitized_sql=True,
        receipt_id=receipt_id,
        created_at=created_at,
    )


def test_receipt_preserves_rewrite_to_allow_lifecycle() -> None:
    receipt = _receipt()

    assert receipt.initial_decision == Decision.REWRITE
    assert receipt.initial_reason_codes == (ReasonCode.SMALL_GROUP_RISK,)
    assert receipt.final_decision == Decision.ALLOW
    assert receipt.final_reason_codes == (ReasonCode.NO_COMPOSITIONAL_RISK,)
    assert receipt.execution is not None
    assert receipt.execution.preview_row_count == 1


def test_receipt_never_contains_raw_execution_rows() -> None:
    receipt = _receipt()
    encoded = receipt.model_dump_json()

    assert "RAW_SECRET_VALUE" not in encoded
    assert '"rows"' not in encoded
    assert receipt.execution is not None
    assert receipt.execution.columns[-1] == "internal_debug"


def test_sanitized_sql_redacts_literal_values() -> None:
    sanitized = sanitize_sql(ORIGINAL_SQL)

    assert "central" not in sanitized
    assert "0.9" not in sanitized
    assert "?" in sanitized


def test_content_hash_is_independent_of_id_and_time() -> None:
    first = _receipt()
    second = _receipt(
        receipt_id="tj_fedcba9876543210",
        created_at=datetime(2026, 7, 23, 20, 0, tzinfo=timezone.utc),
    )

    assert first.content_sha256 == second.content_sha256
    assert compute_content_hash(first) == first.content_sha256
    assert compute_content_hash(second) == second.content_sha256


def test_store_writes_reads_and_is_idempotent(tmp_path) -> None:
    receipt = _receipt()
    store = ReceiptStore(tmp_path / "receipts")

    first_path = store.write(receipt)
    second_path = store.write(receipt)
    loaded = store.read(receipt.receipt_id)

    assert first_path == second_path
    assert loaded == receipt
    assert first_path.stat().st_size > 0


def test_store_detects_tampering(tmp_path) -> None:
    receipt = _receipt()
    store = ReceiptStore(tmp_path)
    path = store.write(receipt)
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["task_purpose"] = "tampered purpose"
    path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(ValueError, match="hash mismatch"):
        store.read(receipt.receipt_id)


def test_store_rejects_path_traversal_ids(tmp_path) -> None:
    store = ReceiptStore(tmp_path)

    with pytest.raises(ValueError, match="invalid receipt ID"):
        store.read("../../etc/passwd")


def test_strict_schema_rejects_unknown_fields() -> None:
    payload = _receipt().model_dump(mode="json")
    payload["raw_rows"] = [["secret"]]

    with pytest.raises(ValidationError):
        DecisionReceipt.model_validate(payload)


def test_execution_requires_all_verification_checks_to_pass() -> None:
    receipt = _receipt()
    payload = receipt.model_dump(mode="json")
    payload["verification"][0]["passed"] = False
    payload["content_sha256"] = "0" * 64

    with pytest.raises(ValidationError, match="verification checks"):
        DecisionReceipt.model_validate(payload)


def test_hash_changes_when_semantic_content_changes() -> None:
    receipt = _receipt()
    payload = receipt.model_dump(mode="json")
    payload["task_purpose"] = "Different governed purpose"

    assert compute_content_hash(payload) != receipt.content_sha256


def test_created_at_normalizes_to_utc() -> None:
    receipt = _receipt(
        created_at=datetime(
            2026,
            7,
            22,
            23,
            0,
            tzinfo=timezone(timedelta(hours=3)),
        )
    )

    assert receipt.created_at == datetime(2026, 7, 22, 20, 0, tzinfo=timezone.utc)
