"""Build, hash, persist, and verify immutable ToxicJoin receipts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import sqlglot
from pydantic import BaseModel
from sqlglot import exp

from toxicjoin.context.fixture import ContextResolution
from toxicjoin.models import PolicyDecision
from toxicjoin.receipts.models import (
    DecisionReceipt,
    ReceiptColumnEvidence,
    ReceiptExecutionSummary,
    ReceiptMode,
    ReceiptSqlEvidence,
    ReceiptVerificationCheck,
    ReceiptWriteback,
)
from toxicjoin.verify import VerificationResult


_RECEIPT_ID = re.compile(r"^tj_[0-9a-f]{16}$")
_HASH_EXCLUDED_FIELDS = {"receipt_id", "created_at", "content_sha256"}


def sanitize_sql(sql: str, *, dialect: str = "duckdb") -> str:
    """Return formatted SQL with every literal value replaced by a placeholder.

    Sanitization is display-only. The original SQL hash remains the authoritative
    identity and the sanitized text is never executed.
    """

    root = sqlglot.parse_one(sql, read=dialect)

    def redact(node: exp.Expression) -> exp.Expression:
        if isinstance(node, exp.Literal):
            return exp.Placeholder()
        return node

    return root.transform(redact, copy=True).sql(dialect=dialect, pretty=True)


def build_receipt(
    *,
    task_purpose: str,
    mode: ReceiptMode,
    original_sql: str,
    initial_decision: PolicyDecision,
    context: ContextResolution,
    safe_sql: str | None = None,
    final_decision: PolicyDecision | None = None,
    verification: VerificationResult | None = None,
    writeback: ReceiptWriteback | None = None,
    include_sanitized_sql: bool = False,
    dialect: str = "duckdb",
    receipt_id: str | None = None,
    created_at: datetime | None = None,
) -> DecisionReceipt:
    """Build a strict receipt without copying raw result rows into the payload."""

    resolved_receipt_id = receipt_id or f"tj_{uuid4().hex[:16]}"
    resolved_created_at = (created_at or datetime.now(timezone.utc)).astimezone(timezone.utc)

    sql_evidence = ReceiptSqlEvidence(
        original_sha256=_sha256_text(original_sql),
        safe_sha256=_sha256_text(safe_sql) if safe_sql is not None else None,
        sanitized_original=(
            sanitize_sql(original_sql, dialect=dialect)
            if include_sanitized_sql
            else None
        ),
        sanitized_safe=(
            sanitize_sql(safe_sql, dialect=dialect)
            if include_sanitized_sql and safe_sql is not None
            else None
        ),
    )

    column_evidence = tuple(
        ReceiptColumnEvidence(
            dataset=column.ref.dataset,
            field_path=column.ref.field_path,
            category=column.category,
            datahub_urn=column.datahub_urn,
            tags=tuple(sorted(column.tags)),
            glossary_terms=tuple(sorted(column.glossary_terms)),
            resolved=column.resolved,
        )
        for column in sorted(
            context.all_referenced_context,
            key=lambda value: value.ref.key,
        )
    )

    verification_checks = tuple(
        ReceiptVerificationCheck(
            name=check.name,
            passed=check.passed,
            detail=check.detail,
        )
        for check in (verification.checks if verification is not None else ())
    )

    execution_summary = None
    if verification is not None and verification.execution is not None:
        execution = verification.execution
        execution_summary = ReceiptExecutionSummary(
            query_sha256=execution.query_sha256,
            columns=execution.columns,
            preview_row_count=execution.preview_row_count,
            truncated=execution.truncated,
            elapsed_ms=round(execution.elapsed_ms, 6),
        )

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "receipt_id": resolved_receipt_id,
        "created_at": resolved_created_at,
        "mode": mode,
        "task_purpose": task_purpose,
        "initial_decision": initial_decision.decision,
        "initial_reason_codes": initial_decision.reason_codes,
        "final_decision": final_decision.decision if final_decision is not None else None,
        "final_reason_codes": (
            final_decision.reason_codes if final_decision is not None else ()
        ),
        "policy_version": initial_decision.policy_version,
        "sql": sql_evidence,
        "columns": column_evidence,
        "verification": verification_checks,
        "execution": execution_summary,
        "writeback": writeback or ReceiptWriteback(),
        "content_sha256": "0" * 64,
    }
    payload["content_sha256"] = compute_content_hash(payload)
    return DecisionReceipt.model_validate(payload)


def compute_content_hash(receipt_or_payload: BaseModel | Mapping[str, Any]) -> str:
    """Hash deterministic receipt content, excluding ID, time, and the hash field."""

    if isinstance(receipt_or_payload, BaseModel):
        payload = receipt_or_payload.model_dump(mode="json")
    else:
        payload = _json_compatible(dict(receipt_or_payload))

    canonical_payload = {
        key: value
        for key, value in payload.items()
        if key not in _HASH_EXCLUDED_FIELDS
    }
    canonical = json.dumps(
        canonical_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class ReceiptStore:
    """Filesystem receipt store with exclusive atomic creation and tamper checks."""

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    def write(self, receipt: DecisionReceipt) -> Path:
        self._verify_hash(receipt)
        self.root.mkdir(parents=True, exist_ok=True)
        target = self._path_for(receipt.receipt_id)
        encoded = (
            json.dumps(
                receipt.model_dump(mode="json"),
                sort_keys=True,
                indent=2,
                ensure_ascii=True,
            )
            + "\n"
        ).encode("utf-8")

        if target.exists():
            existing = self.read(receipt.receipt_id)
            if existing == receipt:
                return target
            raise FileExistsError(f"receipt already exists with different content: {target}")

        temp_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=self.root,
                prefix=f".{receipt.receipt_id}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temp_path = Path(handle.name)
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_path, 0o600)

            try:
                os.link(temp_path, target)
            except FileExistsError:
                existing = self.read(receipt.receipt_id)
                if existing != receipt:
                    raise FileExistsError(
                        f"receipt concurrently created with different content: {target}"
                    )
            except OSError:
                # Portable exclusive fallback for filesystems without hard-link support.
                descriptor = os.open(
                    target,
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
                try:
                    with os.fdopen(descriptor, "wb") as output:
                        output.write(encoded)
                        output.flush()
                        os.fsync(output.fileno())
                except Exception:
                    target.unlink(missing_ok=True)
                    raise
        finally:
            if temp_path is not None:
                temp_path.unlink(missing_ok=True)

        stored = self.read(receipt.receipt_id)
        if stored != receipt:
            raise ValueError("stored receipt differs from the validated input")
        return target

    def read(self, receipt_id: str) -> DecisionReceipt:
        path = self._path_for(receipt_id)
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except OSError as exc:
            raise FileNotFoundError(f"receipt not found: {receipt_id}") from exc
        except json.JSONDecodeError as exc:
            raise ValueError(f"receipt is not valid JSON: {receipt_id}") from exc

        receipt = DecisionReceipt.model_validate(raw)
        self._verify_hash(receipt)
        return receipt

    def _path_for(self, receipt_id: str) -> Path:
        if not _RECEIPT_ID.fullmatch(receipt_id):
            raise ValueError("invalid receipt ID")
        return self.root / f"{receipt_id}.json"

    @staticmethod
    def _verify_hash(receipt: DecisionReceipt) -> None:
        expected = compute_content_hash(receipt)
        if receipt.content_sha256 != expected:
            raise ValueError(
                f"receipt content hash mismatch: expected {expected}, "
                f"received {receipt.content_sha256}"
            )


def _sha256_text(value: str | None) -> str | None:
    if value is None:
        return None
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _json_compatible(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat()
    if isinstance(value, Mapping):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_compatible(item) for item in value]
    if hasattr(value, "value") and isinstance(value.value, str):
        return value.value
    return value
