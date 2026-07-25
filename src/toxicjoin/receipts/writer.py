"""Build, authenticate, persist, and verify immutable ToxicJoin receipts."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import tempfile
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

import sqlglot
from pydantic import BaseModel
from sqlglot import exp

from toxicjoin.auth import RequestIdentity, current_request_identity
from toxicjoin.context.fixture import ContextResolution
from toxicjoin.context.governance import GovernanceContextBinding
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
_RECEIPT_HMAC_ENV = "TOXICJOIN_RECEIPT_HMAC_KEY"
_CONTENT_HASH_EXCLUDED_FIELDS = {"content_sha256", "integrity_hmac_sha256"}
_HMAC_EXCLUDED_FIELDS = {"integrity_hmac_sha256"}
_MIN_INTEGRITY_KEY_BYTES = 32


def allocate_receipt_id() -> str:
    """Allocate the opaque receipt identity before disclosure authorization begins."""

    return f"tj_{uuid4().hex[:16]}"


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
    identity: RequestIdentity | None = None,
    governance_binding: GovernanceContextBinding | None = None,
    safe_sql: str | None = None,
    final_decision: PolicyDecision | None = None,
    verification: VerificationResult | None = None,
    writeback: ReceiptWriteback | None = None,
    include_sanitized_sql: bool = False,
    dialect: str = "duckdb",
    receipt_id: str | None = None,
    created_at: datetime | None = None,
) -> DecisionReceipt:
    """Build an unsigned strict receipt without copying raw result rows.

    ``ReceiptStore.seal`` must authenticate the receipt before persistence or release.
    Keeping construction and authentication separate lets the store own the integrity
    secret instead of passing key material through policy/execution layers.
    """

    resolved_receipt_id = receipt_id or allocate_receipt_id()
    resolved_created_at = (created_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    resolved_identity = identity or current_request_identity()

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
            lineage_sources=tuple(
                sorted(column.lineage_sources, key=lambda source: source.ref.key)
            ),
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
        "schema_version": "1.5",
        "receipt_id": resolved_receipt_id,
        "created_at": resolved_created_at,
        "mode": mode,
        "identity": resolved_identity,
        "task_purpose": task_purpose,
        "initial_decision": initial_decision.decision,
        "initial_reason_codes": initial_decision.reason_codes,
        "initial_evidence": _json_compatible(initial_decision.evidence),
        "final_decision": final_decision.decision if final_decision is not None else None,
        "final_reason_codes": (
            final_decision.reason_codes if final_decision is not None else ()
        ),
        "final_evidence": (
            _json_compatible(final_decision.evidence)
            if final_decision is not None
            else {}
        ),
        "policy_version": initial_decision.policy_version,
        "governance": governance_binding,
        "sql": sql_evidence,
        "columns": column_evidence,
        "verification": verification_checks,
        "execution": execution_summary,
        "writeback": writeback or ReceiptWriteback(),
        "content_sha256": "0" * 64,
        "integrity_hmac_sha256": None,
    }
    payload["content_sha256"] = compute_content_hash(payload)
    return DecisionReceipt.model_validate(payload)


def compute_content_hash(receipt_or_payload: BaseModel | Mapping[str, Any]) -> str:
    """Hash the complete receipt identity/content except integrity fields themselves."""

    if isinstance(receipt_or_payload, BaseModel):
        payload = receipt_or_payload.model_dump(mode="json")
    else:
        payload = _json_compatible(dict(receipt_or_payload))

    canonical_payload = {
        key: value
        for key, value in payload.items()
        if key not in _CONTENT_HASH_EXCLUDED_FIELDS
        and not (key == "identity" and value is None)
    }
    canonical = _canonical_json(canonical_payload)
    return hashlib.sha256(canonical).hexdigest()


def compute_integrity_hmac(
    receipt_or_payload: BaseModel | Mapping[str, Any],
    *,
    integrity_key: bytes,
) -> str:
    """Authenticate the persisted receipt with a key not stored in receipt JSON."""

    _validate_integrity_key(integrity_key)
    if isinstance(receipt_or_payload, BaseModel):
        payload = receipt_or_payload.model_dump(mode="json")
    else:
        payload = _json_compatible(dict(receipt_or_payload))
    canonical_payload = {
        key: value for key, value in payload.items() if key not in _HMAC_EXCLUDED_FIELDS
    }
    return hmac.new(
        integrity_key,
        _canonical_json(canonical_payload),
        hashlib.sha256,
    ).hexdigest()


class ReceiptStore:
    """Filesystem receipt store with keyed authenticity and exclusive atomic creation.

    A caller may provide ``integrity_key`` directly, or configure
    ``TOXICJOIN_RECEIPT_HMAC_KEY`` with at least 32 UTF-8 bytes. Otherwise a random
    256-bit key is persisted outside the receipt directory in a sibling 0600 key file.
    If receipts already exist and that key disappears, initialization fails closed rather
    than silently generating a new key that would make old audit evidence unverifiable.
    """

    def __init__(
        self,
        root: str | Path,
        *,
        integrity_key: bytes | None = None,
        integrity_key_path: str | Path | None = None,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self.root = Path(root)
        self.integrity_key_path = (
            Path(integrity_key_path)
            if integrity_key_path is not None
            else self.root.parent / f".{self.root.name}.receipt-hmac.key"
        )
        self._integrity_key = self._resolve_integrity_key(
            integrity_key=integrity_key,
            environ=os.environ if environ is None else environ,
        )

    def seal(self, receipt: DecisionReceipt) -> DecisionReceipt:
        """Return a receipt authenticated by this store's integrity key."""

        self._verify_hash(receipt)
        sealed = receipt.model_copy(
            update={
                "integrity_hmac_sha256": compute_integrity_hmac(
                    receipt,
                    integrity_key=self._integrity_key,
                )
            }
        )
        self._verify_hmac(sealed)
        return sealed

    def write(self, receipt: DecisionReceipt) -> Path:
        self._verify_hash(receipt)
        self._verify_hmac(receipt)
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
        if receipt.receipt_id != receipt_id:
            raise ValueError(
                f"receipt identity mismatch: requested {receipt_id}, payload {receipt.receipt_id}"
            )
        self._verify_hash(receipt)
        self._verify_hmac(receipt)
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

    def _verify_hmac(self, receipt: DecisionReceipt) -> None:
        presented = receipt.integrity_hmac_sha256
        if presented is None:
            raise ValueError("receipt integrity HMAC is missing")
        expected = compute_integrity_hmac(
            receipt,
            integrity_key=self._integrity_key,
        )
        if not hmac.compare_digest(presented, expected):
            raise ValueError("receipt integrity HMAC mismatch")

    def _resolve_integrity_key(
        self,
        *,
        integrity_key: bytes | None,
        environ: Mapping[str, str],
    ) -> bytes:
        if integrity_key is not None:
            _validate_integrity_key(integrity_key)
            return bytes(integrity_key)

        configured = environ.get(_RECEIPT_HMAC_ENV)
        if configured is not None:
            if not configured:
                raise ValueError(f"{_RECEIPT_HMAC_ENV} must not be empty when configured")
            encoded = configured.encode("utf-8")
            _validate_integrity_key(encoded)
            return encoded

        return self._load_or_create_integrity_key_file()

    def _load_or_create_integrity_key_file(self) -> bytes:
        self.integrity_key_path.parent.mkdir(parents=True, exist_ok=True)
        if self.integrity_key_path.exists() or self.integrity_key_path.is_symlink():
            return self._read_integrity_key_file()
        if self.root.is_dir() and any(self.root.glob("tj_*.json")):
            raise ValueError(
                "receipt integrity key is missing while persisted receipts already exist"
            )

        generated = secrets.token_bytes(_MIN_INTEGRITY_KEY_BYTES)
        try:
            descriptor = os.open(
                self.integrity_key_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            return self._read_integrity_key_file()
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(generated)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            self.integrity_key_path.unlink(missing_ok=True)
            raise
        return generated

    def _read_integrity_key_file(self) -> bytes:
        path = self.integrity_key_path
        if path.is_symlink():
            raise ValueError("receipt integrity key path must not be a symbolic link")
        try:
            metadata = path.stat()
            key = path.read_bytes()
        except OSError as exc:
            raise ValueError("unable to read receipt integrity key") from exc
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("receipt integrity key must be a regular file")
        if os.name == "posix" and stat.S_IMODE(metadata.st_mode) & 0o077:
            raise ValueError("receipt integrity key permissions must not allow group/world access")
        _validate_integrity_key(key)
        return key


def _validate_integrity_key(key: bytes) -> None:
    if len(key) < _MIN_INTEGRITY_KEY_BYTES:
        raise ValueError(
            f"receipt integrity key must contain at least {_MIN_INTEGRITY_KEY_BYTES} bytes"
        )


def _canonical_json(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


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
