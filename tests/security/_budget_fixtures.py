"""Builders for window-sensitive composition tests.

Exercising the rolling window needs records with controlled ``created_at`` values, which the
ledger only ever assigns from the wall clock. These helpers construct valid, fully hashed
records directly so the window boundary can be tested without sleeping.
"""

from __future__ import annotations

from datetime import datetime

from toxicjoin.auth import RequestIdentity
from toxicjoin.demo import default_fixture_catalog
from toxicjoin.disclosure import (
    build_composition_metadata,
    build_disclosure_event,
)
from toxicjoin.disclosure.models import (
    DisclosureEvent,
    DisclosureRecord,
    compute_event_sha256,
    compute_record_sha256,
)
from toxicjoin.models import ColumnRef
from toxicjoin.sql import analyze_sql


_COHORT_KEY = b"b" * 32
_SUBJECT = ColumnRef(dataset="orders", field_path="customer_id")

PROTECTED_SQL = (
    "SELECT o.category, COUNT(DISTINCT o.customer_id) AS n "
    "FROM orders o GROUP BY o.category"
)


def _identity() -> RequestIdentity:
    return RequestIdentity(
        principal_id="principal-budget",
        credential_id="credential-budget",
        agent_id="agent-budget",
    )


def _bound_event(sql: str, receipt_index: int) -> DisclosureEvent:
    plan = analyze_sql(sql, dialect="duckdb")
    event = build_disclosure_event(
        identity=_identity(),
        catalog=default_fixture_catalog(),
        query_plan=plan,
        subject_key=_SUBJECT,
        receipt_id=f"tj_{receipt_index:016x}",
        policy_version="0.2.0",
    )
    composition = build_composition_metadata(
        event.semantic,
        sql,
        secret_key=_COHORT_KEY,
    )
    return DisclosureEvent.model_validate(
        {
            **event.model_dump(mode="json"),
            "composition": composition.model_dump(mode="json"),
        }
    )


def protected_candidate(receipt_index: int = 2) -> DisclosureEvent:
    """A protected release awaiting evaluation."""

    return _bound_event(PROTECTED_SQL, receipt_index)


def protected_record(*, created_at: datetime, receipt_index: int = 1) -> DisclosureRecord:
    """A committed protected release stamped at an exact time."""

    event = _bound_event(PROTECTED_SQL, receipt_index)
    payload = {
        "schema_version": "1.1",
        "record_id": f"dl_{receipt_index:032x}",
        "sequence": receipt_index,
        "created_at": created_at,
        "event": event,
        "event_sha256": compute_event_sha256(event),
        "previous_content_sha256": None,
        "content_sha256": "0" * 64,
    }
    unsealed = DisclosureRecord.model_construct(**payload)
    return DisclosureRecord.model_validate(
        {
            **payload,
            "created_at": created_at,
            "content_sha256": compute_record_sha256(unsealed),
        }
    )
