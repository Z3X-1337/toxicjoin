"""Constrained SQL rewrites for privacy-preserving grouped output."""

from __future__ import annotations

import sqlglot
from sqlglot import exp

from toxicjoin.models import ColumnRef, QueryPlan, ReasonCode, StrictModel
from toxicjoin.sql import analyze_sql


class RewriteError(ValueError):
    """Fail-closed rewrite failure with a stable reason code."""

    def __init__(self, detail: str) -> None:
        self.reason_code = ReasonCode.REWRITE_FAILED
        self.detail = detail
        super().__init__(f"{self.reason_code.value}: {detail}")


class RewriteResult(StrictModel):
    original_sql: str
    safe_sql: str
    operations: tuple[str, ...]
    original_plan: QueryPlan
    safe_plan: QueryPlan


def enforce_minimum_group_size(
    sql: str,
    *,
    subject_key: ColumnRef,
    minimum_group_size: int,
    dialect: str = "duckdb",
) -> RewriteResult:
    """Add or strengthen a trusted subject-count threshold in a grouped query.

    This rewriter intentionally supports one narrow transformation. It never turns
    individual-level output into grouped output and never removes arbitrary clauses.
    Unsupported cases fail closed instead of producing best-effort SQL.
    """

    if minimum_group_size < 2:
        raise RewriteError("minimum_group_size must be at least 2")

    original_plan = analyze_sql(sql, dialect=dialect)
    if not original_plan.is_grouped:
        raise RewriteError("minimum-group rewrite requires an already grouped query")
    if original_plan.contains_wildcard:
        raise RewriteError("wildcard projections must be expanded before rewriting")

    matching_refs = [
        ref for ref in original_plan.referenced_columns if ref.key == subject_key.key
    ]
    if not matching_refs:
        raise RewriteError(
            f"subject key {subject_key.key!r} is not referenced by the query"
        )

    detected_subject = original_plan.minimum_group_size_subject
    detected_threshold = original_plan.minimum_group_size_present
    if detected_subject is not None and detected_subject.key != subject_key.key:
        raise RewriteError(
            "query contains a distinct-count threshold for a different subject key"
        )

    if (
        detected_subject is not None
        and detected_subject.key == subject_key.key
        and detected_threshold is not None
        and detected_threshold >= minimum_group_size
    ):
        return RewriteResult(
            original_sql=sql,
            safe_sql=sql,
            operations=("NO_OP_TRUSTED_THRESHOLD_PRESENT",),
            original_plan=original_plan,
            safe_plan=original_plan,
        )

    if "UNTRUSTED_GROUP_THRESHOLD_OR_EXPRESSION" in original_plan.analysis_warnings:
        raise RewriteError("HAVING expressions containing OR are outside the safe rewrite profile")
    if "UNTRUSTED_GROUP_THRESHOLD_MULTIPLE_SUBJECTS" in original_plan.analysis_warnings:
        raise RewriteError("multiple threshold subjects are outside the safe rewrite profile")

    try:
        root = sqlglot.parse_one(sql, read=dialect)
    except Exception as exc:  # analyze_sql already normalized parser failures.
        raise RewriteError(f"unable to parse SQL for rewrite: {exc}") from exc
    if not isinstance(root, exp.Select):
        raise RewriteError("rewrite target is not a SELECT")

    reference = matching_refs[0]
    qualifier = subject_key.alias or reference.alias
    subject_expression = exp.column(subject_key.field_path, table=qualifier)
    threshold_expression = exp.GTE(
        this=exp.Count(
            this=exp.Distinct(expressions=[subject_expression]),
        ),
        expression=exp.Literal.number(minimum_group_size),
    )

    existing_having = root.args.get("having")
    if existing_having is None:
        root.set("having", exp.Having(this=threshold_expression))
        operation = "ADD_MINIMUM_SUBJECT_THRESHOLD"
    else:
        existing_body = (
            existing_having.this
            if isinstance(existing_having, exp.Having)
            else existing_having
        )
        root.set(
            "having",
            exp.Having(this=exp.and_(existing_body.copy(), threshold_expression)),
        )
        operation = "STRENGTHEN_MINIMUM_SUBJECT_THRESHOLD"

    safe_sql = root.sql(dialect=dialect, pretty=True)
    safe_plan = analyze_sql(safe_sql, dialect=dialect)

    if safe_plan.minimum_group_size_present is None:
        raise RewriteError("rewritten SQL did not expose a trusted group threshold")
    if safe_plan.minimum_group_size_present < minimum_group_size:
        raise RewriteError("rewritten SQL threshold is below the required minimum")
    if safe_plan.minimum_group_size_subject is None:
        raise RewriteError("rewritten SQL did not expose a threshold subject")
    if safe_plan.minimum_group_size_subject.key != subject_key.key:
        raise RewriteError("rewritten SQL threshold is bound to the wrong subject")

    return RewriteResult(
        original_sql=sql,
        safe_sql=safe_sql,
        operations=(operation,),
        original_plan=original_plan,
        safe_plan=safe_plan,
    )
