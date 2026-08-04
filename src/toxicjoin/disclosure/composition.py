"""Conservative cross-query composition policy for protected analytical releases.

The model intentionally does not claim general set-relation inference or differential
privacy. It allows at most one new protected release per privacy scope. Reusing the
same receipt is handled separately as idempotency, but a second protected release is
blocked even when its SQL/semantic family is identical because the underlying data may
have changed between executions.
"""

from __future__ import annotations

import hashlib
import hmac
from datetime import datetime, timedelta, timezone

import sqlglot
from sqlglot import exp

from toxicjoin.disclosure.models import (
    CompositionRule,
    DisclosureBudget,
    DisclosureComposition,
    DisclosureCompositionEvaluation,
    DisclosureEvent,
    DisclosureRecord,
    DisclosureSemanticRelease,
)
from toxicjoin.models import SensitivityCategory


_PROTECTED_CATEGORIES = {
    SensitivityCategory.DIRECT_IDENTIFIER,
    SensitivityCategory.STABLE_PSEUDONYM,
    SensitivityCategory.QUASI_IDENTIFIER,
    SensitivityCategory.SENSITIVE_ATTRIBUTE,
}


class DisclosureCompositionError(ValueError):
    """Raised when a cohort identity cannot be derived or validated safely."""


def build_composition_metadata(
    semantic: DisclosureSemanticRelease,
    sql: str,
    *,
    secret_key: bytes,
    dialect: str = "duckdb",
) -> DisclosureComposition:
    """Build a keyed cohort identity without persisting SQL text or literal values."""

    if len(secret_key) < 32:
        raise DisclosureCompositionError("cohort HMAC key must be at least 32 bytes")
    canonical = canonicalize_cohort_sql(sql, dialect=dialect)
    cohort_hmac = hmac.new(secret_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return DisclosureComposition(
        protected_release=is_protected_release(semantic),
        release_family_sha256=semantic.semantic_sha256,
        cohort_hmac_sha256=cohort_hmac,
    )


def canonicalize_cohort_sql(sql: str, *, dialect: str = "duckdb") -> str:
    """Canonicalize disclosure-shaping SQL while ignoring root output aliases only.

    Root projection *expressions* remain part of the keyed cohort identity. CASE/FILTER
    predicates, comparison thresholds, target identifiers, aggregate arguments, WHERE,
    JOIN, CTE, HAVING, QUALIFY, DISTINCT, GROUP BY, LIMIT, OFFSET, and literal values all
    affect what information can be released and therefore must remain HMAC-protected.
    Cosmetic root aliases are removed. An unlimited root ORDER BY remains ignored because
    it changes ordering, not membership or released values; with LIMIT/OFFSET it stays.
    """

    try:
        statements = tuple(sqlglot.parse(sql, read=dialect))
    except sqlglot.errors.ParseError as exc:
        raise DisclosureCompositionError("unable to parse SQL for cohort identity") from exc
    if len(statements) != 1 or not isinstance(statements[0], exp.Select):
        raise DisclosureCompositionError("cohort identity requires exactly one SELECT")

    root = statements[0].copy()
    has_row_limit = root.args.get("limit") is not None or root.args.get("offset") is not None
    root.set(
        "expressions",
        [
            projection.this.copy()
            if isinstance(projection, exp.Alias)
            else projection.copy()
            for projection in root.expressions
        ],
    )
    if not has_row_limit:
        root.set("order", None)
    return root.sql(dialect=dialect, pretty=False, comments=False)


def is_protected_release(semantic: DisclosureSemanticRelease) -> bool:
    """Return whether sequential variation could add privacy information.

    Every aggregate is protected because even a count over a stable subject population
    can support membership/differencing attacks. Non-aggregate output is protected when
    its governed lineage exposes any non-public category.
    """

    if semantic.aggregate_functions:
        return True
    return any(
        source.category in _PROTECTED_CATEGORIES
        for output in semantic.outputs
        for source in output.sources
    )


def validate_event_composition(event: DisclosureEvent) -> None:
    """Fail closed if persisted composition metadata disagrees with governed semantics."""

    composition = event.composition
    if composition is None:
        return
    if composition.release_family_sha256 != event.semantic.semantic_sha256:
        raise DisclosureCompositionError("composition release family mismatch")
    if composition.protected_release != is_protected_release(event.semantic):
        raise DisclosureCompositionError("composition protected-release classification mismatch")


def evaluate_composition_history(
    history: tuple[DisclosureRecord, ...],
    candidate: DisclosureEvent,
    *,
    budget: DisclosureBudget | None = None,
    now: datetime | None = None,
) -> DisclosureCompositionEvaluation:
    """Evaluate one candidate against active release history without mutating state.

    Protected releases consume a bounded per-scope budget inside a rolling window. Releases
    older than the window no longer restrict new work, which is what makes the stateful mode
    usable beyond a single query; the budget is an explicit exposure bound and not a claim
    that the permitted releases cannot be differenced against each other.
    """

    effective_budget = budget or DisclosureBudget()
    evaluated_at = now or datetime.now(timezone.utc)
    horizon = evaluated_at - timedelta(seconds=effective_budget.window_seconds)

    validate_event_composition(candidate)
    composition = candidate.composition
    if composition is None:
        raise DisclosureCompositionError("candidate is missing composition metadata")

    prior_protected: list[DisclosureComposition] = []
    for record in history:
        validate_event_composition(record.event)
        protected = is_protected_release(record.event.semantic)
        if not protected:
            continue
        if record.event.composition is None:
            # History predating composition metadata cannot be reasoned about at all, so it
            # keeps failing closed regardless of the budget.
            return DisclosureCompositionEvaluation(
                allowed=False,
                rule=CompositionRule.LEGACY_HISTORY_BLOCK,
                protected_release=composition.protected_release,
                prior_protected_count=len(prior_protected) + 1,
            )
        if record.created_at <= horizon:
            continue
        prior_protected.append(record.event.composition)

    if not composition.protected_release:
        return DisclosureCompositionEvaluation(
            allowed=True,
            rule=CompositionRule.UNPROTECTED_RELEASE,
            protected_release=False,
            prior_protected_count=len(prior_protected),
        )

    if len(prior_protected) >= effective_budget.max_protected_releases:
        return DisclosureCompositionEvaluation(
            allowed=False,
            rule=CompositionRule.CUMULATIVE_BUDGET_EXHAUSTED,
            protected_release=True,
            prior_protected_count=len(prior_protected),
        )

    return DisclosureCompositionEvaluation(
        allowed=True,
        rule=(
            CompositionRule.FIRST_PROTECTED_RELEASE
            if not prior_protected
            else CompositionRule.PROTECTED_RELEASE_WITHIN_BUDGET
        ),
        protected_release=True,
        prior_protected_count=len(prior_protected),
    )
