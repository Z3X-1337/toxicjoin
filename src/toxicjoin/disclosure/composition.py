"""Conservative cross-query composition policy for protected analytical releases.

The model intentionally does not claim general set-relation inference or differential
privacy. It allows one protected release family/cohort per privacy scope and repeated
identical releases of that same family/cohort. A different protected cohort or semantic
family in the same scope is blocked before execution authorization.
"""

from __future__ import annotations

import hashlib
import hmac

import sqlglot
from sqlglot import exp

from toxicjoin.disclosure.models import (
    CompositionRule,
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
    """Canonicalize row-selection structure while excluding root output aliases.

    The root SELECT list is replaced with a constant because released output semantics
    are tracked independently by ``DisclosureSemanticRelease``. ORDER BY is removed
    because it changes presentation order, not cohort membership. WHERE, JOIN, CTE,
    HAVING, QUALIFY, DISTINCT, GROUP BY, LIMIT, OFFSET, and literal predicates remain in
    the in-memory canonical form and are protected by HMAC before persistence.
    """

    try:
        statements = tuple(sqlglot.parse(sql, read=dialect))
    except sqlglot.errors.ParseError as exc:
        raise DisclosureCompositionError("unable to parse SQL for cohort identity") from exc
    if len(statements) != 1 or not isinstance(statements[0], exp.Select):
        raise DisclosureCompositionError("cohort identity requires exactly one SELECT")

    root = statements[0].copy()
    root.set("expressions", [exp.Literal.number(1)])
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
) -> DisclosureCompositionEvaluation:
    """Evaluate one candidate against committed history without mutating state."""

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
            return DisclosureCompositionEvaluation(
                allowed=False,
                rule=CompositionRule.LEGACY_HISTORY_BLOCK,
                protected_release=composition.protected_release,
                prior_protected_count=len(prior_protected) + 1,
            )
        prior_protected.append(record.event.composition)

    if not composition.protected_release:
        return DisclosureCompositionEvaluation(
            allowed=True,
            rule=CompositionRule.UNPROTECTED_RELEASE,
            protected_release=False,
            prior_protected_count=len(prior_protected),
        )

    if not prior_protected:
        return DisclosureCompositionEvaluation(
            allowed=True,
            rule=CompositionRule.FIRST_PROTECTED_RELEASE,
            protected_release=True,
            prior_protected_count=0,
        )

    same_release = all(
        previous.release_family_sha256 == composition.release_family_sha256
        and previous.cohort_hmac_sha256 == composition.cohort_hmac_sha256
        for previous in prior_protected
    )
    if same_release:
        return DisclosureCompositionEvaluation(
            allowed=True,
            rule=CompositionRule.REPEAT_IDENTICAL_RELEASE,
            protected_release=True,
            prior_protected_count=len(prior_protected),
        )

    return DisclosureCompositionEvaluation(
        allowed=False,
        rule=CompositionRule.CUMULATIVE_VARIATION_BLOCK,
        protected_release=True,
        prior_protected_count=len(prior_protected),
    )
