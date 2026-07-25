"""Constrained SQL compiler for the finite P0 CPCC remediation grammar."""

from __future__ import annotations

import sqlglot
from pydantic import Field, model_validator
from sqlglot import exp

from toxicjoin.context.models import ContextResolution
from toxicjoin.evidence.canonical import canonical_json_sha256
from toxicjoin.models import (
    ColumnContext,
    ProjectionExposure,
    SensitivityCategory,
    StrictModel,
)
from toxicjoin.repair.models import (
    CpccCandidate,
    RemediationAction,
    RemediationOperator,
    TrustedQiTransformation,
    TrustedSensitiveAggregate,
)
from toxicjoin.rewrite import RewriteError, enforce_minimum_group_size
from toxicjoin.sql import analyze_sql

_HASH_PATTERN = r"^[0-9a-f]{64}$"
_COMPILER_VERSION = "0.1.0"
_PHASE = {
    RemediationOperator.REMOVE_STABLE_IDENTIFIER: 10,
    RemediationOperator.REMOVE_SENSITIVE_PROJECTION: 11,
    RemediationOperator.REMOVE_PROJECTION: 12,
    RemediationOperator.COARSEN_QI: 20,
    RemediationOperator.AGGREGATE_SENSITIVE: 30,
    RemediationOperator.ADD_MINIMUM_GROUP_THRESHOLD: 40,
    RemediationOperator.INCREASE_MINIMUM_GROUP_THRESHOLD: 41,
}


class CpccCompileError(ValueError):
    """Deterministic GENERATE-stage rejection for an inapplicable remediation."""


class CompiledCpccRepair(StrictModel):
    """Canonical output of one constrained CPCC candidate compilation."""

    schema_version: str = Field(default="1.0", pattern=r"^1\.0$")
    compiler_version: str = Field(default=_COMPILER_VERSION, pattern=r"^0\.1\.0$")
    candidate_sha256: str = Field(pattern=_HASH_PATTERN)
    original_sql_sha256: str = Field(pattern=_HASH_PATTERN)
    generated_sql: str = Field(min_length=1, max_length=100_000)
    generated_sql_sha256: str = Field(pattern=_HASH_PATTERN)
    operations: tuple[str, ...] = Field(min_length=1, max_length=2)
    compilation_sha256: str = Field(pattern=_HASH_PATTERN)

    @model_validator(mode="after")
    def validate_compilation(self) -> "CompiledCpccRepair":
        if self.operations != tuple(self.operations):
            raise ValueError("CPCC compiler operations must be canonical")
        if self.generated_sql_sha256 != canonical_json_sha256(
            {"sql": self.generated_sql}
        ):
            raise ValueError("CPCC generated SQL hash mismatch")
        if self.compilation_sha256 != compute_compiled_repair_sha256(self):
            raise ValueError("CPCC compilation hash mismatch")
        return self


def compile_cpcc_candidate(
    sql: str,
    candidate: CpccCandidate,
    *,
    original_resolution: ContextResolution,
    subject_key,
    dialect: str = "duckdb",
) -> CompiledCpccRepair:
    """Compile one candidate using only security-owned deterministic transforms.

    The original governed resolution is used only to bind declared CPCC field keys to exact
    root projections. The generated query is not trusted here: the full validator must reparse
    and reground it from scratch before policy or PPMC evaluation.
    """

    if not sql.strip():
        raise CpccCompileError("original SQL must not be empty")
    original_plan = analyze_sql(sql, dialect=dialect)
    if original_plan.contains_wildcard:
        raise CpccCompileError("wildcard projections are outside the CPCC compiler profile")
    if original_resolution.failures:
        raise CpccCompileError("original governance resolution contains failures")

    current_sql = sql
    operations: list[str] = []
    ordered_actions = tuple(
        sorted(candidate.actions, key=lambda item: (_PHASE[item.operator], item.action_sha256))
    )
    if sum(
        action.operator
        in {
            RemediationOperator.ADD_MINIMUM_GROUP_THRESHOLD,
            RemediationOperator.INCREASE_MINIMUM_GROUP_THRESHOLD,
        }
        for action in ordered_actions
    ) > 1:
        raise CpccCompileError("candidate contains multiple threshold interventions")

    for action in ordered_actions:
        if action.operator in {
            RemediationOperator.ADD_MINIMUM_GROUP_THRESHOLD,
            RemediationOperator.INCREASE_MINIMUM_GROUP_THRESHOLD,
        }:
            current_sql, operation = _compile_threshold_action(
                current_sql,
                action,
                subject_key=subject_key,
                dialect=dialect,
            )
        else:
            current_sql, operation = _compile_projection_action(
                current_sql,
                action,
                original_resolution=original_resolution,
                dialect=dialect,
            )
        operations.append(operation)

    if current_sql.strip() == sql.strip():
        raise CpccCompileError("candidate did not change SQL")

    payload = {
        "candidate_sha256": candidate.candidate_sha256,
        "original_sql_sha256": canonical_json_sha256({"sql": sql}),
        "generated_sql": current_sql,
        "generated_sql_sha256": canonical_json_sha256({"sql": current_sql}),
        "operations": tuple(operations),
    }
    provisional = CompiledCpccRepair.model_construct(
        **payload,
        compilation_sha256="0" * 64,
    )
    return CompiledCpccRepair(
        **payload,
        compilation_sha256=compute_compiled_repair_sha256(provisional),
    )


def compute_compiled_repair_sha256(compilation: CompiledCpccRepair) -> str:
    return canonical_json_sha256(
        compilation.model_dump(mode="json", exclude={"compilation_sha256"})
    )


def _compile_threshold_action(
    sql: str,
    action: RemediationAction,
    *,
    subject_key,
    dialect: str,
) -> tuple[str, str]:
    assert action.minimum_group_size is not None
    plan = analyze_sql(sql, dialect=dialect)
    current = plan.minimum_group_size_present
    if action.operator == RemediationOperator.ADD_MINIMUM_GROUP_THRESHOLD:
        if current is not None:
            raise CpccCompileError("ADD_MINIMUM_GROUP_THRESHOLD requires no existing threshold")
    elif action.operator == RemediationOperator.INCREASE_MINIMUM_GROUP_THRESHOLD:
        if current is None or current >= action.minimum_group_size:
            raise CpccCompileError(
                "INCREASE_MINIMUM_GROUP_THRESHOLD requires a weaker existing threshold"
            )
    else:  # pragma: no cover - guarded by caller.
        raise CpccCompileError("unsupported threshold operator")

    try:
        rewritten = enforce_minimum_group_size(
            sql,
            subject_key=subject_key,
            minimum_group_size=action.minimum_group_size,
            dialect=dialect,
        )
    except RewriteError as exc:
        raise CpccCompileError(str(exc)) from exc
    if rewritten.safe_sql.strip() == sql.strip():
        raise CpccCompileError("threshold intervention produced no SQL change")
    return rewritten.safe_sql, rewritten.operations[0]


def _compile_projection_action(
    sql: str,
    action: RemediationAction,
    *,
    original_resolution: ContextResolution,
    dialect: str,
) -> tuple[str, str]:
    try:
        root = sqlglot.parse_one(sql, read=dialect)
    except Exception as exc:
        raise CpccCompileError(f"unable to parse SQL for CPCC generation: {exc}") from exc
    if not isinstance(root, exp.Select):
        raise CpccCompileError("CPCC generation supports one root SELECT only")

    plan = analyze_sql(sql, dialect=dialect)
    if plan.contains_wildcard:
        raise CpccCompileError("wildcard projections are outside the CPCC compiler profile")
    expressions = list(root.expressions)
    exposures = plan.projected_exposures
    if len(expressions) != len(exposures):
        raise CpccCompileError("root projection/exposure cardinality is ambiguous")

    contexts = _governance_by_ref(original_resolution)
    slots = tuple(
        _ProjectionSlot(index, expression, exposure, contexts)
        for index, (expression, exposure) in enumerate(zip(expressions, exposures, strict=True))
    )

    if action.operator == RemediationOperator.REMOVE_STABLE_IDENTIFIER:
        indexes = tuple(
            slot.index
            for slot in slots
            if slot.has_effective_category(SensitivityCategory.STABLE_PSEUDONYM)
        )
        operation = "REMOVE_STABLE_IDENTIFIER"
        return _remove_projection_indexes(root, indexes, operation=operation, dialect=dialect)

    if action.operator == RemediationOperator.REMOVE_SENSITIVE_PROJECTION:
        indexes = tuple(
            slot.index
            for slot in slots
            if slot.has_effective_category(SensitivityCategory.SENSITIVE_ATTRIBUTE)
        )
        operation = "REMOVE_SENSITIVE_PROJECTION"
        return _remove_projection_indexes(root, indexes, operation=operation, dialect=dialect)

    if action.field_key is None:
        raise CpccCompileError("field-scoped remediation is missing field binding")
    matches = tuple(slot for slot in slots if slot.exact_field_key == action.field_key)
    if len(matches) != 1:
        raise CpccCompileError(
            "field-scoped remediation requires exactly one single-source root projection"
        )
    slot = matches[0]

    if action.operator == RemediationOperator.REMOVE_PROJECTION:
        return _remove_projection_indexes(
            root,
            (slot.index,),
            operation=f"REMOVE_PROJECTION:{action.field_key}",
            dialect=dialect,
        )

    if action.operator == RemediationOperator.COARSEN_QI:
        if not slot.has_effective_category(SensitivityCategory.QUASI_IDENTIFIER):
            raise CpccCompileError("COARSEN_QI target is not a governed quasi-identifier")
        body, alias = _simple_projection_column(slot.expression)
        if action.qi_transformation == TrustedQiTransformation.DATE_TO_MONTH:
            unit = "month"
        elif action.qi_transformation == TrustedQiTransformation.DATE_TO_YEAR:
            unit = "year"
        else:  # pragma: no cover - model restricts enum.
            raise CpccCompileError("unsupported trusted QI transformation")
        replacement = exp.Anonymous(
            this="DATE_TRUNC",
            expressions=[exp.Literal.string(unit), body.copy()],
        )
        expressions[slot.index] = _restore_alias(replacement, alias)
        root.set("expressions", expressions)
        return root.sql(dialect=dialect, pretty=True), f"COARSEN_QI:{unit}:{action.field_key}"

    if action.operator == RemediationOperator.AGGREGATE_SENSITIVE:
        if not slot.has_effective_category(SensitivityCategory.SENSITIVE_ATTRIBUTE):
            raise CpccCompileError("AGGREGATE_SENSITIVE target is not sensitive")
        body, alias = _simple_projection_column(slot.expression)
        if action.aggregate_operator == TrustedSensitiveAggregate.COUNT:
            replacement = exp.Count(this=body.copy())
        elif action.aggregate_operator == TrustedSensitiveAggregate.COUNT_DISTINCT:
            replacement = exp.Count(
                this=exp.Distinct(expressions=[body.copy()])
            )
        else:  # pragma: no cover - model restricts enum.
            raise CpccCompileError("unsupported trusted sensitive aggregate")
        expressions[slot.index] = _restore_alias(replacement, alias)
        root.set("expressions", expressions)
        return (
            root.sql(dialect=dialect, pretty=True),
            f"AGGREGATE_SENSITIVE:{action.aggregate_operator.value}:{action.field_key}",
        )

    raise CpccCompileError(f"unsupported CPCC compiler operator: {action.operator.value}")


class _ProjectionSlot:
    def __init__(
        self,
        index: int,
        expression: exp.Expression,
        exposure: ProjectionExposure,
        contexts: dict[str, ColumnContext],
    ) -> None:
        self.index = index
        self.expression = expression
        self.exposure = exposure
        self._contexts = contexts
        governed: list[ColumnContext] = []
        for source in exposure.source_columns:
            context = contexts.get(source.key)
            if context is None:
                raise CpccCompileError(
                    f"projection source lacks original trusted governance: {source.key}"
                )
            governed.append(context)
        self.governed = tuple(governed)

    @property
    def exact_field_key(self) -> str | None:
        if len(self.governed) != 1:
            return None
        context = self.governed[0]
        if context.datahub_urn is None:
            return None
        return f"{context.datahub_urn}#{context.ref.field_path}"

    def has_effective_category(self, category: SensitivityCategory) -> bool:
        return any(
            context.category == category
            or any(source.category == category for source in context.lineage_sources)
            for context in self.governed
        )


def _governance_by_ref(resolution: ContextResolution) -> dict[str, ColumnContext]:
    result: dict[str, ColumnContext] = {}
    for context in resolution.all_referenced_context:
        if not context.resolved or context.datahub_urn is None:
            raise CpccCompileError("original governance must be fully resolved")
        existing = result.get(context.ref.key)
        if existing is not None and existing != context:
            raise CpccCompileError(
                f"conflicting original governance for {context.ref.key}"
            )
        result[context.ref.key] = context
    return result


def _remove_projection_indexes(
    root: exp.Select,
    indexes: tuple[int, ...],
    *,
    operation: str,
    dialect: str,
) -> tuple[str, str]:
    unique = set(indexes)
    if not unique:
        raise CpccCompileError(f"{operation} has no applicable root projection")
    expressions = [
        expression for index, expression in enumerate(root.expressions) if index not in unique
    ]
    if not expressions:
        raise CpccCompileError(f"{operation} would remove every projected output")
    root.set("expressions", expressions)
    return root.sql(dialect=dialect, pretty=True), operation


def _simple_projection_column(expression: exp.Expression) -> tuple[exp.Column, exp.Identifier | None]:
    if isinstance(expression, exp.Alias):
        body = expression.this
        alias = expression.args.get("alias")
    else:
        body = expression
        alias = None
    if not isinstance(body, exp.Column):
        raise CpccCompileError(
            "CPCC field transformation requires a simple single-column root projection"
        )
    return body, alias.copy() if isinstance(alias, exp.Identifier) else None


def _restore_alias(
    expression: exp.Expression,
    alias: exp.Identifier | None,
) -> exp.Expression:
    if alias is None:
        return expression
    return exp.Alias(this=expression, alias=alias)
