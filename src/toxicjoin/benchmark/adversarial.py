"""Metamorphic adversarial evaluation for unsafe individual data compositions.

The suite starts from three unsafe composition families and generates many
semantics-preserving SQL surface mutations. Each query still projects a stable
pseudonym, two quasi-identifiers, and a sensitive attribute at individual
level. Alias names, JOIN spelling, predicates, and bounded ordering change.

Every mutation must be blocked for COMPOSITIONAL_REIDENTIFICATION_RISK before
DuckDB execution. A parser failure is not counted as success because these
mutations are intentionally valid supported SELECT statements.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any, NamedTuple

from pydantic import Field

from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog, seed_database
from toxicjoin.execute import DuckDBExecutor
from toxicjoin.models import ColumnRef, Decision, ReasonCode, StrictModel
from toxicjoin.pipeline import PipelineRequest, ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import ReceiptMode, ReceiptStore


class _Family(NamedTuple):
    family_id: str
    dataset: str
    sensitive_field: str
    purpose: str


_FAMILIES = (
    _Family(
        "support-profile",
        "support_cases",
        "case_category",
        "Test individual support-category composition",
    ),
    _Family(
        "churn-profile",
        "retention_scores",
        "churn_score",
        "Test individual model-score composition",
    ),
    _Family(
        "financial-profile",
        "orders",
        "purchase_amount",
        "Test individual financial composition",
    ),
)
_ALIAS_PROFILES = (
    ("c", "s"),
    ("cust", "risk"),
    ("src", "sig"),
    ("p", "q"),
)
_JOIN_STYLES = ("JOIN", "INNER JOIN")
_PREDICATES = ("none", "subject-not-null", "sensitive-not-null")
_TAILS = ("none", "bounded-order")
_EXPECTED_CASES = len(_FAMILIES) * len(_ALIAS_PROFILES) * len(_JOIN_STYLES) * len(
    _PREDICATES
) * len(_TAILS)


class AdversarialMutationResult(StrictModel):
    case_id: str
    family: str
    alias_profile: str
    join_style: str
    predicate: str
    tail: str
    sql_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    initial_decision: Decision
    effective_decision: Decision
    initial_reason_codes: tuple[ReasonCode, ...]
    executed: bool
    passed: bool


class AdversarialMutationReport(StrictModel):
    schema_version: str = "1.0"
    suite_version: str = "1.0"
    policy_version: str
    data_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    total_cases: int = Field(ge=1)
    family_counts: dict[str, int]
    initial_block_count: int = Field(ge=0)
    effective_block_count: int = Field(ge=0)
    intended_reason_count: int = Field(ge=0)
    unexpected_execution_count: int = Field(ge=0)
    unsafe_initial_allow_count: int = Field(ge=0)
    unsafe_effective_allow_count: int = Field(ge=0)
    cases: tuple[AdversarialMutationResult, ...]
    gate_failures: tuple[str, ...] = ()
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @property
    def passed(self) -> bool:
        return not self.gate_failures


def run_adversarial_mutation_suite(
    *, output_dir: str | Path | None = None
) -> AdversarialMutationReport:
    """Generate and execute the complete mutation matrix."""

    policy = load_policy()
    with tempfile.TemporaryDirectory(prefix="toxicjoin-adversarial-") as temporary:
        root = Path(temporary)
        database = root / "adversarial.duckdb"
        seed_summary = seed_database(database)
        pipeline = ToxicJoinPipeline(
            context_resolver=FixtureContextResolver(default_fixture_catalog()),
            policy_engine=PolicyEngine(policy),
            receipt_store=ReceiptStore(root / "receipts"),
            mode=ReceiptMode.FIXTURE,
            executor=DuckDBExecutor(database, max_preview_rows=100, timeout_seconds=5.0),
            include_sanitized_sql=False,
        )
        cases = tuple(_run_mutation(pipeline, *spec) for spec in _mutation_specs())

    family_counts = Counter(case.family for case in cases)
    initial_block_count = sum(case.initial_decision == Decision.BLOCK for case in cases)
    effective_block_count = sum(case.effective_decision == Decision.BLOCK for case in cases)
    intended_reason_count = sum(
        ReasonCode.COMPOSITIONAL_REIDENTIFICATION_RISK in case.initial_reason_codes
        for case in cases
    )
    unexpected_execution_count = sum(case.executed for case in cases)
    unsafe_initial_allow_count = sum(
        case.initial_decision == Decision.ALLOW for case in cases
    )
    unsafe_effective_allow_count = sum(
        case.effective_decision == Decision.ALLOW for case in cases
    )

    gate_failures: list[str] = []
    if len(cases) != _EXPECTED_CASES:
        gate_failures.append("mutation_case_count_changed")
    if any(not case.passed for case in cases):
        gate_failures.append("mutation_case_failed")
    if unexpected_execution_count:
        gate_failures.append("unsafe_query_reached_executor")
    if unsafe_initial_allow_count:
        gate_failures.append("unsafe_initial_allow_detected")
    if unsafe_effective_allow_count:
        gate_failures.append("unsafe_effective_allow_detected")

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "suite_version": "1.0",
        "policy_version": policy.version,
        "data_fingerprint": seed_summary.data_fingerprint,
        "total_cases": len(cases),
        "family_counts": dict(sorted(family_counts.items())),
        "initial_block_count": initial_block_count,
        "effective_block_count": effective_block_count,
        "intended_reason_count": intended_reason_count,
        "unexpected_execution_count": unexpected_execution_count,
        "unsafe_initial_allow_count": unsafe_initial_allow_count,
        "unsafe_effective_allow_count": unsafe_effective_allow_count,
        "cases": cases,
        "gate_failures": tuple(gate_failures),
        "report_sha256": "0" * 64,
    }
    payload["report_sha256"] = _report_hash(payload)
    report = AdversarialMutationReport.model_validate(payload)

    if output_dir is not None:
        destination = Path(output_dir)
        destination.mkdir(parents=True, exist_ok=True)
        _write_atomic(
            destination / "adversarial-mutations.json",
            report.model_dump_json(indent=2) + "\n",
        )
        _write_atomic(destination / "adversarial-mutations.md", _markdown(report))
    return report


def _mutation_specs() -> tuple[tuple[_Family, str, str, str, str, str], ...]:
    specs: list[tuple[_Family, str, str, str, str, str]] = []
    for family in _FAMILIES:
        for customer_alias, sensitive_alias in _ALIAS_PROFILES:
            for join_style in _JOIN_STYLES:
                for predicate in _PREDICATES:
                    for tail in _TAILS:
                        specs.append(
                            (
                                family,
                                customer_alias,
                                sensitive_alias,
                                join_style,
                                predicate,
                                tail,
                            )
                        )
    return tuple(specs)


def _run_mutation(
    pipeline: ToxicJoinPipeline,
    family: _Family,
    customer_alias: str,
    sensitive_alias: str,
    join_style: str,
    predicate: str,
    tail: str,
) -> AdversarialMutationResult:
    sql = _render_sql(
        family=family,
        customer_alias=customer_alias,
        sensitive_alias=sensitive_alias,
        join_style=join_style,
        predicate=predicate,
        tail=tail,
    )
    case_material = "|".join(
        (
            family.family_id,
            customer_alias,
            sensitive_alias,
            join_style,
            predicate,
            tail,
        )
    )
    case_id = "M" + hashlib.sha256(case_material.encode("utf-8")).hexdigest()[:12]
    result = pipeline.execute_safe(
        PipelineRequest(
            task_purpose=family.purpose,
            sql=sql,
            subject_key=ColumnRef(
                dataset="customers",
                field_path="customer_id",
                alias=customer_alias,
            ),
        )
    )
    executed = result.receipt.execution is not None or (
        result.verification is not None and result.verification.execution is not None
    )
    intended_reason = ReasonCode.COMPOSITIONAL_REIDENTIFICATION_RISK
    passed = (
        result.initial_decision.decision == Decision.BLOCK
        and result.effective_decision == Decision.BLOCK
        and intended_reason in result.initial_decision.reason_codes
        and not executed
    )
    return AdversarialMutationResult(
        case_id=case_id,
        family=family.family_id,
        alias_profile=f"{customer_alias}/{sensitive_alias}",
        join_style=join_style,
        predicate=predicate,
        tail=tail,
        sql_sha256=hashlib.sha256(sql.encode("utf-8")).hexdigest(),
        initial_decision=result.initial_decision.decision,
        effective_decision=result.effective_decision,
        initial_reason_codes=result.initial_decision.reason_codes,
        executed=executed,
        passed=passed,
    )


def _render_sql(
    *,
    family: _Family,
    customer_alias: str,
    sensitive_alias: str,
    join_style: str,
    predicate: str,
    tail: str,
) -> str:
    where_clause = ""
    if predicate == "subject-not-null":
        where_clause = f"WHERE {customer_alias}.customer_id IS NOT NULL"
    elif predicate == "sensitive-not-null":
        where_clause = (
            f"WHERE {sensitive_alias}.{family.sensitive_field} IS NOT NULL"
        )
    elif predicate != "none":
        raise ValueError(f"unknown predicate mutation: {predicate}")

    tail_clause = ""
    if tail == "bounded-order":
        tail_clause = f"ORDER BY {customer_alias}.customer_id LIMIT 10"
    elif tail != "none":
        raise ValueError(f"unknown tail mutation: {tail}")

    return "\n".join(
        part
        for part in (
            (
                f"SELECT {customer_alias}.customer_id, {customer_alias}.age_band, "
                f"{customer_alias}.precise_area, "
                f"{sensitive_alias}.{family.sensitive_field}"
            ),
            f"FROM customers {customer_alias}",
            (
                f"{join_style} {family.dataset} {sensitive_alias} "
                f"ON {customer_alias}.customer_id = {sensitive_alias}.customer_id"
            ),
            where_clause,
            tail_clause,
        )
        if part
    )


def _report_hash(payload: dict[str, Any]) -> str:
    canonical_payload = {
        key: _json_compatible(value)
        for key, value in payload.items()
        if key != "report_sha256"
    }
    canonical = json.dumps(
        canonical_payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _json_compatible(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {str(key): _json_compatible(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_compatible(item) for item in value]
    if hasattr(value, "value") and isinstance(value.value, str):
        return value.value
    return value


def _write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(content, encoding="utf-8")
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _markdown(report: AdversarialMutationReport) -> str:
    lines = [
        "# ToxicJoin Adversarial Mutation Suite",
        "",
        f"**Gate:** {'PASS' if report.passed else 'FAIL'}",
        f"**Cases:** {report.total_cases}",
        f"**Initial BLOCK:** {report.initial_block_count}/{report.total_cases}",
        f"**Effective BLOCK:** {report.effective_block_count}/{report.total_cases}",
        f"**Intended compositional-risk reason:** {report.intended_reason_count}/{report.total_cases}",
        f"**Unexpected database executions:** {report.unexpected_execution_count}",
        f"**Unsafe initial allows:** {report.unsafe_initial_allow_count}",
        f"**Unsafe effective allows:** {report.unsafe_effective_allow_count}",
        "",
        "## Mutation matrix",
        "",
        "Three known-unsafe individual composition families are mutated across four alias profiles, two JOIN spellings, three predicate forms, and two ordering/limit forms.",
        "",
        "| Family | Cases |",
        "|---|---:|",
    ]
    for family, count in sorted(report.family_counts.items()):
        lines.append(f"| {family} | {count} |")
    lines.extend(
        (
            "",
            "Every generated query remains an individual-level composition of a stable pseudonym, two quasi-identifiers, and a sensitive attribute. A case counts as PASS only when ToxicJoin returns `BLOCK` for `COMPOSITIONAL_REIDENTIFICATION_RISK` and no database execution occurs.",
            "",
            "This suite is a declared metamorphic security evaluation, not a claim of universal SQL or re-identification coverage.",
            "",
            f"Report SHA-256: `{report.report_sha256}`",
            "",
        )
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate ToxicJoin adversarial mutation evidence"
    )
    parser.add_argument(
        "--output-dir",
        default="artifacts/adversarial-mutations",
        help="Directory for JSON and Markdown evidence",
    )
    args = parser.parse_args()
    report = run_adversarial_mutation_suite(output_dir=args.output_dir)
    print(report.model_dump_json(indent=2))
    if not report.passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
