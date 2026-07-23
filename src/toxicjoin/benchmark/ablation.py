"""Ablation study for ToxicJoin's cross-column compositional policy rule.

This is not a competitor benchmark. It uses ToxicJoin's own deterministic policy
engine twice: once with the shipped configuration, and once with only the
non-grouped compositional interaction effectively disabled by setting the
quasi-identifier interaction threshold above the maximum possible in this
declared evaluation.

The parser, governed context resolver, policy implementation, and all other
policy branches remain identical. This isolates whether the cross-column
interaction is necessary to detect the declared unsafe individual profiles.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
from typing import Any

from pydantic import Field

from toxicjoin.benchmark.adversarial import _mutation_specs, _render_sql
from toxicjoin.benchmark.cases import BENCHMARK_CASES
from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog
from toxicjoin.models import ColumnRef, Decision, StrictModel
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.sql import analyze_sql


_ABLATION_QUASI_IDENTIFIER_THRESHOLD = 1_000_000
_EXPECTED_UNSAFE = 144
_EXPECTED_CONTROLS = 20


class AblationUnsafeResult(StrictModel):
    case_id: str
    family: str
    sql_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    full_policy_decision: Decision
    ablated_policy_decision: Decision
    decision_changed: bool
    passed: bool


class AblationControlResult(StrictModel):
    case_id: str
    expected_decision: Decision
    full_policy_decision: Decision
    ablated_policy_decision: Decision
    control_preserved: bool


class CompositionalAblationReport(StrictModel):
    schema_version: str = "1.0"
    evaluation_version: str = "1.0"
    policy_version: str
    ablation: str
    unsafe_cases: int = Field(ge=1)
    control_cases: int = Field(ge=1)
    full_policy_unsafe_blocks: int = Field(ge=0)
    ablated_policy_unsafe_allows: int = Field(ge=0)
    unsafe_decision_changes: int = Field(ge=0)
    controls_preserved: int = Field(ge=0)
    unsafe_results: tuple[AblationUnsafeResult, ...]
    control_results: tuple[AblationControlResult, ...]
    gate_failures: tuple[str, ...] = ()
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @property
    def passed(self) -> bool:
        return not self.gate_failures


def run_compositional_ablation(
    *, output_dir: str | Path | None = None
) -> CompositionalAblationReport:
    """Compare the shipped policy with one targeted interaction-rule ablation."""

    policy = load_policy()
    ablated_policy = policy.model_copy(
        update={
            "version": f"{policy.version}-interaction-ablation",
            "quasi_identifier_threshold": _ABLATION_QUASI_IDENTIFIER_THRESHOLD,
        }
    )
    full_engine = PolicyEngine(policy)
    ablated_engine = PolicyEngine(ablated_policy)
    resolver = FixtureContextResolver(default_fixture_catalog())

    unsafe_results = tuple(
        _evaluate_unsafe_mutation(
            resolver=resolver,
            full_engine=full_engine,
            ablated_engine=ablated_engine,
            spec=spec,
        )
        for spec in _mutation_specs()
    )
    controls = tuple(
        case
        for case in BENCHMARK_CASES
        if case.expected_initial in (Decision.ALLOW, Decision.REWRITE)
    )
    control_results = tuple(
        _evaluate_control(
            resolver=resolver,
            full_engine=full_engine,
            ablated_engine=ablated_engine,
            case=case,
        )
        for case in controls
    )

    full_policy_unsafe_blocks = sum(
        result.full_policy_decision == Decision.BLOCK for result in unsafe_results
    )
    ablated_policy_unsafe_allows = sum(
        result.ablated_policy_decision == Decision.ALLOW for result in unsafe_results
    )
    unsafe_decision_changes = sum(result.decision_changed for result in unsafe_results)
    controls_preserved = sum(result.control_preserved for result in control_results)

    failures: list[str] = []
    if len(unsafe_results) != _EXPECTED_UNSAFE:
        failures.append("unsafe_case_count_changed")
    if len(control_results) != _EXPECTED_CONTROLS:
        failures.append("control_case_count_changed")
    if full_policy_unsafe_blocks != len(unsafe_results):
        failures.append("full_policy_failed_to_block_unsafe_case")
    if ablated_policy_unsafe_allows != len(unsafe_results):
        failures.append("ablation_did_not_isolate_declared_interaction")
    if unsafe_decision_changes != len(unsafe_results):
        failures.append("unsafe_decision_change_count_mismatch")
    if controls_preserved != len(control_results):
        failures.append("ablation_changed_control_behavior")

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "evaluation_version": "1.0",
        "policy_version": policy.version,
        "ablation": (
            "same PolicyEngine with quasi_identifier_threshold raised to "
            f"{_ABLATION_QUASI_IDENTIFIER_THRESHOLD}, disabling the declared "
            "non-grouped pseudonym + quasi-identifiers + sensitive interaction "
            "for this finite evaluation while preserving other branches"
        ),
        "unsafe_cases": len(unsafe_results),
        "control_cases": len(control_results),
        "full_policy_unsafe_blocks": full_policy_unsafe_blocks,
        "ablated_policy_unsafe_allows": ablated_policy_unsafe_allows,
        "unsafe_decision_changes": unsafe_decision_changes,
        "controls_preserved": controls_preserved,
        "unsafe_results": unsafe_results,
        "control_results": control_results,
        "gate_failures": tuple(failures),
        "report_sha256": "0" * 64,
    }
    payload["report_sha256"] = _report_hash(payload)
    report = CompositionalAblationReport.model_validate(payload)

    if output_dir is not None:
        destination = Path(output_dir)
        destination.mkdir(parents=True, exist_ok=True)
        _write_atomic(
            destination / "compositional-ablation.json",
            report.model_dump_json(indent=2) + "\n",
        )
        _write_atomic(destination / "compositional-ablation.md", _markdown(report))
    return report


def _evaluate_unsafe_mutation(*, resolver, full_engine, ablated_engine, spec):
    family, customer_alias, sensitive_alias, join_style, predicate, tail = spec
    sql = _render_sql(
        family=family,
        customer_alias=customer_alias,
        sensitive_alias=sensitive_alias,
        join_style=join_style,
        predicate=predicate,
        tail=tail,
    )
    plan = analyze_sql(sql)
    context = resolver.resolve(plan)
    policy_input = context.to_policy_input(
        task_purpose=family.purpose,
        query_plan=plan,
        subject_key=ColumnRef(
            dataset="customers",
            field_path="customer_id",
            alias=customer_alias,
        ),
    )
    full = full_engine.evaluate(policy_input)
    ablated = ablated_engine.evaluate(policy_input)
    material = "|".join(
        (family.family_id, customer_alias, sensitive_alias, join_style, predicate, tail)
    )
    case_id = "A" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]
    changed = full.decision != ablated.decision
    passed = (
        full.decision == Decision.BLOCK
        and ablated.decision == Decision.ALLOW
        and changed
    )
    return AblationUnsafeResult(
        case_id=case_id,
        family=family.family_id,
        sql_sha256=hashlib.sha256(sql.encode("utf-8")).hexdigest(),
        full_policy_decision=full.decision,
        ablated_policy_decision=ablated.decision,
        decision_changed=changed,
        passed=passed,
    )


def _evaluate_control(*, resolver, full_engine, ablated_engine, case):
    plan = analyze_sql(case.sql)
    context = resolver.resolve(plan)
    policy_input = context.to_policy_input(
        task_purpose=case.task_purpose,
        query_plan=plan,
        subject_key=case.subject_key,
    )
    full = full_engine.evaluate(policy_input)
    ablated = ablated_engine.evaluate(policy_input)
    preserved = (
        full.decision == case.expected_initial
        and ablated.decision == case.expected_initial
    )
    return AblationControlResult(
        case_id=case.case_id,
        expected_decision=case.expected_initial,
        full_policy_decision=full.decision,
        ablated_policy_decision=ablated.decision,
        control_preserved=preserved,
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


def _markdown(report: CompositionalAblationReport) -> str:
    return "\n".join(
        (
            "# ToxicJoin Compositional Interaction Ablation",
            "",
            f"**Gate:** {'PASS' if report.passed else 'FAIL'}",
            f"**Unsafe mutation cases:** {report.unsafe_cases}",
            f"**Benign/remediable controls:** {report.control_cases}",
            f"**Full ToxicJoin policy blocks unsafe mutations:** {report.full_policy_unsafe_blocks}/{report.unsafe_cases}",
            f"**Interaction-ablated policy allows unsafe mutations:** {report.ablated_policy_unsafe_allows}/{report.unsafe_cases}",
            f"**Unsafe decisions changed by the ablation:** {report.unsafe_decision_changes}/{report.unsafe_cases}",
            f"**ALLOW/REWRITE controls preserved:** {report.controls_preserved}/{report.control_cases}",
            "",
            "## Interpretation",
            "",
            "This is an internal ablation study, not a competitor comparison. Both sides use the same ToxicJoin parser, governed metadata resolver, and deterministic PolicyEngine implementation. The ablated side changes one configuration dimension so the declared non-grouped cross-column interaction cannot fire in this finite evaluation.",
            "",
            "The result isolates the value of compositional reasoning: the 144 unsafe individual profiles are blocked by the shipped policy, while the targeted interaction ablation allows them. At the same time, all 20 ALLOW/REWRITE control decisions remain unchanged.",
            "",
            "This does not prove every column-local policy would behave identically, nor does it compare ToxicJoin against DataHub or another product. It measures the causal contribution of ToxicJoin's own compositional interaction rule on this declared suite.",
            "",
            f"Report SHA-256: `{report.report_sha256}`",
            "",
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate ToxicJoin compositional interaction ablation evidence"
    )
    parser.add_argument(
        "--output-dir",
        default="artifacts/compositional-ablation",
        help="Directory for JSON and Markdown evidence",
    )
    args = parser.parse_args()
    report = run_compositional_ablation(output_dir=args.output_dir)
    print(report.model_dump_json(indent=2))
    if not report.passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
