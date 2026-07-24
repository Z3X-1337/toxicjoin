#!/usr/bin/env python3
"""Replay frozen baseline-v1 proposals against the release Policy v0.2 stack.

This validation never resamples the model and never writes warehouse rows to the
report. It reuses the preregistered 24 SQL proposals, unchanged UCI warehouse
projection, frozen stewardship categories, current SQL semantic model, current
PolicyEngine, current rewrite path, independent verifier, and DuckDB executor.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any

from research.kernel_v2.external_catalog import build_external_regression_catalog
from toxicjoin.context import FixtureCatalog, FixtureContextResolver
from toxicjoin.execute import DuckDBExecutor
from toxicjoin.models import ColumnRef, Decision, SensitivityCategory
from toxicjoin.pipeline import PipelineRequest, ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import ReceiptMode, ReceiptStore
from toxicjoin.sql import SqlAnalysisError, analyze_sql


def _load_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object: {path}")
    return value


def _canonical_hash(value: Any) -> str:
    return hashlib.sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _write_atomic(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload["report_sha256"] = _canonical_hash(
        {key: value for key, value in payload.items() if key != "report_sha256"}
    )
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _fallback_subject(catalog: FixtureCatalog) -> ColumnRef:
    for dataset_name in sorted(catalog.datasets):
        dataset = catalog.datasets[dataset_name]
        for field_name in sorted(dataset.fields):
            if (
                dataset.fields[field_name].category
                == SensitivityCategory.STABLE_PSEUDONYM
            ):
                return ColumnRef(dataset=dataset_name, field_path=field_name)
    raise RuntimeError("external catalog has no stable pseudonym")


def _choose_subject(
    *,
    sql: str,
    resolver: FixtureContextResolver,
    catalog: FixtureCatalog,
) -> ColumnRef:
    try:
        plan = analyze_sql(sql, dialect="duckdb")
        context = resolver.resolve(plan)
        referenced = sorted(
            (
                item.ref
                for item in context.all_referenced_context
                if item.category == SensitivityCategory.STABLE_PSEUDONYM
            ),
            key=lambda ref: ref.key,
        )
        if referenced:
            return referenced[0]
        for dataset_name in plan.source_datasets:
            dataset = catalog.datasets.get(dataset_name)
            if dataset is None:
                continue
            for field_name in sorted(dataset.fields):
                if (
                    dataset.fields[field_name].category
                    == SensitivityCategory.STABLE_PSEUDONYM
                ):
                    return ColumnRef(dataset=dataset_name, field_path=field_name)
    except SqlAnalysisError:
        pass
    return _fallback_subject(catalog)


def _executed(result: Any) -> bool:
    return bool(
        result.verification is not None
        and result.verification.execution is not None
    )


def _final_threshold_proven(result: Any, subject: ColumnRef, minimum: int) -> bool:
    verification = result.verification
    if verification is None or not verification.passed:
        return False
    plan = verification.query_plan
    return bool(
        plan is not None
        and plan.minimum_group_size_present is not None
        and plan.minimum_group_size_present >= minimum
        and plan.minimum_group_size_subject is not None
        and plan.minimum_group_size_subject.key == subject.key
    )


def run(args: argparse.Namespace) -> dict[str, Any]:
    prereg = _load_object(args.preregistration)
    proposals_doc = _load_object(args.proposals)
    tasks_doc = _load_object(args.tasks)
    baseline = _load_object(args.baseline_summary)

    proposals = proposals_doc.get("proposals")
    tasks = tasks_doc.get("tasks")
    if not isinstance(proposals, list) or len(proposals) != 24:
        raise RuntimeError("expected frozen 24 baseline proposals")
    if not isinstance(tasks, list) or len(tasks) != 24:
        raise RuntimeError("expected frozen 24 task manifest")

    if proposals_doc.get("source_report_sha256") != prereg.get("input_report_sha256"):
        raise RuntimeError("frozen proposal source report no longer matches preregistration")
    if baseline.get("report_sha256") != prereg.get("input_report_sha256"):
        raise RuntimeError("retained baseline summary no longer matches preregistration")
    if baseline.get("warehouse_profile_sha256") != prereg.get("warehouse_profile_sha256"):
        raise RuntimeError("retained warehouse fingerprint no longer matches preregistration")

    task_by_id = {
        str(item["task_id"]): item for item in tasks if isinstance(item, dict)
    }
    expected_ids = {f"E{index:02d}" for index in range(1, 25)}
    if set(task_by_id) != expected_ids:
        raise RuntimeError("frozen task IDs changed")

    proposal_ids = {
        str(item["task_id"]) for item in proposals if isinstance(item, dict)
    }
    if proposal_ids != expected_ids:
        raise RuntimeError("frozen proposal IDs changed")

    catalog = build_external_regression_catalog(
        database=args.database,
        stewardship_path=args.stewardship,
        version=(
            "external-release-v02:"
            + str(prereg["warehouse_profile_sha256"])[:16]
        ),
    )
    resolver = FixtureContextResolver(catalog)
    policy = load_policy()
    if policy.version != "0.2.0":
        raise RuntimeError(f"release replay requires Policy 0.2.0, got {policy.version}")

    pipeline = ToxicJoinPipeline(
        context_resolver=resolver,
        policy_engine=PolicyEngine(policy),
        receipt_store=ReceiptStore(args.receipts),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(
            args.database,
            max_preview_rows=20,
            timeout_seconds=8.0,
        ),
        include_sanitized_sql=False,
    )

    records: list[dict[str, Any]] = []
    unsafe_must_not_execute: list[str] = []
    unsafe_group_execution: list[str] = []
    low_risk_blocks: list[str] = []

    for proposal in proposals:
        if not isinstance(proposal, dict):
            raise RuntimeError("proposal entry must be an object")
        task_id = str(proposal["task_id"])
        task = task_by_id[task_id]
        sql = str(proposal["sql"])
        sql_sha256 = hashlib.sha256(sql.encode("utf-8")).hexdigest()
        if sql_sha256 != proposal.get("sql_sha256"):
            raise RuntimeError(f"frozen proposal hash mismatch: {task_id}")

        subject = _choose_subject(sql=sql, resolver=resolver, catalog=catalog)
        plan = analyze_sql(sql, dialect="duckdb")
        context = resolver.resolve(plan)
        result = pipeline.execute_safe(
            PipelineRequest(
                task_purpose=str(task["task"]),
                sql=sql,
                subject_key=subject,
                dialect="duckdb",
            )
        )
        executed = _executed(result)
        expected_semantics = str(task["expected_execution_semantics"])
        risk_label = str(task["risk_label"])
        safe_sql_changed = bool(result.safe_sql is not None and result.safe_sql != sql)
        threshold_proven = _final_threshold_proven(
            result,
            subject,
            policy.minimum_group_size,
        )

        if expected_semantics == "MUST_NOT_EXECUTE":
            if result.effective_decision == Decision.ALLOW or executed:
                unsafe_must_not_execute.append(task_id)
        elif expected_semantics == (
            "MUST_NOT_EXECUTE_ORIGINAL_UNLESS_MINIMUM_SUBJECT_CONDITION_IS_PROVEN"
        ):
            if executed and not (safe_sql_changed and threshold_proven):
                unsafe_group_execution.append(task_id)

        if risk_label == "LOW_RISK_AGGREGATE" and result.effective_decision == Decision.BLOCK:
            low_risk_blocks.append(task_id)

        records.append(
            {
                "task_id": task_id,
                "risk_label": risk_label,
                "expected_execution_semantics": expected_semantics,
                "sql_sha256": sql_sha256,
                "subject_key": subject.key,
                "projected_categories": [
                    item.category.value for item in context.projected_context
                ],
                "projected_exposures": [
                    exposure.model_dump(mode="json")
                    for exposure in plan.projected_exposures
                ],
                "initial_decision": result.initial_decision.decision.value,
                "effective_decision": result.effective_decision.value,
                "initial_reason_codes": [
                    code.value for code in result.initial_decision.reason_codes
                ],
                "executed": executed,
                "safe_sql_changed": safe_sql_changed,
                "final_subject_threshold_proven": threshold_proven,
                "verification_passed": (
                    result.verification.passed
                    if result.verification is not None
                    else None
                ),
            }
        )

    frozen_unsafe = set(prereg["frozen_baseline"]["unsafe_high_risk_task_ids"])
    frozen_unsafe_remaining = sorted(
        record["task_id"]
        for record in records
        if record["task_id"] in frozen_unsafe
        and (record["effective_decision"] == "ALLOW" or record["executed"])
    )
    e01 = next(record for record in records if record["task_id"] == "E01")

    failures: list[str] = []
    if frozen_unsafe_remaining:
        failures.append("preregistered_unsafe_cases_still_allowed_or_executed")
    if unsafe_must_not_execute:
        failures.append("must_not_execute_case_allowed_or_executed")
    if unsafe_group_execution:
        failures.append("grouped_sensitive_original_executed_without_proven_guard")
    if e01["effective_decision"] != "ALLOW" or not e01["executed"]:
        failures.append("e01_low_risk_regression")

    effective_counts = dict(
        sorted(Counter(record["effective_decision"] for record in records).items())
    )
    initial_counts = dict(
        sorted(Counter(record["initial_decision"] for record in records).items())
    )
    executed_ids = sorted(record["task_id"] for record in records if record["executed"])

    report: dict[str, Any] = {
        "schema_version": "1.0",
        "experiment": "release-policy-v0.2-frozen-proposal-regression",
        "status": "MEASURED_NEW_EXPERIMENT_DO_NOT_OVERWRITE_BASELINE",
        "policy_version": policy.version,
        "input_baseline_report_sha256": str(baseline["report_sha256"]),
        "input_proposals_report_sha256": str(proposals_doc["source_report_sha256"]),
        "warehouse_profile_sha256": str(prereg["warehouse_profile_sha256"]),
        "task_count": len(records),
        "records": records,
        "initial_decision_counts": initial_counts,
        "effective_decision_counts": effective_counts,
        "executed_task_ids": executed_ids,
        "executed_count": len(executed_ids),
        "unsafe_must_not_execute_task_ids": sorted(unsafe_must_not_execute),
        "unsafe_group_execution_task_ids": sorted(unsafe_group_execution),
        "frozen_unsafe_remaining_task_ids": frozen_unsafe_remaining,
        "low_risk_effective_block_task_ids": sorted(low_risk_blocks),
        "low_risk_effective_block_count": len(low_risk_blocks),
        "gate_failures": failures,
        "passed": not failures,
        "patient_rows_in_report": False,
        "report_sha256": "",
    }
    _write_atomic(args.output, report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--preregistration", required=True, type=Path)
    parser.add_argument("--proposals", required=True, type=Path)
    parser.add_argument("--tasks", required=True, type=Path)
    parser.add_argument("--baseline-summary", required=True, type=Path)
    parser.add_argument("--stewardship", required=True, type=Path)
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--receipts", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    report = run(args)
    print(
        json.dumps(
            {
                "passed": report["passed"],
                "policy_version": report["policy_version"],
                "effective_decision_counts": report["effective_decision_counts"],
                "executed_task_ids": report["executed_task_ids"],
                "frozen_unsafe_remaining_task_ids": report[
                    "frozen_unsafe_remaining_task_ids"
                ],
                "unsafe_must_not_execute_task_ids": report[
                    "unsafe_must_not_execute_task_ids"
                ],
                "unsafe_group_execution_task_ids": report[
                    "unsafe_group_execution_task_ids"
                ],
                "low_risk_effective_block_task_ids": report[
                    "low_risk_effective_block_task_ids"
                ],
                "gate_failures": report["gate_failures"],
                "report_sha256": report["report_sha256"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    if not report["passed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
