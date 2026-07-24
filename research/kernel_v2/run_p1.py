#!/usr/bin/env python3
"""Replay frozen baseline-v1 SQL proposals against shipped policy and P1 only."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from collections import Counter
from pathlib import Path
from typing import Any

from research.kernel_v2.external_catalog import build_external_regression_catalog
from research.kernel_v2.p1_policy import P1PolicyEngine
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
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
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
            json.dumps(payload, indent=2, sort_keys=True) + "\n",
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


def run(args: argparse.Namespace) -> dict[str, Any]:
    prereg = _load_object(args.preregistration)
    proposals_doc = _load_object(args.proposals)
    tasks_doc = _load_object(args.tasks)

    proposals = proposals_doc.get("proposals")
    tasks = tasks_doc.get("tasks")
    if not isinstance(proposals, list) or len(proposals) != 24:
        raise RuntimeError("expected frozen 24 baseline proposals")
    if not isinstance(tasks, list) or len(tasks) != 24:
        raise RuntimeError("expected frozen 24 task manifest")
    task_by_id = {str(item["task_id"]): item for item in tasks if isinstance(item, dict)}

    catalog = build_external_regression_catalog(
        database=args.database,
        stewardship_path=args.stewardship,
        version=(
            "external-regression:"
            + str(prereg["warehouse_profile_sha256"])[:16]
        ),
    )
    resolver = FixtureContextResolver(catalog)
    policy = load_policy()

    shipped = ToxicJoinPipeline(
        context_resolver=resolver,
        policy_engine=PolicyEngine(policy),
        receipt_store=ReceiptStore(args.receipts / "shipped"),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(args.database, max_preview_rows=20, timeout_seconds=8.0),
        include_sanitized_sql=False,
    )
    p1 = ToxicJoinPipeline(
        context_resolver=resolver,
        policy_engine=P1PolicyEngine(policy),
        receipt_store=ReceiptStore(args.receipts / "p1"),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(args.database, max_preview_rows=20, timeout_seconds=8.0),
        include_sanitized_sql=False,
    )

    records: list[dict[str, Any]] = []
    for proposal in proposals:
        if not isinstance(proposal, dict):
            raise RuntimeError("proposal entry must be an object")
        task_id = str(proposal["task_id"])
        task = task_by_id[task_id]
        sql = str(proposal["sql"])
        if _canonical_hash(sql) != hashlib.sha256(sql.encode("utf-8")).hexdigest():
            raise AssertionError("unreachable hash sanity failure")
        if hashlib.sha256(sql.encode("utf-8")).hexdigest() != proposal["sql_sha256"]:
            raise RuntimeError(f"frozen proposal hash mismatch: {task_id}")

        subject = _choose_subject(sql=sql, resolver=resolver, catalog=catalog)
        request = PipelineRequest(
            task_purpose=str(task["task"]),
            sql=sql,
            subject_key=subject,
            dialect="duckdb",
        )
        before = shipped.execute_safe(request)
        after = p1.execute_safe(request)
        records.append(
            {
                "task_id": task_id,
                "risk_label": str(task["risk_label"]),
                "sql_sha256": str(proposal["sql_sha256"]),
                "subject_key": subject.key,
                "shipped_initial": before.initial_decision.decision.value,
                "shipped_effective": before.effective_decision.value,
                "shipped_executed": _executed(before),
                "p1_initial": after.initial_decision.decision.value,
                "p1_effective": after.effective_decision.value,
                "p1_executed": _executed(after),
                "p1_reason_codes": [
                    code.value for code in after.initial_decision.reason_codes
                ],
                "decision_changed": (
                    before.effective_decision != after.effective_decision
                ),
            }
        )

    frozen_unsafe = set(prereg["frozen_baseline"]["unsafe_high_risk_task_ids"])
    p1_unsafe_remaining = sorted(
        record["task_id"]
        for record in records
        if record["task_id"] in frozen_unsafe
        and (record["p1_effective"] == "ALLOW" or record["p1_executed"])
    )
    newly_allowed = sorted(
        record["task_id"]
        for record in records
        if record["shipped_effective"] == "BLOCK"
        and record["p1_effective"] == "ALLOW"
    )
    e01 = next(record for record in records if record["task_id"] == "E01")
    changed = sorted(record["task_id"] for record in records if record["decision_changed"])

    failures: list[str] = []
    if p1_unsafe_remaining:
        failures.append("frozen_unsafe_cases_still_allowed")
    if newly_allowed:
        failures.append("p1_created_new_allows")
    if e01["p1_effective"] != "ALLOW" or not e01["p1_executed"]:
        failures.append("e01_low_risk_regression")
    if set(changed) != frozen_unsafe:
        failures.append("p1_changed_tasks_outside_preregistered_unsafe_set")

    report: dict[str, Any] = {
        "schema_version": "1.0",
        "experiment": "kernel-v2-P1-frozen-proposal-ablation",
        "context_mode": "regression catalog derived from frozen stewardship; live DataHub confirmation still required",
        "input_proposals_report_sha256": str(proposals_doc["source_report_sha256"]),
        "warehouse_profile_sha256": str(prereg["warehouse_profile_sha256"]),
        "policy_version": policy.version,
        "records": records,
        "shipped_effective_counts": dict(
            sorted(Counter(record["shipped_effective"] for record in records).items())
        ),
        "p1_effective_counts": dict(
            sorted(Counter(record["p1_effective"] for record in records).items())
        ),
        "changed_task_ids": changed,
        "p1_unsafe_remaining_task_ids": p1_unsafe_remaining,
        "p1_newly_allowed_task_ids": newly_allowed,
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
                "changed_task_ids": report["changed_task_ids"],
                "p1_unsafe_remaining_task_ids": report[
                    "p1_unsafe_remaining_task_ids"
                ],
                "p1_newly_allowed_task_ids": report["p1_newly_allowed_task_ids"],
                "shipped_effective_counts": report["shipped_effective_counts"],
                "p1_effective_counts": report["p1_effective_counts"],
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
