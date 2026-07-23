"""Measure whether ToxicJoin decisions causally depend on governed metadata.

This evaluation is intentionally deterministic. It uses the same normalized
``FixtureCatalog`` contract produced by the live DataHub MCP adapter, while the
separate live DataHub evidence proves that real DataHub metadata is normalized
into that contract.

The SQL, warehouse data, policy, executor, and subject key stay fixed. Only the
governance state changes. Complete governance must permit the flagship
REWRITE -> ALLOW flow; missing or unclassified governance must fail closed
before execution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from pydantic import Field

from toxicjoin.context import FixtureContextResolver
from toxicjoin.context.fixture import FixtureCatalog
from toxicjoin.demo import default_fixture_catalog, seed_database
from toxicjoin.execute import DuckDBExecutor
from toxicjoin.models import ColumnRef, Decision, ReasonCode, StrictModel
from toxicjoin.pipeline import PipelineRequest, ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import ReceiptMode, ReceiptStore


FLAGSHIP_SQL = """
SELECT
  c.coarse_region,
  AVG(r.churn_score) AS average_churn,
  COUNT(DISTINCT c.customer_id) AS subject_count
FROM customers c
JOIN retention_scores r ON c.customer_id = r.customer_id
GROUP BY c.coarse_region
"""
SUBJECT = ColumnRef(dataset="customers", field_path="customer_id", alias="c")


class GovernanceCaseResult(StrictModel):
    case_id: str
    governance_change: str
    initial_decision: Decision
    effective_decision: Decision
    initial_reason_codes: tuple[ReasonCode, ...]
    executed: bool
    verification_passed: bool | None
    output_group_count: int | None = Field(default=None, ge=0)
    observed_subject_counts: tuple[int, ...] = ()
    passed: bool


class GovernanceDependencyReport(StrictModel):
    schema_version: str = "1.0"
    evaluation_version: str = "1.0"
    policy_version: str
    data_fingerprint: str = Field(pattern=r"^[0-9a-f]{64}$")
    sql_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    cases: tuple[GovernanceCaseResult, ...]
    unsafe_effective_allow_count: int = Field(ge=0)
    gate_failures: tuple[str, ...] = ()
    report_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @property
    def passed(self) -> bool:
        return not self.gate_failures


def run_governance_dependency_evaluation(
    *,
    output_dir: str | Path | None = None,
) -> GovernanceDependencyReport:
    """Run the fixed-SQL governance causality gate."""

    policy = load_policy()
    with tempfile.TemporaryDirectory(prefix="toxicjoin-governance-proof-") as temporary:
        root = Path(temporary)
        database = root / "governance-proof.duckdb"
        seed_summary = seed_database(database)
        executor = DuckDBExecutor(database, max_preview_rows=100, timeout_seconds=5.0)

        cases = (
            _run_case(
                root=root,
                executor=executor,
                case_id="complete-governance",
                governance_change="none; canonical governed context",
                catalog=_catalog_variant("complete"),
                expected_initial=Decision.REWRITE,
                expected_effective=Decision.ALLOW,
                required_reason=ReasonCode.SMALL_GROUP_RISK,
                expect_execution=True,
            ),
            _run_case(
                root=root,
                executor=executor,
                case_id="unclassified-sensitive-field",
                governance_change=(
                    "retention_scores.churn_score has no governed sensitivity classification"
                ),
                catalog=_catalog_variant("unclassified_churn"),
                expected_initial=Decision.BLOCK,
                expected_effective=Decision.BLOCK,
                required_reason=ReasonCode.UNCLASSIFIED_COLUMN,
                expect_execution=False,
            ),
            _run_case(
                root=root,
                executor=executor,
                case_id="missing-sensitive-field",
                governance_change=(
                    "retention_scores.churn_score is absent from governed schema metadata"
                ),
                catalog=_catalog_variant("missing_churn"),
                expected_initial=Decision.BLOCK,
                expected_effective=Decision.BLOCK,
                required_reason=ReasonCode.UNRESOLVED_COLUMN,
                expect_execution=False,
            ),
            _run_case(
                root=root,
                executor=executor,
                case_id="missing-governed-dataset",
                governance_change=(
                    "retention_scores is absent from governed dataset metadata"
                ),
                catalog=_catalog_variant("missing_scores_dataset"),
                expected_initial=Decision.BLOCK,
                expected_effective=Decision.BLOCK,
                required_reason=ReasonCode.UNRESOLVED_DATASET,
                expect_execution=False,
            ),
        )

    unsafe_effective_allow_count = sum(
        case.case_id != "complete-governance"
        and case.effective_decision == Decision.ALLOW
        for case in cases
    )
    failures = [case.case_id for case in cases if not case.passed]
    if unsafe_effective_allow_count:
        failures.append("unsafe_effective_allow_detected")

    payload: dict[str, Any] = {
        "schema_version": "1.0",
        "evaluation_version": "1.0",
        "policy_version": policy.version,
        "data_fingerprint": seed_summary.data_fingerprint,
        "sql_sha256": hashlib.sha256(FLAGSHIP_SQL.encode("utf-8")).hexdigest(),
        "cases": cases,
        "unsafe_effective_allow_count": unsafe_effective_allow_count,
        "gate_failures": tuple(failures),
        "report_sha256": "0" * 64,
    }
    payload["report_sha256"] = _report_hash(payload)
    report = GovernanceDependencyReport.model_validate(payload)

    if output_dir is not None:
        destination = Path(output_dir)
        destination.mkdir(parents=True, exist_ok=True)
        _write_atomic(
            destination / "governance-dependency.json",
            report.model_dump_json(indent=2) + "\n",
        )
        _write_atomic(destination / "governance-dependency.md", _markdown(report))
    return report


def _run_case(
    *,
    root: Path,
    executor: DuckDBExecutor,
    case_id: str,
    governance_change: str,
    catalog: FixtureCatalog,
    expected_initial: Decision,
    expected_effective: Decision,
    required_reason: ReasonCode,
    expect_execution: bool,
) -> GovernanceCaseResult:
    pipeline = ToxicJoinPipeline(
        context_resolver=FixtureContextResolver(catalog),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(root / "receipts" / case_id),
        mode=ReceiptMode.FIXTURE,
        executor=executor,
        include_sanitized_sql=False,
    )
    result = pipeline.execute_safe(
        PipelineRequest(
            task_purpose="Find regions with elevated churn risk",
            sql=FLAGSHIP_SQL,
            subject_key=SUBJECT,
        )
    )

    execution = result.verification.execution if result.verification is not None else None
    executed = execution is not None
    observed_subject_counts: tuple[int, ...] = ()
    output_group_count: int | None = None
    if execution is not None:
        output_group_count = len(execution.rows)
        observed_subject_counts = tuple(sorted(int(row[2]) for row in execution.rows))

    passed = (
        result.initial_decision.decision == expected_initial
        and result.effective_decision == expected_effective
        and required_reason in result.initial_decision.reason_codes
        and executed is expect_execution
        and (
            result.verification is not None and result.verification.passed
            if expect_execution
            else result.verification is None
        )
    )
    if case_id == "complete-governance":
        passed = (
            passed
            and output_group_count == 3
            and observed_subject_counts == (40, 40, 40)
        )

    return GovernanceCaseResult(
        case_id=case_id,
        governance_change=governance_change,
        initial_decision=result.initial_decision.decision,
        effective_decision=result.effective_decision,
        initial_reason_codes=result.initial_decision.reason_codes,
        executed=executed,
        verification_passed=(
            result.verification.passed if result.verification is not None else None
        ),
        output_group_count=output_group_count,
        observed_subject_counts=observed_subject_counts,
        passed=passed,
    )


def _catalog_variant(kind: str) -> FixtureCatalog:
    payload = default_fixture_catalog().model_dump(mode="json")
    datasets = payload["datasets"]
    scores = datasets["retention_scores"]

    if kind == "complete":
        pass
    elif kind == "unclassified_churn":
        scores["fields"]["churn_score"] = {
            "category": "UNCLASSIFIED",
            "tags": [],
            "glossary_terms": [],
        }
    elif kind == "missing_churn":
        del scores["fields"]["churn_score"]
    elif kind == "missing_scores_dataset":
        del datasets["retention_scores"]
    else:
        raise ValueError(f"unknown governance catalog variant: {kind}")

    return FixtureCatalog.model_validate(payload)


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


def _markdown(report: GovernanceDependencyReport) -> str:
    lines = [
        "# ToxicJoin Governance Dependency Evaluation",
        "",
        f"**Gate:** {'PASS' if report.passed else 'FAIL'}",
        f"**Policy version:** `{report.policy_version}`",
        f"**Unsafe effective allows under degraded governance:** {report.unsafe_effective_allow_count}",
        "",
        "The SQL, synthetic warehouse, subject key, policy, and executor are fixed. Only the normalized governance state changes.",
        "",
        "| Governance state | Initial | Effective | Executed? | Result |",
        "|---|---:|---:|---:|---:|",
    ]
    for case in report.cases:
        lines.append(
            "| "
            + " | ".join(
                (
                    case.case_id,
                    f"`{case.initial_decision.value}`",
                    f"`{case.effective_decision.value}`",
                    "yes" if case.executed else "no",
                    "PASS" if case.passed else "FAIL",
                )
            )
            + " |"
        )
    lines.extend(
        (
            "",
            "## Interpretation",
            "",
            "- Complete governed context produces the intended `REWRITE -> ALLOW` path and executes only after independent verification.",
            "- Unclassified, missing-field, and missing-dataset governance states all fail closed before database execution.",
            "- This is a deterministic causality test over the normalized governance contract. Real DataHub OSS SDK/MCP connectivity and normalization are proven separately in `docs/evidence/datahub-live.md`.",
            "- This evaluation tests metadata completeness and classification presence; it does not claim that an incorrectly governed label can be inferred as wrong without an independent source of truth.",
            "",
            f"Report SHA-256: `{report.report_sha256}`",
            "",
        )
    )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate ToxicJoin governance-dependency evidence"
    )
    parser.add_argument(
        "--output-dir",
        default="artifacts/governance-dependency",
        help="Directory for JSON and Markdown evidence",
    )
    args = parser.parse_args()
    report = run_governance_dependency_evaluation(output_dir=args.output_dir)
    print(report.model_dump_json(indent=2))
    if not report.passed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
