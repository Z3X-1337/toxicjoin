"""Generate auditable evidence for cumulative cross-query disclosure enforcement."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from toxicjoin.auth import RequestIdentity, bind_request_identity
from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog, seed_database
from toxicjoin.disclosure import DisclosureLedger
from toxicjoin.execute import DuckDBExecutor
from toxicjoin.models import ColumnRef, Decision
from toxicjoin.pipeline import PipelineRequest, ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import ReceiptMode, ReceiptStore


_SUBJECT = ColumnRef(dataset="customers", field_path="customer_id")
_TASK = "Cumulative privacy evidence for approved aggregate analytics"


def _sql(region: str, *, aggregate: str = "COUNT", alias: str = "subject_count") -> str:
    if aggregate == "COUNT":
        expression = "COUNT(DISTINCT c.customer_id)"
    elif aggregate == "MAX":
        expression = "MAX(c.coarse_region)"
    else:
        raise ValueError(aggregate)
    return (
        f"SELECT {expression} AS {alias} FROM customers c "
        f"WHERE c.coarse_region = '{region}'"
    )


def _identity(
    *,
    credential: str = "evidence-credential-a",
    session: str = "evidence-session-a",
) -> RequestIdentity:
    return RequestIdentity(
        principal_id="evidence-principal",
        credential_id=credential,
        agent_id="evidence-agent",
        session_id=session,
    )


def _pipeline(root: Path) -> ToxicJoinPipeline:
    database = root / "fixture.duckdb"
    if not database.exists():
        seed_database(database)
    return ToxicJoinPipeline(
        context_resolver=FixtureContextResolver(default_fixture_catalog()),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(root / "receipts"),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(database),
        disclosure_ledger=DisclosureLedger(root / "disclosures.sqlite3"),
        stateful_privacy_required=True,
        include_sanitized_sql=False,
    )


def _execute(
    pipeline: ToxicJoinPipeline,
    sql: str,
    *,
    identity: RequestIdentity,
) -> dict[str, Any]:
    with bind_request_identity(identity):
        result = pipeline.execute_safe(
            PipelineRequest(
                task_purpose=_TASK,
                sql=sql,
                subject_key=_SUBJECT,
            )
        )
    verification = result.verification
    return {
        "initial_decision": result.initial_decision.decision.value,
        "effective_decision": result.effective_decision.value,
        "final_reason_codes": [
            code.value
            for code in (
                result.final_decision.reason_codes if result.final_decision is not None else ()
            )
        ],
        "execution_released": bool(verification is not None and verification.execution is not None),
        "execution_attempted": bool(verification is not None and verification.execution_attempted),
        "cumulative_check": next(
            (
                {
                    "passed": check.passed,
                    "detail": check.detail,
                }
                for check in (verification.checks if verification is not None else ())
                if check.name == "cumulative_disclosure"
            ),
            None,
        ),
        "receipt_id": result.receipt.receipt_id,
    }


def generate_report() -> dict[str, Any]:
    cases: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="toxicjoin-disclosure-evidence-") as directory:
        root = Path(directory)

        same_root = root / "same-release"
        pipeline = _pipeline(same_root)
        first = _execute(pipeline, _sql("north"), identity=_identity())
        repeat = _execute(
            pipeline,
            _sql("north", alias="renamed_count"),
            identity=_identity(credential="evidence-credential-b", session="evidence-session-b"),
        )
        cases.append(
            {
                "id": "same_cohort_alias_and_credential_rotation",
                "first": first,
                "second": repeat,
                "assertion": first["effective_decision"] == "ALLOW"
                and repeat["effective_decision"] == "ALLOW"
                and repeat["execution_released"],
            }
        )

        changed_root = root / "changed-cohort"
        pipeline = _pipeline(changed_root)
        first = _execute(pipeline, _sql("north"), identity=_identity())
        changed = _execute(
            pipeline,
            _sql("south"),
            identity=_identity(credential="evidence-credential-b", session="evidence-session-b"),
        )
        cases.append(
            {
                "id": "changed_cohort_differencing_block",
                "first": first,
                "second": changed,
                "assertion": first["effective_decision"] == "ALLOW"
                and changed["initial_decision"] == "ALLOW"
                and changed["effective_decision"] == "BLOCK"
                and "CUMULATIVE_DISCLOSURE_RISK" in changed["final_reason_codes"]
                and not changed["execution_released"]
                and not changed["execution_attempted"],
            }
        )

        family_root = root / "changed-family"
        pipeline = _pipeline(family_root)
        first = _execute(pipeline, _sql("north"), identity=_identity())
        family_changed = _execute(
            pipeline,
            _sql("north", aggregate="MAX", alias="max_region"),
            identity=_identity(),
        )
        cases.append(
            {
                "id": "changed_release_family_block",
                "first": first,
                "second": family_changed,
                "assertion": first["effective_decision"] == "ALLOW"
                and family_changed["initial_decision"] == "ALLOW"
                and family_changed["effective_decision"] == "BLOCK"
                and not family_changed["execution_released"],
            }
        )

        restart_root = root / "restart"
        first_pipeline = _pipeline(restart_root)
        first = _execute(first_pipeline, _sql("north"), identity=_identity())
        restarted_pipeline = _pipeline(restart_root)
        after_restart = _execute(
            restarted_pipeline,
            _sql("south"),
            identity=_identity(),
        )
        cases.append(
            {
                "id": "restart_preserves_privacy_history",
                "first": first,
                "second": after_restart,
                "assertion": first["effective_decision"] == "ALLOW"
                and after_restart["effective_decision"] == "BLOCK"
                and not after_restart["execution_released"],
            }
        )

    return {
        "schema_version": "1.0",
        "git_sha": os.getenv("GITHUB_SHA"),
        "policy_version": load_policy().version,
        "model": "controlled-query cumulative composition",
        "cases": cases,
        "passed": all(case["assertion"] for case in cases),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = generate_report()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    if not report["passed"]:
        raise SystemExit("cumulative disclosure sequence evidence failed")


if __name__ == "__main__":
    main()
