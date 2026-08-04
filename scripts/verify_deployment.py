"""Verify that a deployed ToxicJoin URL serves the hardened engine.

A green deploy proves the container started, not that it enforces anything. This script drives
the public API of a running deployment and asserts on the outcomes that matter: the three
deterministic decisions still hold, and both proven privacy bypasses are still refused with
zero rows released.

It is the check to run after every deploy, because the failure it is designed to catch — a
stale image that still contains the bypasses — looks completely healthy from the outside.

    python scripts/verify_deployment.py https://toxicjoin.fly.dev
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any


CUSTOMER_SUBJECT = {"dataset": "customers", "field_path": "customer_id", "alias": "c"}
ORDER_SUBJECT = {"dataset": "orders", "field_path": "order_id", "alias": "o"}


@dataclass
class Check:
    name: str
    sql: str
    subject: dict[str, str]
    expect_decision: str
    expect_rows: int | None
    expect_reason: str | None = None
    note: str = ""


CHECKS: tuple[Check, ...] = (
    Check(
        name="allow-public-aggregate",
        sql=(
            "SELECT o.category, COUNT(*) AS order_count\n"
            "FROM orders o\nGROUP BY o.category\nORDER BY o.category"
        ),
        subject=CUSTOMER_SUBJECT,
        expect_decision="ALLOW",
        expect_rows=4,
        note="benign work must not be denied",
    ),
    Check(
        name="rewrite-to-verified-allow",
        sql=(
            "SELECT c.coarse_region, AVG(r.churn_score) AS average_churn,\n"
            "       COUNT(DISTINCT c.customer_id) AS subject_count\n"
            "FROM customers c\n"
            "JOIN retention_scores r ON c.customer_id = r.customer_id\n"
            "GROUP BY c.coarse_region"
        ),
        subject=CUSTOMER_SUBJECT,
        expect_decision="ALLOW",
        expect_rows=3,
        note="remediation still reaches a verified release",
    ),
    Check(
        name="block-compositional-risk",
        sql=(
            "SELECT c.customer_id, c.age_band, c.precise_area, s.case_category\n"
            "FROM customers c\n"
            "JOIN support_cases s ON c.customer_id = s.customer_id"
        ),
        subject=CUSTOMER_SUBJECT,
        expect_decision="BLOCK",
        expect_rows=0,
        expect_reason="COMPOSITIONAL_REIDENTIFICATION_RISK",
        note="individual-level composition is refused",
    ),
    Check(
        name="bypass-fabricated-subject-count",
        sql=(
            "SELECT c.age_band, c.coarse_region, AVG(o.purchase_amount) AS avg_spend,\n"
            "       999 AS subject_count\n"
            "FROM customers c\n"
            "JOIN orders o ON c.customer_id = o.customer_id\n"
            "GROUP BY c.age_band, c.coarse_region\n"
            "HAVING NOT (COUNT(DISTINCT c.customer_id) >= 20)"
        ),
        subject=CUSTOMER_SUBJECT,
        expect_decision="BLOCK",
        expect_rows=0,
        note="CLOSED BYPASS: a literal must not stand in for a distinct count",
    ),
    Check(
        name="bypass-attacker-chosen-subject",
        sql=(
            "SELECT c.age_band, c.coarse_region, AVG(o.purchase_amount) AS avg_spend,\n"
            "       COUNT(DISTINCT o.order_id) AS subject_count\n"
            "FROM customers c\n"
            "JOIN orders o ON c.customer_id = o.customer_id\n"
            "GROUP BY c.age_band, c.coarse_region\n"
            "HAVING COUNT(DISTINCT o.order_id) >= 20"
        ),
        subject=ORDER_SUBJECT,
        expect_decision="BLOCK",
        expect_rows=0,
        expect_reason="UNTRUSTED_SUBJECT_KEY",
        note="CLOSED BYPASS: only a governed identifier may witness k-anonymity",
    ),
)


@dataclass
class Result:
    passed: bool
    lines: list[str] = field(default_factory=list)


def _request(url: str, *, payload: dict[str, Any] | None, token: str | None) -> Any:
    headers = {"Accept": "application/json"}
    data = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(request, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))


def _released_rows(body: dict[str, Any]) -> int:
    verification = body.get("verification") or {}
    execution = verification.get("execution")
    return len(execution["rows"]) if execution else 0


def _reasons(body: dict[str, Any]) -> list[str]:
    final = (body.get("final_decision") or {}).get("reason_codes") or []
    return list(final) or list(body["initial_decision"]["reason_codes"])


def run(base_url: str, *, token: str | None) -> Result:
    base = base_url.rstrip("/")
    result = Result(passed=True)

    try:
        ready = _request(f"{base}/api/ready", payload=None, token=token)
    except urllib.error.HTTPError as exc:
        result.passed = False
        result.lines.append(f"FAIL  readiness returned HTTP {exc.code}")
        return result
    except Exception as exc:
        result.passed = False
        result.lines.append(f"FAIL  {base} is unreachable: {type(exc).__name__}")
        return result

    result.lines.append(
        f"      mode={ready.get('mode')} policy={ready.get('policy_version')} "
        f"status={ready.get('status')}"
    )
    if ready.get("status") != "ok":
        result.passed = False
        result.lines.append("FAIL  deployment reports degraded readiness")

    for check in CHECKS:
        payload = {
            "task_purpose": f"deployment verification: {check.name}",
            "sql": check.sql,
            "subject_key": check.subject,
        }
        try:
            body = _request(f"{base}/api/execute-safe", payload=payload, token=token)
        except urllib.error.HTTPError as exc:
            result.passed = False
            result.lines.append(f"FAIL  {check.name}: HTTP {exc.code}")
            continue
        except Exception as exc:
            result.passed = False
            result.lines.append(f"FAIL  {check.name}: {type(exc).__name__}")
            continue

        decision = body.get("effective_decision")
        rows = _released_rows(body)
        problems = []
        if decision != check.expect_decision:
            problems.append(f"decision={decision} expected={check.expect_decision}")
        if check.expect_rows is not None and rows != check.expect_rows:
            problems.append(f"rows={rows} expected={check.expect_rows}")
        if check.expect_reason and check.expect_reason not in _reasons(body):
            problems.append(f"missing reason {check.expect_reason} (got {_reasons(body)})")

        if problems:
            result.passed = False
            result.lines.append(f"FAIL  {check.name}: {'; '.join(problems)}")
            if check.note.startswith("CLOSED BYPASS"):
                result.lines.append(
                    "      ^ this deployment may be running an image from before the fix"
                )
        else:
            result.lines.append(f"pass  {check.name}  ({decision}, {rows} rows) - {check.note}")

    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="base URL of the deployment")
    parser.add_argument(
        "--token",
        default=None,
        help="bearer API key, required for an authenticated deployment",
    )
    args = parser.parse_args()

    print(f"Verifying {args.url}\n")
    result = run(args.url, token=args.token)
    for line in result.lines:
        print(line)

    print()
    if result.passed:
        print("PASS - deployment serves the hardened engine.")
        sys.exit(0)
    print("FAIL - deployment did not behave as required. Do not present this URL.")
    sys.exit(1)


if __name__ == "__main__":
    main()
