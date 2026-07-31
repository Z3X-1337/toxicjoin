"""Produce a live read-only DataHub semantic policy evidence report."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from toxicjoin.context import (
    DataHubAssetMap,
    DataHubSnapshotContextResolver,
    DataHubSnapshotLoader,
)
from toxicjoin.integrations.datahub_authority import (
    DataHubMcpRole,
    RoleBoundDataHubMcpClient,
    read_only_settings_from_env,
)
from toxicjoin.integrations.datahub_mcp import StdioDataHubMcpTransport
from toxicjoin.models import ColumnRef, Decision, ProjectionExposureKind, ReasonCode
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.sql import analyze_sql


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _hash(value: dict[str, Any]) -> str:
    payload = {key: item for key, item in value.items() if key != "report_sha256"}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    ).hexdigest()


def _write(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    temp: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb", dir=path.parent, prefix=f".{path.name}.", delete=False
        ) as handle:
            temp = Path(handle.name)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp, path)
        temp = None
    finally:
        if temp is not None:
            temp.unlink(missing_ok=True)


async def _load(asset_map_path: str) -> Any:
    settings = read_only_settings_from_env()
    if settings.role != DataHubMcpRole.READ_ONLY or settings.mutation_enabled:
        raise RuntimeError("live policy snapshot did not use read-only settings")
    asset_map = DataHubAssetMap.from_path(asset_map_path)
    async with StdioDataHubMcpTransport(settings) as transport:
        client = RoleBoundDataHubMcpClient(transport, role=DataHubMcpRole.READ_ONLY)
        return await DataHubSnapshotLoader(client, asset_map).load(
            require_mutations=False
        )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--asset-map", default="config/datahub-assets.json")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    snapshot = asyncio.run(_load(args.asset_map))
    if "save_document" in snapshot.discovered_tools:
        raise RuntimeError("live policy read process exposed save_document")
    policy = load_policy()
    if policy.version != "0.2.0":
        raise RuntimeError("live policy version mismatch")

    flagship = snapshot.catalog.datasets["retention_scores"].fields["churn_score"]
    flagship_lineage = {
        source.ref.key: source.category.value for source in flagship.lineage_sources
    }
    if set(flagship_lineage) != {
        "location_activity.activity_count",
        "location_activity.precise_area",
        "orders.purchase_amount",
        "support_cases.case_category",
        "support_cases.sensitivity_level",
    }:
        raise RuntimeError("live flagship lineage inventory mismatch")

    sql = """
    SELECT c.customer_id, r.churn_score
    FROM customers c
    JOIN retention_scores r ON c.customer_id = r.customer_id
    LIMIT 5
    """
    plan = analyze_sql(sql, dialect="duckdb")
    context = DataHubSnapshotContextResolver(snapshot).resolve(plan)
    decision = PolicyEngine(policy).evaluate(
        context.to_policy_input(
            task_purpose="Phase 5 exact-source Live DataHub semantic gate",
            query_plan=plan,
            subject_key=ColumnRef(
                dataset="customers", field_path="customer_id", alias="c"
            ),
        )
    )
    if decision.decision != Decision.BLOCK:
        raise RuntimeError("live semantic policy decision was not BLOCK")
    if ReasonCode.COMPOSITIONAL_REIDENTIFICATION_RISK not in decision.reason_codes:
        raise RuntimeError("live policy decision missed compositional risk")

    wrapped = analyze_sql(
        "SELECT UPPER(c.customer_id) AS subject_token FROM customers c LIMIT 5",
        dialect="duckdb",
    )
    exposure = wrapped.projected_exposures
    if len(exposure) != 1 or exposure[0].kind != ProjectionExposureKind.TRANSFORMED_RAW_VALUE:
        raise RuntimeError("transformed raw exposure was not preserved")

    report: dict[str, Any] = {
        "schema_version": "1.0",
        "status": "verified",
        "created_at": _now(),
        "policy_version": policy.version,
        "live_semantic_decision": decision.decision.value,
        "live_semantic_reason_codes": [code.value for code in decision.reason_codes],
        "wrapped_output_kind": exposure[0].kind.value,
        "snapshot_catalog_version": snapshot.catalog.version,
        "flagship_lineage": flagship_lineage,
        "read_only_mcp": True,
        "save_document_exposed": False,
        "report_sha256": "0" * 64,
    }
    report["report_sha256"] = _hash(report)
    _write(Path(args.output), report)
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
