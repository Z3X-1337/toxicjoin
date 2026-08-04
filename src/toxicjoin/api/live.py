"""Construct the live-DataHub runtime for the HTTP server.

`create_default_pipeline` builds fixture mode and nothing built the live equivalent, so the
governed path existed as a library and a one-shot CLI but never as a running service. This
module is that missing assembly step, and it is deliberately strict about three things:

* **Read-only credentials only.** The context path is built from `DATAHUB_GMS_READ_TOKEN`
  through a role-bound client that cannot mutate. Write-back is a separate, isolated process
  and does not belong on the request path.
* **Fail fast at startup.** If DataHub is unreachable or its metadata does not normalize, the
  server does not come up. A process that starts anyway would be advertising live governance
  it cannot supply.
* **Stateful privacy is not optional.** `ReceiptMode.LIVE` already refuses to disable it; this
  factory provisions the ledger so that requirement can actually be met.
"""

from __future__ import annotations

import asyncio
import os
from dataclasses import dataclass
from pathlib import Path

from toxicjoin.context.datahub import (
    DataHubAssetMap,
    DataHubSnapshot,
    DataHubSnapshotContextResolver,
    DataHubSnapshotLoader,
)
from toxicjoin.context.refresher import DataHubSnapshotRefresher
from toxicjoin.disclosure import DisclosureLedger
from toxicjoin.execute import DuckDBExecutor
from toxicjoin.integrations.datahub_authority import (
    DataHubMcpRole,
    RoleBoundDataHubMcpClient,
    read_only_settings_from_env,
)
from toxicjoin.integrations.datahub_mcp import (
    DataHubMcpTransport,
    StdioDataHubMcpTransport,
)
from toxicjoin.pipeline import ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import ReceiptMode, ReceiptStore


MODE_ENV = "TOXICJOIN_MODE"
ASSET_MAP_ENV = "TOXICJOIN_DATAHUB_ASSET_MAP"
SNAPSHOT_MAX_AGE_ENV = "TOXICJOIN_DATAHUB_SNAPSHOT_MAX_AGE_SECONDS"
DEFAULT_ASSET_MAP = "config/datahub-assets.json"


def live_mode_requested(environ: dict[str, str] | None = None) -> bool:
    source = os.environ if environ is None else environ
    return source.get(MODE_ENV, "").strip().casefold() == "live"


@dataclass(frozen=True)
class LiveRuntime:
    """The live pipeline and the refresher whose lifetime is tied to the server."""

    pipeline: ToxicJoinPipeline
    refresher: DataHubSnapshotRefresher
    snapshot: DataHubSnapshot


async def load_live_snapshot(
    *,
    asset_map: DataHubAssetMap,
    transport_factory=StdioDataHubMcpTransport,
) -> DataHubSnapshot:
    """Acquire one governed snapshot through a read-only MCP session."""

    settings = read_only_settings_from_env()
    transport: DataHubMcpTransport = transport_factory(settings)
    async with transport as connected:
        client = RoleBoundDataHubMcpClient(connected, role=DataHubMcpRole.READ_ONLY)
        return await DataHubSnapshotLoader(client, asset_map).load(
            require_mutations=False,
        )


async def create_live_pipeline_async(
    *,
    asset_map: DataHubAssetMap | None = None,
    transport_factory=StdioDataHubMcpTransport,
    runtime_dir: Path | None = None,
) -> LiveRuntime:
    """Build the live runtime, failing rather than degrading to fixture governance.

    This is the form the server uses. The ASGI lifespan already runs inside an event loop, so
    the bootstrap snapshot must be awaited there rather than driven by ``asyncio.run``, which
    refuses to nest and would make every live startup fail for the wrong reason.
    """

    resolved_map = asset_map or DataHubAssetMap.from_path(
        os.getenv(ASSET_MAP_ENV, DEFAULT_ASSET_MAP)
    )
    max_age = _snapshot_max_age()

    async def loader() -> DataHubSnapshot:
        return await load_live_snapshot(
            asset_map=resolved_map,
            transport_factory=transport_factory,
        )

    try:
        bootstrap = await loader()
    except Exception as exc:
        raise ValueError(
            "live mode could not acquire a governed DataHub snapshot at startup"
        ) from exc

    resolver = DataHubSnapshotContextResolver(bootstrap, max_age_seconds=max_age)
    refresher = DataHubSnapshotRefresher(resolver=resolver, loader=loader)

    root = runtime_dir or Path(os.getenv("TOXICJOIN_RUNTIME_DIR", ".toxicjoin"))
    database = Path(os.getenv("TOXICJOIN_DATABASE", str(root / "warehouse.duckdb")))
    if not database.is_file():
        raise ValueError(
            f"live mode requires an existing warehouse database at {database}; "
            "load the governed tables before starting the server"
        )

    pipeline = ToxicJoinPipeline(
        context_resolver=resolver,
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(
            Path(os.getenv("TOXICJOIN_RECEIPT_DIR", str(root / "receipts")))
        ),
        mode=ReceiptMode.LIVE,
        executor=DuckDBExecutor(database),
        disclosure_ledger=DisclosureLedger(
            Path(
                os.getenv(
                    "TOXICJOIN_DISCLOSURE_LEDGER",
                    str(root / "disclosures.sqlite3"),
                )
            )
        ),
        include_sanitized_sql=False,
    )
    return LiveRuntime(
        pipeline=pipeline,
        refresher=refresher,
        snapshot=resolver.snapshot,
    )


def create_live_pipeline(
    *,
    asset_map: DataHubAssetMap | None = None,
    transport_factory=StdioDataHubMcpTransport,
    runtime_dir: Path | None = None,
) -> LiveRuntime:
    """Synchronous wrapper for callers that own no event loop (CLI, scripts, tests)."""

    return asyncio.run(
        create_live_pipeline_async(
            asset_map=asset_map,
            transport_factory=transport_factory,
            runtime_dir=runtime_dir,
        )
    )


def _snapshot_max_age() -> float:
    raw = os.getenv(SNAPSHOT_MAX_AGE_ENV)
    if raw is None:
        return 300.0
    try:
        return float(raw)
    except ValueError as exc:
        raise ValueError(f"{SNAPSHOT_MAX_AGE_ENV} must be numeric") from exc
