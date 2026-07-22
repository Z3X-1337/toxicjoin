"""Command-line entry points for ToxicJoin."""

from __future__ import annotations

import os

import uvicorn


def run_api() -> None:
    """Run the production-style FastAPI app with environment-configurable binding."""

    host = os.getenv("TOXICJOIN_HOST", "127.0.0.1")
    try:
        port = int(os.getenv("TOXICJOIN_PORT", "8000"))
    except ValueError as exc:
        raise SystemExit("TOXICJOIN_PORT must be an integer") from exc
    if not 1 <= port <= 65535:
        raise SystemExit("TOXICJOIN_PORT must be between 1 and 65535")

    uvicorn.run(
        "toxicjoin.api.app:app",
        host=host,
        port=port,
        reload=False,
        access_log=True,
    )
