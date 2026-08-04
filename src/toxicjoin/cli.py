"""Command-line entry points for ToxicJoin."""

from __future__ import annotations

import os
from collections.abc import Mapping

import uvicorn

TRUSTED_PROXY_IPS_ENV = "TOXICJOIN_TRUSTED_PROXY_IPS"


def _uvicorn_proxy_kwargs(environ: Mapping[str, str] | None = None) -> dict[str, object]:
    """Resolve how much to trust X-Forwarded-* headers from an upstream proxy.

    uvicorn's own default (proxy_headers=True, forwarded_allow_ips="127.0.0.1") is silent
    and easy to miss. request.client.host feeds the pre-auth failure limiter's key
    (api/app.py:_unauthenticated_principal) directly; if that value is ever trusted from
    an unverified hop, distinct callers behind the same untrusted proxy collapse onto one
    limiter key (CWE-346, a shared-budget denial of service) or, if a proxy is trusted but
    forwards a caller-supplied header verbatim, an attacker can mint a fresh key per
    request and the failure throttle stops throttling (CWE-290). Trust nothing by default;
    an operator who sits behind a known proxy chain opts in explicitly.
    """

    source: Mapping[str, str] = os.environ if environ is None else environ
    trusted = source.get(TRUSTED_PROXY_IPS_ENV, "").strip()
    if not trusted:
        return {"proxy_headers": False}
    return {"proxy_headers": True, "forwarded_allow_ips": trusted}


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
        **_uvicorn_proxy_kwargs(),
    )
