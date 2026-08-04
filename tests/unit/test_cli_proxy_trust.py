"""The pre-auth failure limiter keys on request.client.host, so uvicorn's proxy-header
trust boundary must never be silent. See toxicjoin.cli._uvicorn_proxy_kwargs.
"""

from __future__ import annotations

from toxicjoin.cli import TRUSTED_PROXY_IPS_ENV, _uvicorn_proxy_kwargs


def test_default_is_no_proxy_trust() -> None:
    """With no operator opt-in, X-Forwarded-* must never be trusted."""

    assert _uvicorn_proxy_kwargs({}) == {"proxy_headers": False}


def test_blank_value_is_treated_as_unset() -> None:
    assert _uvicorn_proxy_kwargs({TRUSTED_PROXY_IPS_ENV: "   "}) == {"proxy_headers": False}


def test_explicit_opt_in_trusts_only_the_configured_hops() -> None:
    environ = {TRUSTED_PROXY_IPS_ENV: "10.0.0.0/8,172.16.0.5"}

    assert _uvicorn_proxy_kwargs(environ) == {
        "proxy_headers": True,
        "forwarded_allow_ips": "10.0.0.0/8,172.16.0.5",
    }


def test_real_os_environ_is_used_when_no_mapping_given(monkeypatch) -> None:
    monkeypatch.delenv(TRUSTED_PROXY_IPS_ENV, raising=False)
    assert _uvicorn_proxy_kwargs() == {"proxy_headers": False}

    monkeypatch.setenv(TRUSTED_PROXY_IPS_ENV, "127.0.0.1")
    assert _uvicorn_proxy_kwargs() == {
        "proxy_headers": True,
        "forwarded_allow_ips": "127.0.0.1",
    }
