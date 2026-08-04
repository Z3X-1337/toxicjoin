"""Live mode is selected by environment, so its guards must hold before startup.

`create_app` decides whether the surface is restricted, and that decision used to depend only
on an authenticator or an already-constructed LIVE pipeline. Live mode supplies neither: the
pipeline materializes during lifespan startup. Without recognizing the deferred case, a server
launched with `TOXICJOIN_MODE=live` and no credentials would compute as unrestricted and hand
the anonymous fixture identity every scope over real governed data.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from toxicjoin.api import create_app
from toxicjoin.api.live import (
    MODE_ENV,
    SNAPSHOT_MAX_AGE_ENV,
    create_live_pipeline,
    live_mode_requested,
)
from toxicjoin.auth import ApiKeyAuthenticator, ApiKeyCredentialConfig, AuthScope


VALID_KEY = "L" * 48


def _authenticator() -> ApiKeyAuthenticator:
    return ApiKeyAuthenticator(
        (
            ApiKeyCredentialConfig(
                credential_id="live-cred",
                api_key=VALID_KEY,
                principal_id="live-analyst",
                scopes=(AuthScope.SYSTEM_READ, AuthScope.ANALYZE, AuthScope.EXECUTE),
            ),
        )
    )


def test_live_mode_detection_is_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(MODE_ENV, raising=False)
    assert live_mode_requested() is False

    monkeypatch.setenv(MODE_ENV, "live")
    assert live_mode_requested() is True

    monkeypatch.setenv(MODE_ENV, "LIVE")
    assert live_mode_requested() is True

    monkeypatch.setenv(MODE_ENV, "fixture")
    assert live_mode_requested() is False


def test_live_mode_without_credentials_refuses_to_build(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(MODE_ENV, "live")
    monkeypatch.delenv("TOXICJOIN_API_KEYS_JSON", raising=False)

    with pytest.raises(ValueError, match="LIVE API requires configured authentication"):
        create_app()


def test_live_mode_surface_is_restricted_before_startup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Docs and the unauthenticated demo endpoints must be gone from the moment it builds."""

    monkeypatch.setenv(MODE_ENV, "live")
    app = create_app(authenticator=_authenticator())

    assert app.state.restricted_surface is True
    assert app.docs_url is None
    assert app.openapi_url is None
    paths = {getattr(route, "path", "") for route in app.routes}
    assert "/api/demo/scenarios" not in paths
    assert "/api/benchmark/summary" not in paths


def test_fixture_mode_remains_open_for_judges(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(MODE_ENV, raising=False)
    monkeypatch.delenv("TOXICJOIN_API_KEYS_JSON", raising=False)
    app = create_app()

    assert app.state.restricted_surface is False
    assert app.docs_url == "/docs"


def test_live_startup_fails_when_datahub_is_unreachable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A server that came up anyway would advertise governance it cannot supply."""

    monkeypatch.setenv("DATAHUB_GMS_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", "placeholder-token")
    monkeypatch.setenv("TOXICJOIN_RUNTIME_DIR", str(tmp_path))

    class _DeadTransport:
        def __init__(self, settings) -> None:
            del settings

        async def __aenter__(self):
            raise ConnectionError("gms unreachable")

        async def __aexit__(self, *_: object) -> None:
            return None

    with pytest.raises(ValueError, match="could not acquire a governed DataHub snapshot"):
        create_live_pipeline(transport_factory=_DeadTransport)


def test_live_startup_runs_inside_the_asgi_event_loop(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The bootstrap snapshot must be awaited, not driven by a nested ``asyncio.run``.

    A nested run raises `RuntimeError: asyncio.run() cannot be called from a running event
    loop`, which would make *every* live startup fail with an error that has nothing to do
    with DataHub — masking the real cause behind a plumbing bug.
    """

    monkeypatch.setenv(MODE_ENV, "live")
    monkeypatch.setenv("DATAHUB_GMS_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", "placeholder-token")
    monkeypatch.setenv("TOXICJOIN_RUNTIME_DIR", str(tmp_path))
    monkeypatch.delenv("TOXICJOIN_DATABASE", raising=False)

    app = create_app(authenticator=_authenticator())

    with pytest.raises(ValueError, match="could not acquire a governed DataHub snapshot"):
        with TestClient(app):
            pass  # pragma: no cover - startup must raise before the body runs


def test_live_mode_never_falls_back_to_fixture_governance(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Degrading to synthetic metadata would be the worst possible failure mode."""

    monkeypatch.setenv(MODE_ENV, "live")
    monkeypatch.setenv("DATAHUB_GMS_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", "placeholder-token")
    monkeypatch.setenv("TOXICJOIN_RUNTIME_DIR", str(tmp_path))
    monkeypatch.delenv("TOXICJOIN_DATABASE", raising=False)

    app = create_app(authenticator=_authenticator())
    with pytest.raises(ValueError):
        with TestClient(app):
            pass  # pragma: no cover

    # The failure must be terminal, not a downgrade: no pipeline was ever installed.
    assert getattr(app.state, "pipeline", None) is None


def test_snapshot_max_age_configuration_must_be_numeric(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(SNAPSHOT_MAX_AGE_ENV, "not-a-number")
    monkeypatch.setenv("DATAHUB_GMS_URL", "http://127.0.0.1:1")
    monkeypatch.setenv("DATAHUB_GMS_READ_TOKEN", "placeholder-token")

    with pytest.raises(ValueError, match="must be numeric"):
        create_live_pipeline()
