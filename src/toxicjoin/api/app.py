"""FastAPI application for the ToxicJoin safety pipeline and judge interface."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager, contextmanager
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Annotated, Any, Iterator

from fastapi import FastAPI, HTTPException, Path as ApiPath, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from toxicjoin.api.live import create_live_pipeline_async, live_mode_requested
from toxicjoin.api.limits import (
    ApiResourceLimits,
    AuthFailureLimiter,
    PrincipalTrafficLimiter,
    RequestBodyLimitMiddleware,
    ResponseBodyLimitMiddleware,
    TrafficLimitError,
)
from toxicjoin.agent.governed import AgentProposalError
from toxicjoin.agent.runtime import AgentSessionResult, GovernedAgentSession
from toxicjoin.api.models import (
    AgentRunRequest,
    DemoScenarioList,
    HealthResponse,
    LivenessResponse,
    PipelineResponse,
)
from toxicjoin.api.scenarios import SCENARIOS
from toxicjoin.auth import (
    FIXTURE_ANONYMOUS_PRINCIPAL,
    ApiKeyAuthenticator,
    AuthScope,
    AuthenticatedRequest,
    AuthenticationError,
    AuthorizationError,
    RequestIdentity,
    bind_request_identity,
    fixture_anonymous_request,
)
from toxicjoin.benchmark.evidence import BENCHMARK_EVIDENCE, BenchmarkEvidenceSummary
from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog, seed_database
from toxicjoin.disclosure import DisclosureLedger
from toxicjoin.execute import DuckDBExecutor
from toxicjoin.pipeline import PipelineRequest, ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import DecisionReceipt, ReceiptMode, ReceiptStore


_CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'self'",
        "base-uri 'none'",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "form-action 'none'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "font-src 'self' data:",
        "connect-src 'self'",
    )
)
_RESERVED_SPA_PREFIXES = ("api/", "docs", "redoc")
_ALLOWED_HOSTS_ENV = "TOXICJOIN_ALLOWED_HOSTS"
_DEFAULT_SECURE_ALLOWED_HOSTS = ("localhost", "127.0.0.1", "testserver")
_HSTS_VALUE = "max-age=31536000; includeSubDomains"


def create_default_pipeline(
    *,
    stateful_privacy_required: bool = False,
) -> ToxicJoinPipeline:
    """Create the zero-configuration deterministic fixture pipeline."""

    runtime_dir = Path(os.getenv("TOXICJOIN_RUNTIME_DIR", ".toxicjoin"))
    database = Path(
        os.getenv("TOXICJOIN_DATABASE", str(runtime_dir / "demo.duckdb"))
    )
    receipt_dir = Path(
        os.getenv("TOXICJOIN_RECEIPT_DIR", str(runtime_dir / "receipts"))
    )
    disclosure_path = Path(
        os.getenv(
            "TOXICJOIN_DISCLOSURE_LEDGER",
            str(runtime_dir / "disclosures.sqlite3"),
        )
    )

    if not database.exists():
        seed_database(database)

    return ToxicJoinPipeline(
        context_resolver=FixtureContextResolver(default_fixture_catalog()),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(receipt_dir),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(database),
        disclosure_ledger=DisclosureLedger(disclosure_path),
        stateful_privacy_required=stateful_privacy_required,
        include_sanitized_sql=True,
    )


def create_app(
    pipeline: ToxicJoinPipeline | None = None,
    *,
    web_dist: str | Path | None = None,
    authenticator: ApiKeyAuthenticator | None = None,
    resource_limits: ApiResourceLimits | None = None,
    traffic_limiter: PrincipalTrafficLimiter | None = None,
) -> FastAPI:
    """Build the API and optionally serve a prebuilt judge interface."""

    resolved_web_dist = _resolve_web_dist(web_dist)
    resolved_authenticator = (
        authenticator
        if authenticator is not None
        else ApiKeyAuthenticator.from_environment()
    )
    resolved_limits = resource_limits or ApiResourceLimits.from_environment()
    resolved_traffic_limiter = traffic_limiter or PrincipalTrafficLimiter(
        resolved_limits
    )
    # Live mode is decided by environment and only materializes during lifespan startup, so
    # it has to be recognized here too. Without this the surface would compute as
    # unrestricted, exposing docs and granting the anonymous fixture identity every scope
    # against real governed data.
    deferred_live = pipeline is None and live_mode_requested()
    if (
        (pipeline is not None and pipeline.mode == ReceiptMode.LIVE) or deferred_live
    ) and resolved_authenticator is None:
        raise ValueError("LIVE API requires configured authentication")

    restricted_surface = (
        resolved_authenticator is not None
        or deferred_live
        or (pipeline is not None and pipeline.mode == ReceiptMode.LIVE)
    )
    if pipeline is not None and restricted_surface:
        if pipeline.disclosure_ledger is None or not pipeline.stateful_privacy_required:
            raise ValueError(
                "restricted API requires an enabled stateful privacy disclosure ledger"
            )

    serve_judge_interface = resolved_web_dist is not None and not restricted_surface
    fastapi_kwargs = {
        "title": "ToxicJoin",
        "version": _package_version(),
        "description": (
            "Compositional privacy firewall for AI data agents. The default "
            "deployment is explicitly labeled fixture mode."
            if pipeline is None
            else "Compositional privacy firewall for AI data agents."
        ),
        "docs_url": None if restricted_surface else "/docs",
        "redoc_url": None if restricted_surface else "/redoc",
        "openapi_url": None if restricted_surface else "/openapi.json",
    }

    if pipeline is None:

        @asynccontextmanager
        async def lifespan(application: FastAPI):
            if live_mode_requested():
                # Startup raises if DataHub is unreachable. A server that came up anyway
                # would be advertising live governance it cannot supply.
                runtime = await create_live_pipeline_async()
                application.state.pipeline = runtime.pipeline
                application.state.snapshot_refresher = runtime.refresher
                runtime.refresher.start()
                try:
                    yield
                finally:
                    runtime.refresher.stop()
                return

            application.state.pipeline = create_default_pipeline(
                stateful_privacy_required=restricted_surface
            )
            yield

        application = FastAPI(lifespan=lifespan, **fastapi_kwargs)
    else:
        application = FastAPI(**fastapi_kwargs)
        application.state.pipeline = pipeline

    application.state.web_dist = resolved_web_dist if serve_judge_interface else None
    application.state.authenticator = resolved_authenticator
    application.state.resource_limits = resolved_limits
    application.state.traffic_limiter = resolved_traffic_limiter
    application.state.auth_failure_limiter = AuthFailureLimiter(
        max_failures=resolved_limits.auth_failure_limit,
        window_seconds=resolved_limits.auth_failure_window_seconds,
    )
    application.state.restricted_surface = restricted_surface
    application.state.snapshot_refresher = None
    application.add_middleware(
        RequestBodyLimitMiddleware,
        max_bytes=resolved_limits.max_request_bytes,
    )
    application.add_middleware(
        ResponseBodyLimitMiddleware,
        max_bytes=resolved_limits.max_response_bytes,
    )
    if restricted_surface:
        application.add_middleware(
            TrustedHostMiddleware,
            allowed_hosts=list(_secure_allowed_hosts()),
        )

    @application.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        response.headers.setdefault("Content-Security-Policy", _CONTENT_SECURITY_POLICY)
        response.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=()",
        )
        if request.url.scheme == "https":
            response.headers.setdefault("Strict-Transport-Security", _HSTS_VALUE)
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, max-age=0"
            response.headers["Pragma"] = "no-cache"
        elif request.url.path.startswith("/assets/"):
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        else:
            response.headers["Cache-Control"] = "no-cache, max-age=0"
        return response

    @application.get("/api/health", response_model=LivenessResponse)
    def health() -> LivenessResponse:
        return LivenessResponse()

    @application.get("/api/ready", response_model=HealthResponse)
    def readiness(request: Request, response: Response) -> HealthResponse:
        authenticated = _require_scope(request, AuthScope.SYSTEM_READ)
        with _traffic_slot(request, _traffic_principal(request, authenticated)):
            services = _pipeline(request)
            database_ready = (
                services.executor is not None
                and services.executor.database.is_file()
            )
            receipt_root = services.receipt_store.root
            receipt_parent = receipt_root if receipt_root.exists() else receipt_root.parent
            receipt_store_ready = receipt_parent.exists() and os.access(
                receipt_parent,
                os.W_OK,
            )
            privacy_ready = not services.stateful_privacy_required or (
                services.disclosure_ledger is not None
                and services.disclosure_ledger.path.is_file()
                and services.disclosure_ledger.cohort_key_path.is_file()
            )
            freshness_check = getattr(services.context_resolver, "is_fresh", None)
            snapshot_fresh = callable(freshness_check) and bool(freshness_check())
            # A live deployment whose refresher has died is not ready even while the current
            # snapshot is still inside its window: it is minutes away from refusing
            # everything, and that must surface before it happens rather than after.
            refresher = getattr(request.app.state, "snapshot_refresher", None)
            refresher_ready = refresher is None or refresher.health().running
            governance_ready = services.mode != ReceiptMode.LIVE or (
                snapshot_fresh and refresher_ready
            )
            ready = (
                database_ready
                and receipt_store_ready
                and privacy_ready
                and governance_ready
            )
            if not ready:
                response.status_code = 503
            return HealthResponse(
                status="ok" if ready else "degraded",
                version=_package_version(),
                mode=services.mode,
                policy_version=services.policy_engine.config.version,
                database_ready=database_ready,
                receipt_store_ready=receipt_store_ready,
                governance_ready=governance_ready,
            )

    if not restricted_surface:

        @application.get(
            "/api/benchmark/summary",
            response_model=BenchmarkEvidenceSummary,
        )
        def benchmark_summary() -> BenchmarkEvidenceSummary:
            return BENCHMARK_EVIDENCE

        @application.get("/api/demo/scenarios", response_model=DemoScenarioList)
        def demo_scenarios() -> DemoScenarioList:
            return DemoScenarioList(scenarios=SCENARIOS)

    @application.post("/api/analyze", response_model=PipelineResponse)
    def analyze(payload: PipelineRequest, request: Request) -> PipelineResponse:
        authenticated = _require_scope(request, AuthScope.ANALYZE)
        with _traffic_slot(request, _traffic_principal(request, authenticated)):
            result = _run_pipeline(
                request,
                payload,
                execute=False,
                identity=authenticated.identity,
            )
        return PipelineResponse.from_result(result)

    @application.post("/api/execute-safe", response_model=PipelineResponse)
    def execute_safe(payload: PipelineRequest, request: Request) -> PipelineResponse:
        authenticated = _require_scope(request, AuthScope.EXECUTE)
        with _traffic_slot(request, _traffic_principal(request, authenticated)):
            result = _run_pipeline(
                request,
                payload,
                execute=True,
                identity=authenticated.identity,
            )
        return PipelineResponse.from_result(result)

    @application.post("/api/agent/run", response_model=AgentSessionResult)
    def agent_run(payload: AgentRunRequest, request: Request) -> AgentSessionResult:
        """Let the Governed Agent attempt a goal under the firewall.

        The agent proposes; ToxicJoin decides. Every attempt runs the full pipeline, so a
        refusal here is the same refusal `/api/execute-safe` would give, and the agent only
        ever sees a deterministic reason code to adapt from.
        """

        scope = AuthScope.EXECUTE if payload.execute else AuthScope.ANALYZE
        authenticated = _require_scope(request, scope)
        with _traffic_slot(request, _traffic_principal(request, authenticated)):
            pipeline = _pipeline(request)
            resolver = pipeline.context_resolver
            catalog = getattr(resolver, "catalog", None)
            if catalog is None:
                raise HTTPException(
                    status_code=503,
                    detail={"code": "AGENT_CONTEXT_UNAVAILABLE"},
                )
            try:
                with bind_request_identity(authenticated.identity):
                    session = GovernedAgentSession(pipeline=pipeline, catalog=catalog)
                    return session.run(
                        goal=payload.goal,
                        subject_key=payload.subject_key,
                        execute=payload.execute,
                    )
            except AgentProposalError as exc:
                raise HTTPException(
                    status_code=422,
                    detail={"code": exc.code},
                ) from exc
            except Exception as exc:
                raise HTTPException(
                    status_code=503,
                    detail={"code": "AGENT_SESSION_FAILURE"},
                ) from exc

    @application.get(
        "/api/receipts/{receipt_id}",
        response_model=DecisionReceipt,
    )
    def get_receipt(
        receipt_id: Annotated[
            str,
            ApiPath(pattern=r"^tj_[0-9a-f]{16}$"),
        ],
        request: Request,
    ) -> DecisionReceipt:
        authenticated = _require_scope(request, AuthScope.RECEIPTS_READ)
        with _traffic_slot(request, _traffic_principal(request, authenticated)):
            try:
                receipt = _pipeline(request).receipt_store.read(receipt_id)
            except FileNotFoundError as exc:
                raise HTTPException(
                    status_code=404,
                    detail={"code": "RECEIPT_NOT_FOUND"},
                ) from exc
            except ValueError as exc:
                raise HTTPException(
                    status_code=409,
                    detail={"code": "RECEIPT_INTEGRITY_FAILURE"},
                ) from exc

            if not _receipt_visible_to(receipt, authenticated, request=request):
                raise HTTPException(
                    status_code=404,
                    detail={"code": "RECEIPT_NOT_FOUND"},
                )
            return receipt

    if serve_judge_interface:
        assert resolved_web_dist is not None
        assets = resolved_web_dist / "assets"
        if assets.is_dir():
            application.mount(
                "/assets",
                StaticFiles(directory=assets, check_dir=True),
                name="judge-assets",
            )

        @application.get("/", include_in_schema=False)
        def judge_interface() -> FileResponse:
            return FileResponse(resolved_web_dist / "index.html")

        @application.get("/{path:path}", include_in_schema=False)
        def spa_fallback(path: str) -> FileResponse:
            normalized = path.lstrip("/")
            if normalized == "openapi.json" or normalized.startswith(
                _RESERVED_SPA_PREFIXES
            ):
                raise HTTPException(status_code=404, detail={"code": "NOT_FOUND"})
            if Path(normalized).suffix:
                raise HTTPException(status_code=404, detail={"code": "ASSET_NOT_FOUND"})
            return FileResponse(resolved_web_dist / "index.html")

    else:

        @application.get("/", include_in_schema=False)
        def service_root() -> JSONResponse:
            payload: dict[str, Any] = {"name": "ToxicJoin"}
            if not restricted_surface:
                payload.update(
                    {
                        "version": _package_version(),
                        "judge_interface": "not_built",
                        "api_docs": "/docs",
                    }
                )
            return JSONResponse(payload)

    return application


def _secure_allowed_hosts() -> tuple[str, ...]:
    configured = os.getenv(_ALLOWED_HOSTS_ENV)
    if configured is None:
        return _DEFAULT_SECURE_ALLOWED_HOSTS
    hosts = tuple(item.strip() for item in configured.split(",") if item.strip())
    if not hosts:
        raise ValueError(f"{_ALLOWED_HOSTS_ENV} must contain at least one host")
    if len(hosts) > 32:
        raise ValueError(f"{_ALLOWED_HOSTS_ENV} contains too many hosts")
    for host in hosts:
        if host == "*":
            raise ValueError(f"{_ALLOWED_HOSTS_ENV} cannot contain wildcard '*'")
        if "://" in host or "/" in host or any(character.isspace() for character in host):
            raise ValueError(f"invalid host pattern in {_ALLOWED_HOSTS_ENV}")
    return tuple(dict.fromkeys(hosts))


def _resolve_web_dist(value: str | Path | None) -> Path | None:
    """Resolve the judge interface directory from the most explicit source only.

    Explicit configuration is authoritative. Falling through from a configured-but-missing
    directory to a repository-relative probe would let a typo or a half-finished deploy
    silently serve a different, possibly stale build than the operator asked for, so only the
    unconfigured case consults the development default.
    """

    configured_env = os.getenv("TOXICJOIN_WEB_DIST")
    if value is not None:
        candidate = Path(value)
    elif configured_env:
        candidate = Path(configured_env)
    else:
        candidate = Path("apps/web/dist")

    resolved = candidate.expanduser().resolve()
    if resolved.is_dir() and (resolved / "index.html").is_file():
        return resolved
    return None


def _pipeline(request: Request) -> ToxicJoinPipeline:
    pipeline = getattr(request.app.state, "pipeline", None)
    if pipeline is None:
        raise HTTPException(
            status_code=503,
            detail={"code": "PIPELINE_NOT_READY"},
        )
    return pipeline


_UNAUTHENTICATED_PRINCIPAL_PREFIX = "unauthenticated:"


def _unauthenticated_principal(request: Request) -> str:
    """Derive a pre-authentication limiter key from the peer address.

    The per-principal limiter cannot key on an identity that does not exist yet, so before
    this change every rejected credential was unmetered and an attacker could probe keys as
    fast as the network allowed. The peer address is spoofable behind a proxy and is not used
    for any authorization decision; it exists only to give failed attempts a cost.
    """

    client = request.client
    host = client.host if client is not None else "unknown"
    return f"{_UNAUTHENTICATED_PRINCIPAL_PREFIX}{host}"


def _require_scope(request: Request, scope: AuthScope) -> AuthenticatedRequest:
    authenticator = getattr(request.app.state, "authenticator", None)
    if authenticator is None:
        if _pipeline(request).mode == ReceiptMode.LIVE:
            raise HTTPException(
                status_code=503,
                detail={"code": "AUTH_NOT_CONFIGURED"},
            )
        return fixture_anonymous_request()

    failure_limiter = getattr(request.app.state, "auth_failure_limiter", None)
    peer = _unauthenticated_principal(request)
    if failure_limiter is not None:
        try:
            failure_limiter.check(peer)
        except TrafficLimitError as exc:
            raise HTTPException(
                status_code=429,
                detail={"code": exc.code},
                headers={"Retry-After": str(exc.retry_after_seconds)},
            ) from exc

    def reject(status_code: int, detail: dict[str, object], headers: dict[str, str] | None):
        if failure_limiter is not None:
            failure_limiter.record_failure(peer)
        return HTTPException(status_code=status_code, detail=detail, headers=headers)

    authorization = request.headers.get("authorization", "")
    scheme, separator, token = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token.strip():
        raise reject(
            401,
            {"code": "AUTH_MISSING_BEARER"},
            {"WWW-Authenticate": "Bearer"},
        )

    session_id = request.headers.get("x-toxicjoin-session")
    try:
        return authenticator.require_scope(
            token.strip(),
            scope,
            session_id=session_id,
        )
    except AuthenticationError as exc:
        raise reject(401, {"code": exc.code}, {"WWW-Authenticate": "Bearer"}) from exc
    except AuthorizationError as exc:
        raise reject(
            403,
            {"code": exc.code, "required_scope": scope.value},
            None,
        ) from exc


def _traffic_principal(request: Request, authenticated: AuthenticatedRequest) -> str:
    """Return the key traffic budgets are accounted against.

    Authenticated callers are metered by their real principal. The unauthenticated fixture
    surface deliberately shares one *identity* so receipts and disclosure history stay
    unpartitioned — but metering every visitor against that single key would give the entire
    public demo two concurrent requests and sixty per minute in total, so two reviewers
    clicking at once would rate-limit each other. Traffic is therefore keyed per peer while
    the identity stays shared.
    """

    principal = authenticated.identity.principal_id
    if principal != FIXTURE_ANONYMOUS_PRINCIPAL:
        return principal
    client = request.client
    return f"{principal}@{client.host if client is not None else 'unknown'}"


@contextmanager
def _traffic_slot(request: Request, principal_id: str) -> Iterator[None]:
    limiter = getattr(request.app.state, "traffic_limiter", None)
    if limiter is None:
        raise HTTPException(
            status_code=503,
            detail={"code": "TRAFFIC_LIMITER_NOT_READY"},
        )
    try:
        with limiter.acquire(principal_id):
            yield
    except TrafficLimitError as exc:
        raise HTTPException(
            status_code=429,
            detail={"code": exc.code},
            headers={"Retry-After": str(exc.retry_after_seconds)},
        ) from exc


def _receipt_visible_to(
    receipt: DecisionReceipt,
    authenticated: AuthenticatedRequest,
    *,
    request: Request,
) -> bool:
    if receipt.identity is None:
        return getattr(request.app.state, "authenticator", None) is None
    return receipt.identity.principal_id == authenticated.identity.principal_id


def _run_pipeline(
    request: Request,
    payload: PipelineRequest,
    *,
    execute: bool,
    identity: RequestIdentity,
) -> Any:
    pipeline = _pipeline(request)
    try:
        with bind_request_identity(identity):
            return pipeline.execute_safe(payload) if execute else pipeline.analyze(payload)
    except Exception as exc:
        # Stable public error only. Internal exception types/messages remain server-side.
        raise HTTPException(
            status_code=503,
            detail={"code": "PIPELINE_PERSISTENCE_FAILURE"},
        ) from exc


def _package_version() -> str:
    try:
        return version("toxicjoin")
    except PackageNotFoundError:
        return "0.1.0"


app = create_app()
