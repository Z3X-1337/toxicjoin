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

from toxicjoin.api.limits import (
    ApiResourceLimits,
    PrincipalTrafficLimiter,
    RequestBodyLimitMiddleware,
    ResponseBodyLimitMiddleware,
    TrafficLimitError,
)
from toxicjoin.api.models import (
    DemoScenarioList,
    HealthResponse,
    LivenessResponse,
    PipelineResponse,
)
from toxicjoin.api.scenarios import SCENARIOS
from toxicjoin.auth import (
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


def create_default_pipeline() -> ToxicJoinPipeline:
    """Create the zero-configuration deterministic fixture pipeline."""

    runtime_dir = Path(os.getenv("TOXICJOIN_RUNTIME_DIR", ".toxicjoin"))
    database = Path(
        os.getenv("TOXICJOIN_DATABASE", str(runtime_dir / "demo.duckdb"))
    )
    receipt_dir = Path(
        os.getenv("TOXICJOIN_RECEIPT_DIR", str(runtime_dir / "receipts"))
    )

    if not database.exists():
        seed_database(database)

    return ToxicJoinPipeline(
        context_resolver=FixtureContextResolver(default_fixture_catalog()),
        policy_engine=PolicyEngine(load_policy()),
        receipt_store=ReceiptStore(receipt_dir),
        mode=ReceiptMode.FIXTURE,
        executor=DuckDBExecutor(database),
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
    if (
        pipeline is not None
        and pipeline.mode == ReceiptMode.LIVE
        and resolved_authenticator is None
    ):
        raise ValueError("LIVE API requires configured authentication")

    restricted_surface = resolved_authenticator is not None or (
        pipeline is not None and pipeline.mode == ReceiptMode.LIVE
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
            application.state.pipeline = create_default_pipeline()
            yield

        application = FastAPI(lifespan=lifespan, **fastapi_kwargs)
    else:
        application = FastAPI(**fastapi_kwargs)
        application.state.pipeline = pipeline

    application.state.web_dist = resolved_web_dist if serve_judge_interface else None
    application.state.authenticator = resolved_authenticator
    application.state.resource_limits = resolved_limits
    application.state.traffic_limiter = resolved_traffic_limiter
    application.state.restricted_surface = restricted_surface
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
        with _traffic_slot(request, authenticated.identity.principal_id):
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
            ready = database_ready and receipt_store_ready
            if not ready:
                response.status_code = 503
            return HealthResponse(
                status="ok" if ready else "degraded",
                version=_package_version(),
                mode=services.mode,
                policy_version=services.policy_engine.config.version,
                database_ready=database_ready,
                receipt_store_ready=receipt_store_ready,
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
        with _traffic_slot(request, authenticated.identity.principal_id):
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
        with _traffic_slot(request, authenticated.identity.principal_id):
            result = _run_pipeline(
                request,
                payload,
                execute=True,
                identity=authenticated.identity,
            )
        return PipelineResponse.from_result(result)

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
        with _traffic_slot(request, authenticated.identity.principal_id):
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
    candidates: list[Path] = []
    if value is not None:
        candidates.append(Path(value))
    configured = os.getenv("TOXICJOIN_WEB_DIST")
    if configured:
        candidates.append(Path(configured))
    candidates.append(Path("apps/web/dist"))

    for candidate in candidates:
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


def _require_scope(request: Request, scope: AuthScope) -> AuthenticatedRequest:
    authenticator = getattr(request.app.state, "authenticator", None)
    if authenticator is None:
        if _pipeline(request).mode == ReceiptMode.LIVE:
            raise HTTPException(
                status_code=503,
                detail={"code": "AUTH_NOT_CONFIGURED"},
            )
        return fixture_anonymous_request()

    authorization = request.headers.get("authorization", "")
    scheme, separator, token = authorization.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token.strip():
        raise HTTPException(
            status_code=401,
            detail={"code": "AUTH_MISSING_BEARER"},
            headers={"WWW-Authenticate": "Bearer"},
        )

    session_id = request.headers.get("x-toxicjoin-session")
    try:
        return authenticator.require_scope(
            token.strip(),
            scope,
            session_id=session_id,
        )
    except AuthenticationError as exc:
        raise HTTPException(
            status_code=401,
            detail={"code": exc.code},
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    except AuthorizationError as exc:
        raise HTTPException(
            status_code=403,
            detail={"code": exc.code, "required_scope": scope.value},
        ) from exc


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
