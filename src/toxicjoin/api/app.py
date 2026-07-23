"""FastAPI application for the ToxicJoin safety pipeline and judge interface."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Annotated, Any

from fastapi import FastAPI, HTTPException, Path as ApiPath, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from toxicjoin.api.models import (
    DemoScenarioList,
    HealthResponse,
    PipelineResponse,
)
from toxicjoin.api.scenarios import SCENARIOS
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
        "script-src 'self' https://cdn.jsdelivr.net",
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
        "img-src 'self' data:",
        "font-src 'self' data:",
        "connect-src 'self'",
    )
)
_RESERVED_SPA_PREFIXES = ("api/", "docs", "redoc")


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
) -> FastAPI:
    """Build the API and optionally serve a prebuilt judge interface."""

    resolved_web_dist = _resolve_web_dist(web_dist)
    if pipeline is None:

        @asynccontextmanager
        async def lifespan(application: FastAPI):
            application.state.pipeline = create_default_pipeline()
            yield

        application = FastAPI(
            title="ToxicJoin",
            version=_package_version(),
            description=(
                "Compositional privacy firewall for AI data agents. The default "
                "deployment is explicitly labeled fixture mode."
            ),
            lifespan=lifespan,
        )
    else:
        application = FastAPI(
            title="ToxicJoin",
            version=_package_version(),
            description="Compositional privacy firewall for AI data agents.",
        )
        application.state.pipeline = pipeline

    application.state.web_dist = resolved_web_dist

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
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, max-age=0"
            response.headers["Pragma"] = "no-cache"
        elif request.url.path.startswith("/assets/"):
            response.headers["Cache-Control"] = "public, max-age=31536000, immutable"
        else:
            response.headers["Cache-Control"] = "no-cache, max-age=0"
        return response

    @application.get("/api/health", response_model=HealthResponse)
    def health(request: Request) -> HealthResponse:
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
        return HealthResponse(
            status="ok" if database_ready and receipt_store_ready else "degraded",
            version=_package_version(),
            mode=services.mode,
            policy_version=services.policy_engine.config.version,
            database_ready=database_ready,
            receipt_store_ready=receipt_store_ready,
        )

    @application.get(
        "/api/benchmark/summary",
        response_model=BenchmarkEvidenceSummary,
    )
    def benchmark_summary() -> BenchmarkEvidenceSummary:
        return BENCHMARK_EVIDENCE

    @application.post("/api/analyze", response_model=PipelineResponse)
    def analyze(payload: PipelineRequest, request: Request) -> PipelineResponse:
        result = _run_pipeline(request, payload, execute=False)
        return PipelineResponse.from_result(result)

    @application.post("/api/execute-safe", response_model=PipelineResponse)
    def execute_safe(payload: PipelineRequest, request: Request) -> PipelineResponse:
        result = _run_pipeline(request, payload, execute=True)
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
        try:
            return _pipeline(request).receipt_store.read(receipt_id)
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

    @application.get("/api/demo/scenarios", response_model=DemoScenarioList)
    def demo_scenarios() -> DemoScenarioList:
        return DemoScenarioList(scenarios=SCENARIOS)

    if resolved_web_dist is not None:
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
            return JSONResponse(
                {
                    "name": "ToxicJoin",
                    "version": _package_version(),
                    "judge_interface": "not_built",
                    "api_docs": "/docs",
                }
            )

    return application


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


def _run_pipeline(
    request: Request,
    payload: PipelineRequest,
    *,
    execute: bool,
) -> Any:
    pipeline = _pipeline(request)
    try:
        return pipeline.execute_safe(payload) if execute else pipeline.analyze(payload)
    except Exception as exc:
        # Do not expose paths, SQL, credentials, or exception messages through the API.
        raise HTTPException(
            status_code=503,
            detail={
                "code": "PIPELINE_PERSISTENCE_FAILURE",
                "error_type": type(exc).__name__,
            },
        ) from exc


def _package_version() -> str:
    try:
        return version("toxicjoin")
    except PackageNotFoundError:
        return "0.1.0"


app = create_app()
