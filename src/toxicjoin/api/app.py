"""FastAPI application for the ToxicJoin safety pipeline."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, HTTPException, Path as ApiPath, Request

from toxicjoin.api.models import (
    DemoScenarioList,
    HealthResponse,
    PipelineResponse,
)
from toxicjoin.api.scenarios import SCENARIOS
from toxicjoin.context import FixtureContextResolver
from toxicjoin.demo import default_fixture_catalog, seed_database
from toxicjoin.execute import DuckDBExecutor
from toxicjoin.pipeline import PipelineRequest, ToxicJoinPipeline
from toxicjoin.policy import PolicyEngine, load_policy
from toxicjoin.receipts import DecisionReceipt, ReceiptMode, ReceiptStore


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


def create_app(pipeline: ToxicJoinPipeline | None = None) -> FastAPI:
    """Build the API with an injected pipeline or a lazy default fixture pipeline."""

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

    return application


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
):
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
