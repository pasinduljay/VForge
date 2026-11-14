"""Dedicated TLS 1.3 + mutual-TLS ASGI gateway for Runner Agent endpoints (/api/v1/runner/*)."""

from __future__ import annotations

import asyncio
import logging
import os
import ssl
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

import uvicorn
from fastapi import Depends, FastAPI, Request, Response, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from uvicorn.protocols.http.h11_impl import H11Protocol

from vforge import __version__
from vforge.config import Settings, get_settings
from vforge.db import (
    build_engine,
    build_session_factory,
    set_db_context,
    verify_runtime_db_identity,
)
from vforge.errors import ForbiddenError, VForgeError
from vforge.logging import configure_logging
from vforge.models.runner import Runner
from vforge.schemas import (
    RunnerArtifactOut,
    RunnerArtifactUploadRequest,
    RunnerEventCreate,
    RunnerEventOut,
    RunnerHeartbeatOut,
    RunnerHeartbeatRequest,
    RunnerJobClaimOut,
    RunnerJobClaimRequest,
    RunnerJobCompleteOut,
    RunnerJobCompleteRequest,
    RunnerJobTargetAuthOut,
    TargetHealthProbeCreate,
    TargetHealthProbeOut,
)
from vforge.security.mtls import RunnerCertClaims, verify_runner_cert_der
from vforge.services.runners import (
    authenticate_mtls_runner,
    claim_next_runner_job,
    complete_runner_job,
    get_runner_job_openapi_spec,
    get_runner_job_sbom_input,
    get_runner_job_source_snapshot,
    get_runner_job_target_auth,
    record_runner_event,
    record_runner_heartbeat,
    record_target_health_probe,
    upload_runner_artifact,
)

logger = logging.getLogger("vforge.runner_gateway")


class MtlsH11Protocol(H11Protocol):
    """Inject OpenSSL-verified TLS client certificate DER directly into ASGI extensions."""

    def connection_made(self, transport: asyncio.Transport) -> None:  # type: ignore[override]
        super().connection_made(transport)
        ssl_object = transport.get_extra_info("ssl_object")
        peer_der = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
        base_app = self.app

        async def _with_mtls_scope(scope: Any, receive: Any, send: Any) -> None:
            if peer_der:
                scope.setdefault("extensions", {})["vforge.mtls_peer_der"] = peer_der
            await base_app(scope, receive, send)

        self.app = _with_mtls_scope


@dataclass
class MtlsRunnerContext:
    runner: Runner
    claims: RunnerCertClaims
    db: AsyncSession


async def get_authenticated_runner(request: Request) -> AsyncIterator[MtlsRunnerContext]:
    """Fail-closed dependency extracting and authenticating the mTLS peer certificate."""
    extensions = request.scope.get("extensions") or {}
    peer_der = extensions.get("vforge.mtls_peer_der")
    if not isinstance(peer_der, (bytes, bytearray)) or not peer_der:
        raise ForbiddenError("Mutual TLS client certificate is required")

    try:
        claims = verify_runner_cert_der(bytes(peer_der))
    except ValueError as exc:
        raise ForbiddenError(str(exc)) from exc

    session_factory = request.app.state.session_factory
    if session_factory is None:
        raise ForbiddenError("Runner gateway database session unavailable")

    async with session_factory() as session:
        async with session.begin():
            await set_db_context(
                session,
                org_id=claims.organization_id,
            )
            runner = await authenticate_mtls_runner(session, claims=claims)
            yield MtlsRunnerContext(runner=runner, claims=claims, db=session)


@asynccontextmanager
async def _gateway_lifespan(application: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    configure_logging(settings.log_level)
    settings.validate_startup_configuration()
    db_url = settings.effective_database_url
    engine = build_engine(db_url) if db_url else None
    if engine is not None:
        identity = await verify_runtime_db_identity(engine)
        logger.info("runner_gateway_verified_db role=%s", identity["role"])
    application.state.engine = engine
    application.state.session_factory = build_session_factory(engine) if engine else None
    try:
        yield
    finally:
        if engine is not None:
            await engine.dispose()


def create_runner_gateway_app(*, with_lifespan: bool = True) -> FastAPI:
    """Create dedicated mTLS-only FastAPI application serving /api/v1/runner/*."""
    application = FastAPI(
        title="VForge mTLS Runner Gateway",
        version=__version__,
        description="Dedicated mutually-authenticated control endpoint for isolated runners.",
        lifespan=_gateway_lifespan if with_lifespan else None,
    )

    @application.exception_handler(VForgeError)
    async def _handle_vf_error(_request: Request, exc: VForgeError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})

    @application.get("/health", status_code=status.HTTP_200_OK)
    def gateway_health() -> dict[str, str]:
        return {"status": "ok", "service": "vforge-runner-gateway"}

    @application.post("/api/v1/runner/jobs/claim", response_model=RunnerJobClaimOut)
    async def claim_job_route(
        payload: RunnerJobClaimRequest,
        ctx: MtlsRunnerContext = Depends(get_authenticated_runner),  # noqa: B008
        settings: Settings = Depends(get_settings),  # noqa: B008
    ) -> RunnerJobClaimOut:
        return await claim_next_runner_job(
            ctx.db,
            runner=ctx.runner,
            payload=payload,
            settings=settings,
        )

    @application.post(
        "/api/v1/runner/jobs/{job_id}/heartbeat",
        response_model=RunnerHeartbeatOut,
    )
    async def heartbeat_route(
        job_id: uuid.UUID,
        payload: RunnerHeartbeatRequest,
        ctx: MtlsRunnerContext = Depends(get_authenticated_runner),  # noqa: B008
    ) -> RunnerHeartbeatOut:
        return await record_runner_heartbeat(
            ctx.db,
            runner=ctx.runner,
            job_id=job_id,
            payload=payload,
        )

    @application.post(
        "/api/v1/runner/jobs/{job_id}/events",
        response_model=RunnerEventOut,
        status_code=status.HTTP_201_CREATED,
    )
    async def event_route(
        job_id: uuid.UUID,
        payload: RunnerEventCreate,
        ctx: MtlsRunnerContext = Depends(get_authenticated_runner),  # noqa: B008
    ) -> RunnerEventOut:
        event = await record_runner_event(
            ctx.db,
            runner=ctx.runner,
            job_id=job_id,
            payload=payload,
        )
        return RunnerEventOut.model_validate(event)

    @application.post(
        "/api/v1/runner/jobs/{job_id}/artifacts",
        response_model=RunnerArtifactOut,
        status_code=status.HTTP_201_CREATED,
    )
    async def upload_artifact_route(
        job_id: uuid.UUID,
        payload: RunnerArtifactUploadRequest,
        ctx: MtlsRunnerContext = Depends(get_authenticated_runner),  # noqa: B008
        settings: Settings = Depends(get_settings),  # noqa: B008
    ) -> RunnerArtifactOut:
        artifact = await upload_runner_artifact(
            ctx.db,
            runner=ctx.runner,
            job_id=job_id,
            payload=payload,
            settings=settings,
        )
        return RunnerArtifactOut.model_validate(artifact)

    @application.get("/api/v1/runner/jobs/{job_id}/source-snapshot")
    async def get_source_snapshot_route(
        job_id: uuid.UUID,
        ctx: MtlsRunnerContext = Depends(get_authenticated_runner),  # noqa: B008
        settings: Settings = Depends(get_settings),  # noqa: B008
    ) -> Response:
        snap, archive_bytes = await get_runner_job_source_snapshot(
            ctx.db,
            runner=ctx.runner,
            job_id=job_id,
            settings=settings,
        )
        return Response(
            content=archive_bytes,
            media_type="application/gzip",
            headers={
                "X-Source-Snapshot-Id": str(snap.id),
                "X-Source-Snapshot-Sha256": snap.archive_sha256,
            },
        )

    @application.get("/api/v1/runner/jobs/{job_id}/sbom-input")
    async def download_sbom_input_route(
        job_id: uuid.UUID,
        ctx: MtlsRunnerContext = Depends(get_authenticated_runner),  # noqa: B008
        settings: Settings = Depends(get_settings),  # noqa: B008
    ) -> Response:
        sbom_doc, sbom_bytes = await get_runner_job_sbom_input(
            ctx.db,
            runner=ctx.runner,
            job_id=job_id,
            settings=settings,
        )
        return Response(
            content=sbom_bytes,
            media_type="application/vnd.cyclonedx+json",
            headers={
                "X-SBOM-Document-Id": str(sbom_doc.id),
                "X-SBOM-SHA256": sbom_doc.bom_sha256,
            },
        )

    @application.get(
        "/api/v1/runner/jobs/{job_id}/target-auth",
        response_model=RunnerJobTargetAuthOut,
    )
    async def get_target_auth_route(
        job_id: uuid.UUID,
        response: Response,
        ctx: MtlsRunnerContext = Depends(get_authenticated_runner),  # noqa: B008
        settings: Settings = Depends(get_settings),  # noqa: B008
    ) -> RunnerJobTargetAuthOut:
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        auth_data = await get_runner_job_target_auth(
            ctx.db,
            runner=ctx.runner,
            job_id=job_id,
            settings=settings,
        )
        return RunnerJobTargetAuthOut(**auth_data)

    @application.get("/api/v1/runner/jobs/{job_id}/openapi-spec")
    async def get_openapi_spec_route(
        job_id: uuid.UUID,
        ctx: MtlsRunnerContext = Depends(get_authenticated_runner),  # noqa: B008
    ) -> Response:
        spec_bytes = await get_runner_job_openapi_spec(
            ctx.db,
            runner=ctx.runner,
            job_id=job_id,
        )
        return Response(
            content=spec_bytes,
            media_type="application/json",
            headers={"Cache-Control": "no-store, no-cache, must-revalidate"},
        )

    @application.post(
        "/api/v1/runner/jobs/{job_id}/health-probes",
        response_model=TargetHealthProbeOut,
        status_code=status.HTTP_201_CREATED,
    )
    async def post_target_health_probe_route(
        job_id: uuid.UUID,
        payload: TargetHealthProbeCreate,
        ctx: MtlsRunnerContext = Depends(get_authenticated_runner),  # noqa: B008
    ) -> TargetHealthProbeOut:
        probe = await record_target_health_probe(
            ctx.db,
            runner=ctx.runner,
            job_id=job_id,
            payload=payload,
        )
        return TargetHealthProbeOut.model_validate(probe)

    @application.post(
        "/api/v1/runner/jobs/{job_id}/complete",
        response_model=RunnerJobCompleteOut,
    )
    async def complete_job_route(
        job_id: uuid.UUID,
        payload: RunnerJobCompleteRequest,
        ctx: MtlsRunnerContext = Depends(get_authenticated_runner),  # noqa: B008
        settings: Settings = Depends(get_settings),  # noqa: B008
    ) -> RunnerJobCompleteOut:
        return await complete_runner_job(
            ctx.db,
            runner=ctx.runner,
            job_id=job_id,
            payload=payload,
            settings=settings,
        )

    return application


gateway_app = create_runner_gateway_app()


class Tls13MtlsUvicornConfig(uvicorn.Config):
    """Uvicorn Config that pins OpenSSL server context to TLS 1.3 minimum for mTLS."""

    def load(self) -> None:
        super().load()
        if self.ssl is not None:
            self.ssl.minimum_version = ssl.TLSVersion.TLSv1_3


def create_mtls_uvicorn_config(
    target_app: FastAPI,
    *,
    host: str,
    port: int,
    certfile: str,
    keyfile: str,
    ca_certs: str,
    log_level: str | None = None,
) -> uvicorn.Config:
    """Build a strict TLS 1.3 + CERT_REQUIRED uvicorn configuration for the runner gateway."""
    return Tls13MtlsUvicornConfig(
        target_app,
        host=host,
        port=port,
        http=MtlsH11Protocol,
        ssl_version=ssl.PROTOCOL_TLS_SERVER,
        ssl_certfile=certfile,
        ssl_keyfile=keyfile,
        ssl_ca_certs=ca_certs,
        ssl_cert_reqs=ssl.CERT_REQUIRED,
        log_level=log_level,
    )


def main() -> None:
    """Launch strict TLS 1.3 + CERT_REQUIRED runner mTLS server."""
    settings = get_settings()
    ca_path = settings.runner_mtls_ca_cert_path.strip()
    cert_path = settings.runner_gateway_cert_path.strip()
    key_path = settings.runner_gateway_key_path.strip()
    if not (ca_path and cert_path and key_path):
        raise RuntimeError(
            "RUNNER_MTLS_CA_CERT_PATH, RUNNER_GATEWAY_CERT_PATH, and "
            "RUNNER_GATEWAY_KEY_PATH are required to start the runner mTLS gateway"
        )
    host = os.environ.get("RUNNER_GATEWAY_HOST", "0.0.0.0")  # noqa: S104
    port = int(os.environ.get("RUNNER_GATEWAY_PORT", "8443"))
    config = create_mtls_uvicorn_config(
        gateway_app,
        host=host,
        port=port,
        certfile=cert_path,
        keyfile=key_path,
        ca_certs=ca_path,
    )
    uvicorn.Server(config).run()


if __name__ == "__main__":
    main()
