"""Control-plane RBAC routes for runner pools, runner mTLS enrollment/revocation, & artifacts."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.api.deps import (
    TenantContext,
    enforce_sensitive_rate_limit,
    get_db,
    get_tenant_context,
)
from vforge.config import Settings, get_settings
from vforge.schemas import (
    RunnerArtifactOut,
    RunnerEventOut,
    RunnerOut,
    RunnerPoolCreate,
    RunnerPoolOut,
    RunnerRegisterRequest,
    RunnerRevokeRequest,
)
from vforge.services.runners import (
    create_runner_pool,
    download_decrypted_artifact,
    list_runner_events,
    list_runner_pools,
    list_runners,
    list_scan_artifacts,
    register_runner,
    revoke_runner,
)

router = APIRouter(prefix="/api/v1/organizations/{org_id}", tags=["runners"])


@router.post(
    "/runner-pools",
    response_model=RunnerPoolOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_pool_route(
    payload: RunnerPoolCreate,
    _rate_limited: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> RunnerPoolOut:
    pool = await create_runner_pool(
        db,
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        payload=payload,
        correlation_id=ctx.correlation_id,
    )
    return RunnerPoolOut.model_validate(pool)


@router.get("/runner-pools", response_model=list[RunnerPoolOut])
async def list_pools_route(
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> list[RunnerPoolOut]:
    pools = await list_runner_pools(
        db,
        org_id=ctx.org_id,
        actor_role=ctx.role,
    )
    return [RunnerPoolOut.model_validate(p) for p in pools]


@router.post(
    "/runners",
    response_model=RunnerOut,
    status_code=status.HTTP_201_CREATED,
)
async def register_runner_route(
    payload: RunnerRegisterRequest,
    _rate_limited: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> RunnerOut:
    runner = await register_runner(
        db,
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        payload=payload,
        correlation_id=ctx.correlation_id,
    )
    return RunnerOut.model_validate(runner)


@router.get("/runners", response_model=list[RunnerOut])
async def list_runners_route(
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> list[RunnerOut]:
    runners = await list_runners(
        db,
        org_id=ctx.org_id,
        actor_role=ctx.role,
    )
    return [RunnerOut.model_validate(r) for r in runners]


@router.get("/runner-events", response_model=list[RunnerEventOut])
async def list_runner_events_route(
    limit: int = 100,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> list[RunnerEventOut]:
    events = await list_runner_events(
        db,
        org_id=ctx.org_id,
        actor_role=ctx.role,
        limit=limit,
    )
    return [RunnerEventOut.model_validate(e) for e in events]


@router.post(
    "/runners/{runner_id}/revoke",
    response_model=RunnerOut,
)
async def revoke_runner_route(
    runner_id: uuid.UUID,
    payload: RunnerRevokeRequest,
    _rate_limited: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> RunnerOut:
    runner = await revoke_runner(
        db,
        org_id=ctx.org_id,
        runner_id=runner_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        reason=payload.reason,
        correlation_id=ctx.correlation_id,
    )
    return RunnerOut.model_validate(runner)


@router.get("/scans/{scan_id}/artifacts", response_model=list[RunnerArtifactOut])
async def list_artifacts_route(
    scan_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> list[RunnerArtifactOut]:
    items = await list_scan_artifacts(
        db,
        org_id=ctx.org_id,
        scan_run_id=scan_id,
        actor_role=ctx.role,
    )
    return [RunnerArtifactOut.model_validate(item) for item in items]


@router.get("/scans/{scan_id}/artifacts/{artifact_id}/download")
async def download_artifact_route(
    scan_id: uuid.UUID,
    artifact_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> Response:
    artifact, plaintext = await download_decrypted_artifact(
        db,
        org_id=ctx.org_id,
        scan_run_id=scan_id,
        artifact_id=artifact_id,
        actor_role=ctx.role,
        settings=settings,
    )
    return Response(
        content=plaintext,
        media_type=artifact.content_type,
        headers={
            "X-VForge-Artifact-SHA256": artifact.sha256,
            "Cache-Control": "no-store",
        },
    )
