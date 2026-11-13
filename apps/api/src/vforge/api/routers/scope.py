"""Scope evaluation and immutable signed snapshot API endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.api.deps import (
    TenantContext,
    enforce_sensitive_rate_limit,
    get_db,
    get_tenant_context,
)
from vforge.auth.rbac import Permission, assert_permission
from vforge.config import Settings, get_settings
from vforge.errors import ConflictError, NotFoundError
from vforge.models import Asset, AuthorizationStatus
from vforge.schemas import (
    PaginatedResponse,
    ScopeEvaluateRequest,
    ScopeEvaluationResponse,
    ScopeSnapshotOut,
    SnapshotVerifyRequest,
    SnapshotVerifyResponse,
)
from vforge.services import governance as gov_service
from vforge.services import scope as scope_service

router = APIRouter(prefix="/api/v1/organizations/{org_id}", tags=["scope-enforcement"])


@router.post(
    "/scope/evaluate",
    response_model=ScopeEvaluationResponse,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def evaluate_scope(
    payload: ScopeEvaluateRequest,
    request: Request,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> ScopeEvaluationResponse:
    return await scope_service.evaluate_scope(
        db,
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        request=payload,
        correlation_id=ctx.correlation_id,
        settings=settings,
        dns_resolver=getattr(request.app.state, "dns_resolver", None),
        opa_client=getattr(request.app.state, "opa_client", None),
        signer=getattr(request.app.state, "snapshot_signer", None),
    )


@router.get("/snapshots", response_model=PaginatedResponse)
async def list_snapshots(
    authorization_id: uuid.UUID | None = Query(default=None),  # noqa: B008
    asset_id: uuid.UUID | None = Query(default=None),  # noqa: B008
    limit: int = Query(default=50, ge=1, le=200),  # noqa: B008
    offset: int = Query(default=0, ge=0),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> PaginatedResponse:
    rows, total = await scope_service.list_snapshots(
        db,
        org_id=ctx.org_id,
        actor_role=ctx.role,
        authorization_id=authorization_id,
        asset_id=asset_id,
        limit=limit,
        offset=offset,
    )
    return PaginatedResponse(
        items=[ScopeSnapshotOut.model_validate(row) for row in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/authorizations/{authorization_id}/snapshots",
    response_model=ScopeSnapshotOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def create_snapshot(
    authorization_id: uuid.UUID,
    request: Request,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> ScopeSnapshotOut:
    assert_permission(ctx.role, Permission.SNAPSHOT_CREATE)
    auth = await gov_service.get_authorization(
        db,
        org_id=ctx.org_id,
        authorization_id=authorization_id,
        actor_role=ctx.role,
    )
    if auth.status != AuthorizationStatus.APPROVED.value:
        raise ConflictError(f"Cannot issue snapshot for authorization in status '{auth.status}'")

    asset = (
        await db.execute(
            select(Asset).where(Asset.id == auth.asset_id, Asset.organization_id == ctx.org_id)
        )
    ).scalar_one_or_none()
    if asset is None:
        raise NotFoundError("Asset not found")

    snapshot = await scope_service.create_signed_snapshot_for_authorization(
        db,
        auth=auth,
        asset=asset,
        actor_id=ctx.user.id,
        correlation_id=ctx.correlation_id,
        settings=settings,
        dns_resolver=getattr(request.app.state, "dns_resolver", None),
        signer=getattr(request.app.state, "snapshot_signer", None),
    )
    return ScopeSnapshotOut.model_validate(snapshot)


@router.get("/snapshots/{snapshot_id}", response_model=ScopeSnapshotOut)
async def get_snapshot(
    snapshot_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> ScopeSnapshotOut:
    snapshot = await scope_service.get_snapshot(
        db,
        org_id=ctx.org_id,
        snapshot_id=snapshot_id,
        actor_role=ctx.role,
    )
    return ScopeSnapshotOut.model_validate(snapshot)


@router.post(
    "/snapshots/{snapshot_id}/verify",
    response_model=SnapshotVerifyResponse,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def verify_snapshot(
    snapshot_id: uuid.UUID,
    request: Request,
    payload: SnapshotVerifyRequest = SnapshotVerifyRequest(),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> SnapshotVerifyResponse:
    return await scope_service.verify_snapshot(
        db,
        org_id=ctx.org_id,
        snapshot_id=snapshot_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        revalidate_dns=payload.revalidate_dns,
        correlation_id=ctx.correlation_id,
        settings=settings,
        dns_resolver=getattr(request.app.state, "dns_resolver", None),
        opa_client=getattr(request.app.state, "opa_client", None),
        signer=getattr(request.app.state, "snapshot_signer", None),
    )
