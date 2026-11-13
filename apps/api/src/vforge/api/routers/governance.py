"""Authorizations and versioned scan-profile API endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.api.deps import (
    TenantContext,
    enforce_sensitive_rate_limit,
    get_db,
    get_tenant_context,
)
from vforge.config import Settings, get_settings
from vforge.models.enums import AuthorizationStatus
from vforge.schemas import (
    AuthorizationCreate,
    AuthorizationDecisionRequest,
    AuthorizationOut,
    AuthorizationRevokeRequest,
    AuthorizationUpdate,
    PaginatedResponse,
    ScanProfileCreate,
    ScanProfileOut,
    ScanProfileUpdate,
)
from vforge.services import governance as gov_service

router = APIRouter(prefix="/api/v1/organizations/{org_id}", tags=["authorizations-scan-profiles"])


# --- Authorizations ---


@router.get("/authorizations", response_model=PaginatedResponse)
async def list_authorizations(
    asset_id: uuid.UUID | None = Query(default=None),  # noqa: B008
    status_filter: AuthorizationStatus | None = Query(default=None, alias="status"),  # noqa: B008
    limit: int = Query(default=50, ge=1, le=200),  # noqa: B008
    offset: int = Query(default=0, ge=0),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> PaginatedResponse:
    rows, total = await gov_service.list_authorizations(
        db,
        org_id=ctx.org_id,
        actor_role=ctx.role,
        asset_id=asset_id,
        status=status_filter,
        limit=limit,
        offset=offset,
    )
    return PaginatedResponse(
        items=[AuthorizationOut.model_validate(item) for item in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/authorizations",
    response_model=AuthorizationOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def request_authorization(
    payload: AuthorizationCreate,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> AuthorizationOut:
    auth = await gov_service.request_authorization(
        db,
        org_id=ctx.org_id,
        asset_id=payload.asset_id,
        requester_id=ctx.user.id,
        actor_role=ctx.role,
        approved_testing_scope=payload.approved_testing_scope,
        approved_activities=payload.approved_activities,
        allowed_ports=payload.allowed_ports,
        permitted_intensity=payload.permitted_intensity,
        allow_private_networks=payload.allow_private_networks,
        authorization_reference=payload.authorization_reference,
        valid_from=payload.valid_from,
        expires_at=payload.expires_at,
        correlation_id=ctx.correlation_id,
        settings=settings,
    )
    return AuthorizationOut.model_validate(auth)


@router.patch(
    "/authorizations/{authorization_id}",
    response_model=AuthorizationOut,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def update_authorization(
    authorization_id: uuid.UUID,
    payload: AuthorizationUpdate,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> AuthorizationOut:
    auth = await gov_service.update_authorization(
        db,
        org_id=ctx.org_id,
        authorization_id=authorization_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        approved_testing_scope=payload.approved_testing_scope,
        approved_activities=payload.approved_activities,
        allowed_ports=payload.allowed_ports,
        permitted_intensity=payload.permitted_intensity,
        allow_private_networks=payload.allow_private_networks,
        authorization_reference=payload.authorization_reference,
        valid_from=payload.valid_from,
        expires_at=payload.expires_at,
        correlation_id=ctx.correlation_id,
        settings=settings,
    )
    return AuthorizationOut.model_validate(auth)


@router.get("/authorizations/{authorization_id}", response_model=AuthorizationOut)
async def get_authorization(
    authorization_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> AuthorizationOut:
    auth = await gov_service.get_authorization(
        db,
        org_id=ctx.org_id,
        authorization_id=authorization_id,
        actor_role=ctx.role,
    )
    return AuthorizationOut.model_validate(auth)


@router.post(
    "/authorizations/{authorization_id}/approve",
    response_model=AuthorizationOut,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def approve_authorization(
    authorization_id: uuid.UUID,
    payload: AuthorizationDecisionRequest,
    request: Request,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> AuthorizationOut:
    dns_resolver = getattr(request.app.state, "dns_resolver", None)
    signer = getattr(request.app.state, "snapshot_signer", None)
    auth = await gov_service.approve_authorization(
        db,
        org_id=ctx.org_id,
        authorization_id=authorization_id,
        approver_id=ctx.user.id,
        actor_role=ctx.role,
        reason=payload.reason,
        correlation_id=ctx.correlation_id,
        settings=settings,
        dns_resolver=dns_resolver,
        signer=signer,
    )
    return AuthorizationOut.model_validate(auth)


@router.post(
    "/authorizations/{authorization_id}/reject",
    response_model=AuthorizationOut,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def reject_authorization(
    authorization_id: uuid.UUID,
    payload: AuthorizationDecisionRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> AuthorizationOut:
    auth = await gov_service.reject_authorization(
        db,
        org_id=ctx.org_id,
        authorization_id=authorization_id,
        approver_id=ctx.user.id,
        actor_role=ctx.role,
        reason=payload.reason,
        correlation_id=ctx.correlation_id,
    )
    return AuthorizationOut.model_validate(auth)


@router.post(
    "/authorizations/{authorization_id}/revoke",
    response_model=AuthorizationOut,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def revoke_authorization(
    authorization_id: uuid.UUID,
    payload: AuthorizationRevokeRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> AuthorizationOut:
    auth = await gov_service.revoke_authorization(
        db,
        org_id=ctx.org_id,
        authorization_id=authorization_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        reason=payload.reason,
        correlation_id=ctx.correlation_id,
    )
    return AuthorizationOut.model_validate(auth)


# --- Scan Profiles ---


@router.get("/scan-profiles", response_model=PaginatedResponse)
async def list_scan_profiles(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> PaginatedResponse:
    rows, total = await gov_service.list_scan_profiles(
        db,
        org_id=ctx.org_id,
        actor_role=ctx.role,
        limit=limit,
        offset=offset,
    )
    return PaginatedResponse(
        items=[ScanProfileOut.model_validate(item) for item in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/scan-profiles",
    response_model=ScanProfileOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_scan_profile(
    payload: ScanProfileCreate,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> ScanProfileOut:
    profile = await gov_service.create_scan_profile(
        db,
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        name=payload.name,
        configuration=payload.configuration,
        status=payload.status,
        correlation_id=ctx.correlation_id,
    )
    return ScanProfileOut.model_validate(profile)


@router.patch("/scan-profiles/{scan_profile_id}", response_model=ScanProfileOut)
async def update_scan_profile(
    scan_profile_id: uuid.UUID,
    payload: ScanProfileUpdate,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> ScanProfileOut:
    profile = await gov_service.update_scan_profile(
        db,
        org_id=ctx.org_id,
        scan_profile_id=scan_profile_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        status=payload.status,
        configuration=payload.configuration,
        correlation_id=ctx.correlation_id,
    )
    return ScanProfileOut.model_validate(profile)
