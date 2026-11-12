"""Organization and membership API endpoints."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.api.deps import (
    Principal,
    TenantContext,
    enforce_sensitive_rate_limit,
    get_current_principal,
    get_db,
    get_tenant_context,
)
from vforge.models.enums import MembershipStatus, Role
from vforge.schemas import (
    MembershipCreate,
    MembershipOut,
    MembershipUpdate,
    OrganizationCreate,
    OrganizationOut,
    OrganizationUpdate,
    PaginatedResponse,
)
from vforge.services import organizations as org_service

router = APIRouter(prefix="/api/v1/organizations", tags=["organizations"])


@router.get("", response_model=list[OrganizationOut])
async def list_my_organizations(
    principal: Principal = Depends(get_current_principal),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> list[OrganizationOut]:
    pairs = await org_service.list_user_memberships(db, user_id=principal.user.id)
    return [OrganizationOut.model_validate(org) for _membership, org in pairs]


@router.post(
    "",
    response_model=OrganizationOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def create_organization(
    payload: OrganizationCreate,
    principal: Principal = Depends(get_current_principal),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> OrganizationOut:
    org = await org_service.create_organization(
        db,
        user_id=principal.user.id,
        name=payload.name,
        slug=payload.slug,
        correlation_id=principal.correlation_id,
    )
    return OrganizationOut.model_validate(org)


@router.get("/{org_id}", response_model=OrganizationOut)
async def get_organization(
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> OrganizationOut:
    org = await org_service.get_organization(db, org_id=ctx.org_id, actor_role=ctx.role)
    return OrganizationOut.model_validate(org)


@router.patch(
    "/{org_id}",
    response_model=OrganizationOut,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def update_organization(
    payload: OrganizationUpdate,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> OrganizationOut:
    org = await org_service.update_organization(
        db,
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        name=payload.name,
        status=payload.status,
        correlation_id=ctx.correlation_id,
    )
    return OrganizationOut.model_validate(org)


@router.get("/{org_id}/memberships", response_model=PaginatedResponse)
async def list_memberships(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> PaginatedResponse:
    rows, total = await org_service.list_memberships(
        db,
        org_id=ctx.org_id,
        actor_role=ctx.role,
        limit=limit,
        offset=offset,
    )
    items = [
        MembershipOut(
            id=m.id,
            organization_id=m.organization_id,
            user_id=m.user_id,
            role=Role(m.role),
            status=MembershipStatus(m.status),
            user_email=u.email,
            user_display_name=u.display_name,
            oidc_issuer=u.oidc_issuer,
            oidc_subject=u.oidc_subject,
            created_at=m.created_at,
            updated_at=m.updated_at,
        )
        for m, u in rows
    ]
    return PaginatedResponse(items=items, total=total, limit=limit, offset=offset)


@router.post(
    "/{org_id}/memberships",
    response_model=MembershipOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def add_membership(
    payload: MembershipCreate,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> MembershipOut:
    m, u = await org_service.add_membership(
        db,
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        oidc_issuer=payload.oidc_issuer,
        oidc_subject=payload.oidc_subject,
        email=str(payload.email),
        display_name=payload.display_name,
        role=payload.role,
        status=payload.status,
        correlation_id=ctx.correlation_id,
    )
    return MembershipOut(
        id=m.id,
        organization_id=m.organization_id,
        user_id=m.user_id,
        role=Role(m.role),
        status=MembershipStatus(m.status),
        user_email=u.email,
        user_display_name=u.display_name,
        oidc_issuer=u.oidc_issuer,
        oidc_subject=u.oidc_subject,
        created_at=m.created_at,
        updated_at=m.updated_at,
    )


@router.patch(
    "/{org_id}/memberships/{membership_id}",
    response_model=MembershipOut,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def update_membership(
    membership_id: uuid.UUID,
    payload: MembershipUpdate,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> MembershipOut:
    m, u = await org_service.update_membership(
        db,
        org_id=ctx.org_id,
        membership_id=membership_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        new_role=payload.role,
        new_status=payload.status,
        correlation_id=ctx.correlation_id,
    )
    return MembershipOut(
        id=m.id,
        organization_id=m.organization_id,
        user_id=m.user_id,
        role=Role(m.role),
        status=MembershipStatus(m.status),
        user_email=u.email,
        user_display_name=u.display_name,
        oidc_issuer=u.oidc_issuer,
        oidc_subject=u.oidc_subject,
        created_at=m.created_at,
        updated_at=m.updated_at,
    )


@router.delete(
    "/{org_id}/memberships/{membership_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def remove_membership(
    membership_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> None:
    await org_service.remove_membership(
        db,
        org_id=ctx.org_id,
        membership_id=membership_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        correlation_id=ctx.correlation_id,
    )
