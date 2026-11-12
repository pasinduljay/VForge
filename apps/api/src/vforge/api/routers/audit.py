"""Read-only audit-log query endpoint gated by audit permissions."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.api.deps import TenantContext, get_db, get_tenant_context
from vforge.auth.rbac import Permission, assert_permission
from vforge.schemas import AuditEventOut, PaginatedResponse
from vforge.services.audit import list_audit_events

router = APIRouter(prefix="/api/v1/organizations/{org_id}/audit-events", tags=["audit"])


@router.get("", response_model=PaginatedResponse)
async def list_organization_audit_events(
    action: str | None = Query(default=None),
    resource_type: str | None = Query(default=None),
    outcome: str | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> PaginatedResponse:
    assert_permission(ctx.role, Permission.AUDIT_READ)
    rows, total = await list_audit_events(
        db,
        organization_id=ctx.org_id,
        action=action,
        resource_type=resource_type,
        outcome=outcome,
        limit=limit,
        offset=offset,
    )
    return PaginatedResponse(
        items=[AuditEventOut.model_validate(item) for item in rows],
        total=total,
        limit=limit,
        offset=offset,
    )
