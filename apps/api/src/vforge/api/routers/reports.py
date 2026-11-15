"""Control-plane API routes for Phase 8 executive/technical reporting and downloads."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.api.deps import (
    TenantContext,
    enforce_sensitive_rate_limit,
    get_db,
    get_tenant_context,
)
from vforge.config import Settings, get_settings
from vforge.schemas import (
    PaginatedResponse,
    ReportGenerateRequest,
    ReportOut,
)
from vforge.services.reporting import (
    download_report_bytes,
    generate_report,
    get_report,
    list_reports,
)

router = APIRouter(prefix="/api/v1/organizations/{org_id}", tags=["reports"])


@router.post(
    "/reports",
    response_model=ReportOut,
    status_code=status.HTTP_201_CREATED,
)
async def generate_report_route(
    payload: ReportGenerateRequest,
    _rate_limited: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> ReportOut:
    rep = await generate_report(
        db,
        org_id=ctx.org_id,
        project_id=payload.project_id,
        scan_run_id=payload.scan_run_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        report_type=payload.report_type,
        format=payload.format,
        title=payload.title,
        settings=settings,
    )
    return ReportOut.model_validate(rep)


@router.get("/reports", response_model=PaginatedResponse)
async def list_reports_route(
    project_id: uuid.UUID | None = Query(default=None),  # noqa: B008
    scan_run_id: uuid.UUID | None = Query(default=None),  # noqa: B008
    limit: int = Query(default=50, ge=1, le=200),  # noqa: B008
    offset: int = Query(default=0, ge=0),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> PaginatedResponse:
    items, total = await list_reports(
        db,
        org_id=ctx.org_id,
        actor_role=ctx.role,
        project_id=project_id,
        scan_run_id=scan_run_id,
        limit=limit,
        offset=offset,
    )
    return PaginatedResponse(
        items=[ReportOut.model_validate(item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/reports/{report_id}", response_model=ReportOut)
async def get_report_route(
    report_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> ReportOut:
    rep = await get_report(
        db,
        org_id=ctx.org_id,
        report_id=report_id,
        actor_role=ctx.role,
    )
    return ReportOut.model_validate(rep)


@router.get("/reports/{report_id}/download")
async def download_report_route(
    report_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> Response:
    filename, content_type, data = await download_report_bytes(
        db,
        org_id=ctx.org_id,
        report_id=report_id,
        actor_role=ctx.role,
        settings=settings,
    )
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"',
        "Content-Type": content_type,
        "Cache-Control": "no-store, no-cache, must-revalidate",
    }
    return Response(content=data, media_type=content_type, headers=headers)
