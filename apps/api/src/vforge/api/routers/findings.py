"""Control-plane API routes for Phase 8 findings triage, lifecycle events, and risk exceptions."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.api.deps import (
    TenantContext,
    enforce_sensitive_rate_limit,
    get_db,
    get_tenant_context,
)
from vforge.auth.rbac import Permission, assert_permission
from vforge.models.enums import (
    FindingCategory,
    FindingSeverity,
    FindingStatus,
    RiskExceptionStatus,
)
from vforge.schemas import (
    FindingDetailOut,
    FindingEventOut,
    FindingOccurrenceOut,
    FindingOut,
    FindingUpdate,
    PaginatedResponse,
    RiskExceptionCreate,
    RiskExceptionOut,
    RiskExceptionReview,
)
from vforge.services.findings import (
    check_and_update_sla_breaches,
    get_finding_with_details,
    list_finding_events,
    list_findings,
    list_risk_exceptions,
    request_risk_exception,
    review_risk_exception,
    update_finding,
)

router = APIRouter(prefix="/api/v1/organizations/{org_id}", tags=["findings"])


@router.get("/findings", response_model=PaginatedResponse)
async def list_findings_route(
    project_id: uuid.UUID | None = Query(default=None),  # noqa: B008
    scan_run_id: uuid.UUID | None = Query(default=None),  # noqa: B008
    category: FindingCategory | None = Query(default=None),  # noqa: B008
    severity: FindingSeverity | None = Query(default=None),  # noqa: B008
    finding_status: FindingStatus | None = Query(default=None, alias="status"),  # noqa: B008
    purl: str | None = Query(default=None, max_length=512),  # noqa: B008
    limit: int = Query(default=50, ge=1, le=200),  # noqa: B008
    offset: int = Query(default=0, ge=0),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> PaginatedResponse:
    items, total = await list_findings(
        db,
        org_id=ctx.org_id,
        actor_role=ctx.role,
        project_id=project_id,
        scan_run_id=scan_run_id,
        category=category,
        severity=severity,
        status=finding_status,
        purl=purl,
        limit=limit,
        offset=offset,
    )
    return PaginatedResponse(
        items=[FindingOut.model_validate(item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/findings/{finding_id}", response_model=FindingDetailOut)
async def get_finding_route(
    finding_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> FindingDetailOut:
    finding, occurrences, events, active_exc = await get_finding_with_details(
        db,
        org_id=ctx.org_id,
        finding_id=finding_id,
        actor_role=ctx.role,
    )
    base = FindingOut.model_validate(finding).model_dump()
    return FindingDetailOut(
        **base,
        occurrences=[FindingOccurrenceOut.model_validate(occ) for occ in occurrences],
        events=[FindingEventOut.model_validate(ev) for ev in events],
        active_risk_exception=(RiskExceptionOut.model_validate(active_exc) if active_exc else None),
    )


@router.patch("/findings/{finding_id}", response_model=FindingDetailOut)
async def patch_finding_route(
    finding_id: uuid.UUID,
    payload: FindingUpdate,
    _rate_limited: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> FindingDetailOut:
    finding, occurrences, events, active_exc = await update_finding(
        db,
        org_id=ctx.org_id,
        finding_id=finding_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        payload=payload,
    )
    base = FindingOut.model_validate(finding).model_dump()
    return FindingDetailOut(
        **base,
        occurrences=[FindingOccurrenceOut.model_validate(occ) for occ in occurrences],
        events=[FindingEventOut.model_validate(ev) for ev in events],
        active_risk_exception=(RiskExceptionOut.model_validate(active_exc) if active_exc else None),
    )


@router.get("/findings/{finding_id}/events", response_model=list[FindingEventOut])
async def list_finding_events_route(
    finding_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> list[FindingEventOut]:
    events = await list_finding_events(
        db,
        org_id=ctx.org_id,
        finding_id=finding_id,
        actor_role=ctx.role,
    )
    return [FindingEventOut.model_validate(ev) for ev in events]


@router.post(
    "/findings/{finding_id}/risk-exceptions",
    response_model=RiskExceptionOut,
    status_code=status.HTTP_201_CREATED,
)
async def request_risk_exception_route(
    finding_id: uuid.UUID,
    payload: RiskExceptionCreate,
    _rate_limited: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> RiskExceptionOut:
    exc = await request_risk_exception(
        db,
        org_id=ctx.org_id,
        finding_id=finding_id,
        requested_by=ctx.user.id,
        actor_role=ctx.role,
        payload=payload,
    )
    return RiskExceptionOut.model_validate(exc)


@router.get("/risk-exceptions", response_model=PaginatedResponse)
async def list_risk_exceptions_route(
    project_id: uuid.UUID | None = Query(default=None),  # noqa: B008
    finding_id: uuid.UUID | None = Query(default=None),  # noqa: B008
    exception_status: RiskExceptionStatus | None = Query(default=None, alias="status"),  # noqa: B008
    limit: int = Query(default=50, ge=1, le=200),  # noqa: B008
    offset: int = Query(default=0, ge=0),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> PaginatedResponse:
    items, total = await list_risk_exceptions(
        db,
        org_id=ctx.org_id,
        actor_role=ctx.role,
        project_id=project_id,
        finding_id=finding_id,
        status=exception_status,
        limit=limit,
        offset=offset,
    )
    return PaginatedResponse(
        items=[RiskExceptionOut.model_validate(item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post("/risk-exceptions/{exception_id}/review", response_model=RiskExceptionOut)
async def review_risk_exception_route(
    exception_id: uuid.UUID,
    payload: RiskExceptionReview,
    _rate_limited: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> RiskExceptionOut:
    exc = await review_risk_exception(
        db,
        org_id=ctx.org_id,
        exception_id=exception_id,
        reviewer_id=ctx.user.id,
        reviewer_role=ctx.role,
        payload=payload,
    )
    return RiskExceptionOut.model_validate(exc)


@router.post("/findings/evaluate-sla", response_model=dict[str, int])
async def evaluate_sla_route(
    _rate_limited: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> dict[str, int]:
    assert_permission(ctx.role, Permission.FINDING_TRIAGE)
    breached_count = await check_and_update_sla_breaches(db, org_id=ctx.org_id, actor_role=ctx.role)
    return {"breached_count": breached_count}
