"""Phase 3 scan orchestration API endpoints: create, list, inspect, cancel, and leases."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Header, Query, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.api.deps import (
    TenantContext,
    enforce_sensitive_rate_limit,
    get_db,
    get_tenant_context,
)
from vforge.config import Settings, get_settings
from vforge.errors import ValidationError
from vforge.models.enums import ScanRunStatus, TargetLeaseStatus
from vforge.orchestration.service import (
    create_scan_run,
    get_scan_run,
    list_scan_health_probes,
    list_scan_runs,
    list_target_leases,
    request_cancel_scan_run,
)
from vforge.schemas import (
    PaginatedResponse,
    ScanCancelRequest,
    ScanRunCreate,
    ScanRunDetailOut,
    ScanRunSummaryOut,
    ScanTargetLeaseOut,
    TargetHealthProbeOut,
)

router = APIRouter(prefix="/api/v1/organizations/{org_id}", tags=["scans"])


@router.post(
    "/scans",
    response_model=ScanRunDetailOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_scan_endpoint(
    payload: ScanRunCreate,
    request: Request,
    response: Response,
    idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
    _rate_limited: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> ScanRunDetailOut:
    if not idempotency_key:
        raise ValidationError("Idempotency-Key header is required")

    result = await create_scan_run(
        db,
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        request=payload,
        idempotency_key=idempotency_key,
        correlation_id=ctx.correlation_id,
        settings=settings,
        dns_resolver=getattr(request.app.state, "dns_resolver", None),
        opa_client=getattr(request.app.state, "opa_client", None),
        signer=getattr(request.app.state, "snapshot_signer", None),
    )
    if result.idempotent_replay:
        response.status_code = status.HTTP_200_OK
    return ScanRunDetailOut.model_validate(result.scan_run)


@router.get("/scans", response_model=PaginatedResponse)
async def list_scans_endpoint(
    limit: int = Query(default=50, ge=1, le=200),  # noqa: B008
    offset: int = Query(default=0, ge=0),  # noqa: B008
    status_filter: ScanRunStatus | None = Query(default=None, alias="status"),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> PaginatedResponse:
    items, total = await list_scan_runs(
        db,
        org_id=ctx.org_id,
        actor_role=ctx.role,
        limit=limit,
        offset=offset,
        status_filter=status_filter.value if status_filter else None,
    )
    return PaginatedResponse(
        items=[ScanRunSummaryOut.model_validate(item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/scans/{scan_run_id}", response_model=ScanRunDetailOut)
async def get_scan_endpoint(
    scan_run_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> ScanRunDetailOut:
    run = await get_scan_run(
        db,
        org_id=ctx.org_id,
        scan_run_id=scan_run_id,
        actor_role=ctx.role,
    )
    return ScanRunDetailOut.model_validate(run)


@router.get(
    "/scans/{scan_run_id}/health-probes",
    response_model=list[TargetHealthProbeOut],
)
async def list_scan_health_probes_endpoint(
    scan_run_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> list[TargetHealthProbeOut]:
    probes = await list_scan_health_probes(
        db,
        org_id=ctx.org_id,
        scan_run_id=scan_run_id,
        actor_role=ctx.role,
    )
    return [TargetHealthProbeOut.model_validate(item) for item in probes]


@router.post("/scans/{scan_run_id}/cancel", response_model=ScanRunDetailOut)
async def cancel_scan_endpoint(
    scan_run_id: uuid.UUID,
    payload: ScanCancelRequest | None = None,
    _rate_limited: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> ScanRunDetailOut:
    run = await request_cancel_scan_run(
        db,
        org_id=ctx.org_id,
        scan_run_id=scan_run_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        reason=payload.reason if payload else None,
        correlation_id=ctx.correlation_id,
    )
    return ScanRunDetailOut.model_validate(run)


@router.get("/leases", response_model=list[ScanTargetLeaseOut])
async def list_leases_endpoint(
    status_filter: TargetLeaseStatus | None = Query(default=None, alias="status"),  # noqa: B008
    limit: int = Query(default=100, ge=1, le=200),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> list[ScanTargetLeaseOut]:
    leases = await list_target_leases(
        db,
        org_id=ctx.org_id,
        actor_role=ctx.role,
        status_filter=status_filter.value if status_filter else None,
        limit=limit,
    )
    return [ScanTargetLeaseOut.model_validate(item) for item in leases]
