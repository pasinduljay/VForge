"""Control-plane API routes for Phase 5 source snapshots, findings, and scanner coverage."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Query, status
from vforge_scanners import (
    CAPABILITY_REGISTRY,
    CheckovAdapter,
    GitleaksAdapter,
    GrypeAdapter,
    NmapAdapter,
    NucleiAdapter,
    OpenGrepAdapter,
    SyftAdapter,
    TestsslAdapter,
    ZAPAdapter,
)
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.api.deps import (
    TenantContext,
    enforce_sensitive_rate_limit,
    get_db,
    get_tenant_context,
)
from vforge.auth.rbac import Permission, assert_permission
from vforge.config import Settings, get_settings
from vforge.schemas import (
    PaginatedResponse,
    SbomDocumentDetailOut,
    SbomDocumentOut,
    ScannerCapabilityEntryOut,
    ScannerCoverageOut,
    SourceSnapshotCreate,
    SourceSnapshotOut,
    VulnerabilityDbSnapshotOut,
)
from vforge.services.findings import (
    get_sbom,
    list_sboms,
    list_vulnerability_db_snapshots,
)
from vforge.services.source_snapshots import (
    create_source_snapshot,
    get_source_snapshot,
    list_source_snapshots,
)

router = APIRouter(prefix="/api/v1/organizations/{org_id}", tags=["scanners"])


@router.post(
    "/projects/{project_id}/source-snapshots",
    response_model=SourceSnapshotOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_source_snapshot_route(
    project_id: uuid.UUID,
    payload: SourceSnapshotCreate,
    _rate_limited: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> SourceSnapshotOut:
    snap = await create_source_snapshot(
        db,
        org_id=ctx.org_id,
        project_id=project_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        payload=payload,
        correlation_id=ctx.correlation_id,
        settings=settings,
    )
    return SourceSnapshotOut.model_validate(snap)


@router.get(
    "/projects/{project_id}/source-snapshots",
    response_model=PaginatedResponse,
)
async def list_source_snapshots_route(
    project_id: uuid.UUID,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> PaginatedResponse:
    items, total = await list_source_snapshots(
        db,
        org_id=ctx.org_id,
        project_id=project_id,
        actor_role=ctx.role,
        limit=limit,
        offset=offset,
    )
    return PaginatedResponse(
        items=[SourceSnapshotOut.model_validate(item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/source-snapshots/{snapshot_id}",
    response_model=SourceSnapshotOut,
)
async def get_source_snapshot_route(
    snapshot_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> SourceSnapshotOut:
    snap = await get_source_snapshot(
        db,
        org_id=ctx.org_id,
        snapshot_id=snapshot_id,
        actor_role=ctx.role,
    )
    return SourceSnapshotOut.model_validate(snap)


@router.get("/sboms", response_model=PaginatedResponse)
async def list_sboms_route(
    project_id: uuid.UUID | None = Query(default=None),  # noqa: B008
    scan_run_id: uuid.UUID | None = Query(default=None),  # noqa: B008
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> PaginatedResponse:
    items, total = await list_sboms(
        db,
        org_id=ctx.org_id,
        actor_role=ctx.role,
        project_id=project_id,
        scan_run_id=scan_run_id,
        limit=limit,
        offset=offset,
    )
    return PaginatedResponse(
        items=[SbomDocumentOut.model_validate(item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/sboms/{sbom_id}", response_model=SbomDocumentDetailOut)
async def get_sbom_route(
    sbom_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> SbomDocumentDetailOut:
    sbom = await get_sbom(
        db,
        org_id=ctx.org_id,
        sbom_id=sbom_id,
        actor_role=ctx.role,
    )
    return SbomDocumentDetailOut.model_validate(sbom)


@router.get("/vulnerability-db-snapshots", response_model=PaginatedResponse)
async def list_vulnerability_db_snapshots_route(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> PaginatedResponse:
    items, total = await list_vulnerability_db_snapshots(
        db,
        org_id=ctx.org_id,
        actor_role=ctx.role,
        limit=limit,
        offset=offset,
    )
    return PaginatedResponse(
        items=[VulnerabilityDbSnapshotOut.model_validate(item) for item in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/scanner-coverage", response_model=ScannerCoverageOut)
async def scanner_coverage_route(
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> ScannerCoverageOut:
    assert_permission(ctx.role, Permission.SCAN_READ)
    adapters = [
        OpenGrepAdapter(pinned_image=settings.opengrep_image_digest).metadata(),
        GitleaksAdapter(pinned_image=settings.gitleaks_image_digest).metadata(),
        SyftAdapter(pinned_image=settings.syft_image_digest).metadata(),
        GrypeAdapter(pinned_image=settings.grype_image_digest).metadata(),
        CheckovAdapter(pinned_image=settings.checkov_image_digest).metadata(),
        ZAPAdapter(pinned_image=settings.zap_image_digest).metadata(),
        NucleiAdapter(pinned_image=settings.nuclei_image_digest).metadata(),
        NmapAdapter(pinned_image=settings.nmap_image_digest).metadata(),
        TestsslAdapter(pinned_image=settings.testssl_image_digest).metadata(),
    ]
    return ScannerCoverageOut(
        phase=8,
        scanners_enabled=True,
        tools=[
            {
                "tool_id": m.tool_id,
                "tool_version": m.tool_version,
                "adapter_version": m.adapter_version,
                "capabilities": list(m.capabilities),
                "risk_class": m.risk_class,
                "supported_input_types": list(m.supported_input_types),
                "output_formats": list(m.output_formats),
                "pinned_image": m.pinned_image,
            }
            for m in adapters
        ],
        capabilities=[
            ScannerCapabilityEntryOut(
                language=rec.language,
                tool_id=rec.tool_id,
                support_status=rec.support_status,
                parser_mode=rec.parser_mode,
                supported_versions=rec.supported_versions,
                known_blind_spots=rec.known_blind_spots,
                last_validated=rec.last_validated,
            )
            for rec in CAPABILITY_REGISTRY
        ],
    )
