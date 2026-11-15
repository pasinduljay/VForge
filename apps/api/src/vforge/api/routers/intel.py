"""Control-plane API routes for Phase 9 Threat Intelligence feeds, sync, and finding enrichment."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.api.deps import (
    Principal,
    TenantContext,
    enforce_sensitive_rate_limit,
    get_current_principal,
    get_db,
    get_tenant_context,
)
from vforge.auth.rbac import ROLE_PERMISSIONS, Permission, assert_permission
from vforge.intel.enrichment import (
    batch_enrich_org_findings,
    get_cve_threat_intel,
    get_org_threat_intel_summary,
)
from vforge.intel.exposure import (
    import_exposure_as_finding,
    search_multi_source_exposure,
)
from vforge.intel.sync import sync_intelligence_source
from vforge.models import AuditOutcome, Membership, MembershipStatus, Organization, OrgStatus
from vforge.models.intel import IntelligenceSource, IntelSyncRun
from vforge.schemas import (
    CveThreatIntelOut,
    ExposureFindingImportRequest,
    ExposureFindingImportResponse,
    ExposureSearchRequest,
    ExposureSearchResponse,
    IntelEnrichmentRequest,
    IntelEnrichmentResponse,
    IntelSourceOut,
    IntelSyncRunOut,
    OrgThreatIntelSummaryOut,
)
from vforge.services.audit import record_audit_event

# Global router for platform threat intelligence catalogs
intel_router = APIRouter(prefix="/api/v1/intel", tags=["intel"])

# Org-scoped router for tenant finding enrichment and summaries
org_intel_router = APIRouter(prefix="/api/v1/organizations/{org_id}", tags=["intel"])


async def _require_global_intel_permission(
    db: AsyncSession,
    principal: Principal,
    permission: Permission,
    *,
    forbidden_detail: str,
) -> None:
    allowed_roles = [role.value for role, perms in ROLE_PERMISSIONS.items() if permission in perms]
    membership = (
        (
            await db.execute(
                select(Membership)
                .join(Organization, Organization.id == Membership.organization_id)
                .where(
                    Membership.user_id == principal.user.id,
                    Membership.status == MembershipStatus.ACTIVE.value,
                    Organization.status == OrgStatus.ACTIVE.value,
                    Membership.role.in_(allowed_roles),
                )
            )
        )
        .scalars()
        .first()
    )
    if not membership:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=forbidden_detail,
        )


@intel_router.get(
    "/sources",
    response_model=list[IntelSourceOut],
)
async def list_intelligence_sources_route(
    principal: Principal = Depends(get_current_principal),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> list[IntelSourceOut]:
    """List all registered external threat intelligence sources and their configuration."""
    await _require_global_intel_permission(
        db,
        principal,
        Permission.INTEL_READ,
        forbidden_detail=(
            "Active organization membership with threat intelligence read access is required"
        ),
    )
    sources = (
        (await db.execute(select(IntelligenceSource).order_by(IntelligenceSource.name)))
        .scalars()
        .all()
    )
    return [
        IntelSourceOut(
            id=s.id,
            slug=s.slug,
            name=s.name,
            source_type=s.source_type,
            provider_url=s.provider_url,
            license_name=s.license_name,
            license_url=s.license_url,
            terms_reference=s.terms_reference,
            is_active=s.is_active,
            is_gated=s.is_gated,
            requires_scope_auth=s.requires_scope_auth,
            allow_binary_upload=s.allow_binary_upload,
            created_at=s.created_at,
            updated_at=s.updated_at,
        )
        for s in sources
    ]


@intel_router.post(
    "/sources/{source_slug}/sync",
    response_model=IntelSyncRunOut,
    status_code=status.HTTP_200_OK,
)
async def sync_intelligence_source_route(
    source_slug: str,
    _rate_limited: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
    principal: Principal = Depends(get_current_principal),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> IntelSyncRunOut:
    """Trigger an on-demand synchronization run for an intelligence feed."""
    await _require_global_intel_permission(
        db,
        principal,
        Permission.INTEL_MANAGE,
        forbidden_detail="Global intelligence feed synchronization requires an administrative role",
    )

    try:
        run = await sync_intelligence_source(db, source_slug=source_slug)
        return IntelSyncRunOut(
            id=run.id,
            source_id=run.source_id,
            sync_mode=run.sync_mode,
            cursor_before=run.cursor_before,
            cursor_after=run.cursor_after,
            status=run.status,
            records_fetched=run.records_fetched,
            records_persisted=run.records_persisted,
            error_message=run.error_message,
            raw_payload_hash=run.raw_payload_hash,
            started_at=run.started_at,
            completed_at=run.completed_at,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@intel_router.get(
    "/sources/{source_slug}/runs",
    response_model=list[IntelSyncRunOut],
)
async def list_source_sync_runs_route(
    source_slug: str,
    limit: int = Query(default=20, ge=1, le=100),
    principal: Principal = Depends(get_current_principal),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> list[IntelSyncRunOut]:
    """List recent synchronization executions for a given threat intelligence feed."""
    await _require_global_intel_permission(
        db,
        principal,
        Permission.INTEL_READ,
        forbidden_detail=(
            "Active organization membership with threat intelligence read access is required"
        ),
    )
    source = (
        await db.execute(select(IntelligenceSource).where(IntelligenceSource.slug == source_slug))
    ).scalar_one_or_none()
    if not source:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Source '{source_slug}' not found",
        )

    runs = (
        (
            await db.execute(
                select(IntelSyncRun)
                .where(IntelSyncRun.source_id == source.id)
                .order_by(desc(IntelSyncRun.started_at))
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )

    return [
        IntelSyncRunOut(
            id=r.id,
            source_id=r.source_id,
            sync_mode=r.sync_mode,
            cursor_before=r.cursor_before,
            cursor_after=r.cursor_after,
            status=r.status,
            records_fetched=r.records_fetched,
            records_persisted=r.records_persisted,
            error_message=r.error_message,
            raw_payload_hash=r.raw_payload_hash,
            started_at=r.started_at,
            completed_at=r.completed_at,
        )
        for r in runs
    ]


@intel_router.get(
    "/cve/{cve_id}",
    response_model=CveThreatIntelOut,
)
async def get_cve_threat_intel_route(
    cve_id: str,
    principal: Principal = Depends(get_current_principal),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> CveThreatIntelOut:
    """Retrieve aggregated threat intelligence (KEV, EPSS, NVD, Exploit-DB, OSV) for a CVE."""
    await _require_global_intel_permission(
        db,
        principal,
        Permission.INTEL_READ,
        forbidden_detail=(
            "Active organization membership with threat intelligence read access is required"
        ),
    )
    intel = await get_cve_threat_intel(db, cve_id=cve_id)
    return CveThreatIntelOut(**intel)


@org_intel_router.post(
    "/intel/sources/{source_slug}/sync",
    response_model=IntelSyncRunOut,
    status_code=status.HTTP_200_OK,
)
async def org_sync_intelligence_source_route(
    source_slug: str,
    _rate_limited: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> IntelSyncRunOut:
    """Trigger an on-demand synchronization run for an intelligence feed from org context."""
    assert_permission(ctx.role, Permission.INTEL_MANAGE)
    try:
        run = await sync_intelligence_source(db, source_slug=source_slug)
        return IntelSyncRunOut(
            id=run.id,
            source_id=run.source_id,
            sync_mode=run.sync_mode,
            cursor_before=run.cursor_before,
            cursor_after=run.cursor_after,
            status=run.status,
            records_fetched=run.records_fetched,
            records_persisted=run.records_persisted,
            error_message=run.error_message,
            raw_payload_hash=run.raw_payload_hash,
            started_at=run.started_at,
            completed_at=run.completed_at,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@org_intel_router.get(
    "/intel/sources/{source_slug}/runs",
    response_model=list[IntelSyncRunOut],
)
async def org_list_source_sync_runs_route(
    source_slug: str,
    limit: int = Query(default=20, ge=1, le=100),
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> list[IntelSyncRunOut]:
    """List recent synchronization executions for a given feed within tenant context."""
    assert_permission(ctx.role, Permission.INTEL_READ)
    source = (
        await db.execute(select(IntelligenceSource).where(IntelligenceSource.slug == source_slug))
    ).scalar_one_or_none()
    if not source:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Source '{source_slug}' not found",
        )

    runs = (
        (
            await db.execute(
                select(IntelSyncRun)
                .where(IntelSyncRun.source_id == source.id)
                .order_by(desc(IntelSyncRun.started_at))
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )

    return [
        IntelSyncRunOut(
            id=r.id,
            source_id=r.source_id,
            sync_mode=r.sync_mode,
            cursor_before=r.cursor_before,
            cursor_after=r.cursor_after,
            status=r.status,
            records_fetched=r.records_fetched,
            records_persisted=r.records_persisted,
            error_message=r.error_message,
            raw_payload_hash=r.raw_payload_hash,
            started_at=r.started_at,
            completed_at=r.completed_at,
        )
        for r in runs
    ]


@org_intel_router.post(
    "/findings/enrich",
    response_model=IntelEnrichmentResponse,
    status_code=status.HTTP_200_OK,
)
async def batch_enrich_findings_route(
    payload: IntelEnrichmentRequest,
    _rate_limited: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> IntelEnrichmentResponse:
    """Batch enrich organization findings with active threat intelligence signals."""
    assert_permission(ctx.role, Permission.INTEL_MANAGE)
    count = await batch_enrich_org_findings(
        db,
        org_id=ctx.org_id,
        project_id=payload.project_id,
    )
    return IntelEnrichmentResponse(
        enriched_count=count,
        message=f"Successfully enriched {count} findings with threat intelligence.",
    )


@org_intel_router.get(
    "/intel/summary",
    response_model=OrgThreatIntelSummaryOut,
)
async def get_org_threat_intel_summary_route(
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> OrgThreatIntelSummaryOut:
    """Retrieve threat intelligence status and risk indicators for the organization."""
    assert_permission(ctx.role, Permission.INTEL_READ)
    summary = await get_org_threat_intel_summary(db, org_id=ctx.org_id)
    return OrgThreatIntelSummaryOut(**summary)


@org_intel_router.post(
    "/intel/exposure-search",
    response_model=ExposureSearchResponse,
    status_code=status.HTTP_200_OK,
)
async def search_exposure_intelligence_route(
    payload: ExposureSearchRequest,
    _rate_limited: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> ExposureSearchResponse:
    """Correlate live OSINT & infostealer compromises across Hudson Rock and free feeds."""
    assert_permission(ctx.role, Permission.INTEL_READ)
    result = await search_multi_source_exposure(
        db,
        org_id=ctx.org_id,
        query=payload.query,
        query_type=payload.query_type,
    )
    await record_audit_event(
        db,
        organization_id=ctx.org_id,
        actor_id=ctx.user.id,
        correlation_id=ctx.correlation_id,
        action="intel.exposure_search",
        resource_type="threat_intel",
        outcome=AuditOutcome.SUCCESS,
        metadata={
            "query": result["normalized_query"],
            "detected_type": result["detected_type"],
            "total_records": result["total_records"],
            "sources_count": len(result["sources_queried"]),
        },
    )
    return ExposureSearchResponse.model_validate(result)


@org_intel_router.post(
    "/intel/exposure-findings",
    response_model=ExposureFindingImportResponse,
    status_code=status.HTTP_201_CREATED,
)
async def import_exposure_finding_route(
    payload: ExposureFindingImportRequest,
    _rate_limited: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> ExposureFindingImportResponse:
    """Import an OSINT compromise or exposure record into a project as a tracked Finding."""
    assert_permission(ctx.role, Permission.FINDING_TRIAGE)
    finding, created = await import_exposure_as_finding(
        db,
        org_id=ctx.org_id,
        project_id=payload.project_id,
        actor_id=ctx.user.id,
        source_slug=payload.source_slug,
        category=payload.category,
        severity=payload.severity,
        title=payload.title,
        target=payload.target,
        summary=payload.summary,
        remediation=payload.remediation,
        cve_id=payload.cve_id,
    )
    await record_audit_event(
        db,
        organization_id=ctx.org_id,
        actor_id=ctx.user.id,
        correlation_id=ctx.correlation_id,
        action="intel.exposure_finding_imported",
        resource_type="finding",
        resource_id=finding.id,
        outcome=AuditOutcome.SUCCESS,
        metadata={
            "project_id": str(payload.project_id),
            "source_slug": payload.source_slug,
            "category": payload.category,
            "severity": finding.severity,
            "created": created,
        },
    )
    return ExposureFindingImportResponse(
        finding_id=finding.id,
        project_id=finding.project_id,
        created=created,
        title=finding.title,
        severity=finding.severity,
        category=finding.category,
        status=finding.status,
        message=(
            "Imported exposure record as a new tracked project finding."
            if created
            else "Updated last-seen timestamp on existing tracked project finding."
        ),
    )
