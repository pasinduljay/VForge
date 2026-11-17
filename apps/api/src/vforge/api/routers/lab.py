"""Control-plane API routes for Phase 13 Isolated Learning Lab & Self-Scan Verification."""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.api.deps import (
    TenantContext,
    enforce_sensitive_rate_limit,
    get_db,
    get_tenant_context,
)
from vforge.auth.rbac import Permission, assert_permission
from vforge.config import Settings, get_settings
from vforge.lab.service import (
    get_lab_overview,
    list_challenges,
    provision_lab_workspace,
    record_challenge_remediation,
    reset_lab_workspace,
    run_vforge_self_scan,
    update_lab_consent,
    validate_challenge_safely,
)
from vforge.schemas import (
    LabAuditEventOut,
    LabChallengeOut,
    LabChallengeProgressOut,
    LabComposeIsolationOut,
    LabOverviewOut,
    LabRemediationRequest,
    LabSelfScanOut,
    LabSelfScanRequest,
    LabValidateRequest,
    LabValidateResponse,
    LabValidationRunOut,
    LabWorkspaceConsentRequest,
    LabWorkspaceCreateRequest,
    LabWorkspaceOut,
)

router = APIRouter(prefix="/api/v1/organizations/{org_id}/lab", tags=["learning-lab"])


@router.get("/overview", response_model=LabOverviewOut)
async def lab_overview(
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> LabOverviewOut:
    assert_permission(ctx.role, Permission.LAB_READ)
    overview = await get_lab_overview(db, organization_id=ctx.org_id)
    return LabOverviewOut(
        challenges=[LabChallengeOut.model_validate(c) for c in overview["challenges"]],
        workspaces=[LabWorkspaceOut.model_validate(w) for w in overview["workspaces"]],
        progress=[LabChallengeProgressOut.model_validate(p) for p in overview["progress"]],
        validation_runs=[
            LabValidationRunOut.model_validate(r) for r in overview["validation_runs"]
        ],
        self_scans=[LabSelfScanOut.model_validate(s) for s in overview["self_scans"]],
        audit_events=[LabAuditEventOut.model_validate(a) for a in overview["audit_events"]],
        compose_isolation=LabComposeIsolationOut.model_validate(overview["compose_isolation"]),
    )


@router.get("/challenges", response_model=list[LabChallengeOut])
async def lab_challenges(
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> list[LabChallengeOut]:
    assert_permission(ctx.role, Permission.LAB_READ)
    rows = await list_challenges(db)
    return [LabChallengeOut.model_validate(row) for row in rows]


@router.post(
    "/workspaces",
    response_model=LabWorkspaceOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def create_lab_workspace(
    payload: LabWorkspaceCreateRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> LabWorkspaceOut:
    assert_permission(ctx.role, Permission.LAB_MANAGE)
    ws = await provision_lab_workspace(
        db,
        organization_id=ctx.org_id,
        environment_slug=payload.environment_slug,
        display_name=payload.display_name,
        consent_to_persist_progress=payload.consent_to_persist_progress,
        disposable_account_prefix=payload.disposable_account_prefix,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
        actor_role=ctx.role.value,
        settings=settings,
    )
    out = LabWorkspaceOut.model_validate(ws)
    await db.commit()
    return out


@router.post(
    "/workspaces/{workspace_id}/consent",
    response_model=LabWorkspaceOut,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def update_workspace_consent(
    workspace_id: uuid.UUID,
    payload: LabWorkspaceConsentRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> LabWorkspaceOut:
    assert_permission(ctx.role, Permission.LAB_MANAGE)
    ws = await update_lab_consent(
        db,
        organization_id=ctx.org_id,
        workspace_id=workspace_id,
        consent_to_persist_progress=payload.consent_to_persist_progress,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
        actor_role=ctx.role.value,
        settings=settings,
    )
    out = LabWorkspaceOut.model_validate(ws)
    await db.commit()
    return out


@router.post(
    "/workspaces/{workspace_id}/reset",
    response_model=LabWorkspaceOut,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def reset_workspace_route(
    workspace_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> LabWorkspaceOut:
    assert_permission(ctx.role, Permission.LAB_MANAGE)
    ws = await reset_lab_workspace(
        db,
        organization_id=ctx.org_id,
        workspace_id=workspace_id,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
        actor_role=ctx.role.value,
        settings=settings,
    )
    out = LabWorkspaceOut.model_validate(ws)
    await db.commit()
    return out


@router.post(
    "/workspaces/{workspace_id}/validate",
    response_model=LabValidateResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def validate_challenge_route(
    workspace_id: uuid.UUID,
    payload: LabValidateRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> LabValidateResponse:
    assert_permission(ctx.role, Permission.LAB_PRACTICE)
    run, progress = await validate_challenge_safely(
        db,
        organization_id=ctx.org_id,
        workspace_id=workspace_id,
        challenge_id=payload.challenge_id,
        target_url=payload.target_url,
        tool_slug=payload.tool_slug,
        action_type=payload.action_type,
        disposable_identity_used=payload.disposable_identity_used,
        observed_evidence=payload.observed_evidence,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
        actor_role=ctx.role.value,
        settings=settings,
    )
    out = LabValidateResponse(
        validation_run=LabValidationRunOut.model_validate(run),
        progress=(LabChallengeProgressOut.model_validate(progress) if progress else None),
    )
    await db.commit()
    return out


@router.post(
    "/workspaces/{workspace_id}/remediate",
    response_model=LabChallengeProgressOut,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def record_remediation_route(
    workspace_id: uuid.UUID,
    payload: LabRemediationRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> LabChallengeProgressOut:
    assert_permission(ctx.role, Permission.LAB_PRACTICE)
    progress = await record_challenge_remediation(
        db,
        organization_id=ctx.org_id,
        workspace_id=workspace_id,
        challenge_id=payload.challenge_id,
        remediation_notes=payload.remediation_notes,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
        actor_role=ctx.role.value,
        settings=settings,
    )
    out = LabChallengeProgressOut.model_validate(progress)
    await db.commit()
    return out


@router.post(
    "/self-scans",
    response_model=LabSelfScanOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def trigger_self_scan_route(
    payload: LabSelfScanRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> LabSelfScanOut:
    assert_permission(ctx.role, Permission.LAB_MANAGE)
    scan = await run_vforge_self_scan(
        db,
        organization_id=ctx.org_id,
        target_component=payload.target_component,
        profile_name=payload.profile_name,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
        actor_role=ctx.role.value,
        settings=settings,
    )
    out = LabSelfScanOut.model_validate(scan)
    await db.commit()
    return out
