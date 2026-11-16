"""Control-plane API routes for Phase 10 Release & Update Lifecycle Management."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, status
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
from vforge.auth.rbac import Permission, assert_permission
from vforge.config import Settings, get_settings
from vforge.errors import ForbiddenError
from vforge.lifecycle.monitor import detect_candidates_from_image_locks
from vforge.lifecycle.pipeline import (
    approve_update_candidate,
    promote_feed_snapshot,
    promote_update_candidate,
    record_validation_results,
    register_feed_snapshot,
    register_update_candidate,
    resolve_active_tool_pins,
    rollback_feed_snapshot,
    rollback_tool_version,
    run_automated_validation_gates,
)
from vforge.models import (
    FeedSnapshot,
    Membership,
    MembershipStatus,
    Role,
    ToolCatalog,
    ToolUpdate,
    ToolVersion,
    UpdateAuditEvent,
    UpdateTestResult,
)
from vforge.models.enums import UpdateChannel, UpdateStream, UpdateTestOutcome
from vforge.schemas import (
    CandidateRegisterRequest,
    DetectLocksResponseOut,
    FeedSnapshotOut,
    FeedSnapshotPromoteRequest,
    FeedSnapshotRegisterRequest,
    FeedSnapshotRollbackRequest,
    RollbackResponseOut,
    ToolCatalogOut,
    ToolRollbackRequest,
    ToolUpdateOut,
    ToolVersionOut,
    UpdateApproveRequest,
    UpdateAuditEventOut,
    UpdateLifecycleOverviewOut,
    UpdatePromoteRequest,
    UpdateTestResultOut,
    UpdateValidateRequest,
)

# Platform-wide release & update management mutations and full audit stream
platform_updates_router = APIRouter(
    prefix="/api/v1/updates",
    tags=["updates"],
)

# Organization-scoped read-only overview of active pins, streams, and sanitized org audit events
org_updates_router = APIRouter(
    prefix="/api/v1/organizations/{org_id}/updates",
    tags=["updates"],
)


async def _require_platform_update_operator(
    principal: Principal = Depends(get_current_principal),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> Principal:
    """Require an operator with active admin/owner/security_lead privileges."""
    if settings.platform_admin_emails:
        allowed = {
            email.strip().lower() for email in settings.platform_admin_emails if email.strip()
        }
        if principal.user.email.strip().lower() not in allowed:
            raise ForbiddenError("Platform administrator privileges required for global updates")

    membership = (
        (
            await db.execute(
                select(Membership).where(
                    Membership.user_id == principal.user.id,
                    Membership.status == MembershipStatus.ACTIVE.value,
                    Membership.role.in_(
                        [Role.OWNER.value, Role.ADMIN.value, Role.SECURITY_LEAD.value]
                    ),
                )
            )
        )
        .scalars()
        .first()
    )
    if membership is None:
        raise ForbiddenError("Update management requires Owner, Admin, or Security Lead privileges")
    return principal


def _version_to_out(ver: ToolVersion) -> ToolVersionOut:
    return ToolVersionOut(
        id=ver.id,
        tool_id=ver.tool_id,
        version_tag=ver.version_tag,
        image_repository=ver.image_repository,
        image_digest=ver.image_digest,
        adapter_version=ver.adapter_version,
        approval_channel=ver.approval_channel,
        is_active_stable=ver.is_active_stable,
        is_active_canary=ver.is_active_canary,
        previous_stable_version_id=ver.previous_stable_version_id,
        signature_verified=ver.signature_verified,
        sbom_digest=ver.sbom_digest,
        release_notes_url=ver.release_notes_url,
        promoted_at=ver.promoted_at,
        rolled_back_at=ver.rolled_back_at,
        created_at=ver.created_at,
    )


def _feed_to_out(snap: FeedSnapshot) -> FeedSnapshotOut:
    return FeedSnapshotOut(
        id=snap.id,
        tool_id=snap.tool_id,
        feed_slug=snap.feed_slug,
        stream=snap.stream,
        update_channel=snap.update_channel,
        snapshot_tag=snap.snapshot_tag,
        archive_sha256=snap.archive_sha256,
        schema_version=snap.schema_version,
        record_count=snap.record_count,
        approval_channel=snap.approval_channel,
        is_active_stable=snap.is_active_stable,
        is_active_canary=snap.is_active_canary,
        previous_stable_snapshot_id=snap.previous_stable_snapshot_id,
        source_url=snap.source_url,
        promoted_at=snap.promoted_at,
        rolled_back_at=snap.rolled_back_at,
        created_at=snap.created_at,
    )


async def _serialize_update(db: AsyncSession, row: ToolUpdate) -> ToolUpdateOut:
    await db.refresh(row)
    tool = (await db.execute(select(ToolCatalog).where(ToolCatalog.id == row.tool_id))).scalar_one()
    ver = (
        await db.execute(select(ToolVersion).where(ToolVersion.id == row.candidate_version_id))
    ).scalar_one()
    await db.refresh(ver)
    tests = (
        (
            await db.execute(
                select(UpdateTestResult)
                .where(UpdateTestResult.update_id == row.id)
                .order_by(UpdateTestResult.executed_at.asc())
            )
        )
        .scalars()
        .all()
    )
    return ToolUpdateOut(
        id=row.id,
        tool_id=row.tool_id,
        tool_slug=tool.tool_slug,
        display_name=tool.display_name,
        candidate_version_id=row.candidate_version_id,
        version_tag=ver.version_tag,
        image_digest=ver.image_digest,
        previous_version_id=row.previous_version_id,
        stream=row.stream,
        update_channel=row.update_channel,
        change_type=row.change_type,
        status=row.status,
        is_emergency=row.is_emergency,
        emergency_justification=row.emergency_justification,
        detected_from=row.detected_from,
        approved_at=row.approved_at,
        promoted_at=row.promoted_at,
        rolled_back_at=row.rolled_back_at,
        rollback_reason=row.rollback_reason,
        rejection_reason=row.rejection_reason,
        test_results=[
            UpdateTestResultOut(
                id=t.id,
                update_id=t.update_id,
                tool_version_id=t.tool_version_id,
                test_category=t.test_category,
                outcome=t.outcome,
                summary=t.summary,
                details_json=t.details_json,
                executed_by=t.executed_by,
                executed_at=t.executed_at,
            )
            for t in tests
        ],
        created_at=row.created_at,
        updated_at=row.updated_at,
    )


async def _build_overview(
    db: AsyncSession,
    *,
    allowed_actor_ids: set[uuid.UUID] | None = None,
) -> UpdateLifecycleOverviewOut:
    tools = (
        (await db.execute(select(ToolCatalog).order_by(ToolCatalog.stream, ToolCatalog.tool_slug)))
        .scalars()
        .all()
    )
    versions = (
        (await db.execute(select(ToolVersion).order_by(desc(ToolVersion.created_at))))
        .scalars()
        .all()
    )
    updates = (
        (await db.execute(select(ToolUpdate).order_by(desc(ToolUpdate.created_at)).limit(100)))
        .scalars()
        .all()
    )
    feeds = (
        (await db.execute(select(FeedSnapshot).order_by(desc(FeedSnapshot.created_at)).limit(100)))
        .scalars()
        .all()
    )
    audits = (
        (
            await db.execute(
                select(UpdateAuditEvent).order_by(desc(UpdateAuditEvent.occurred_at)).limit(100)
            )
        )
        .scalars()
        .all()
    )

    stable_by_tool: dict[uuid.UUID, dict[str, Any]] = {}
    canary_by_tool: dict[uuid.UUID, dict[str, Any]] = {}
    for v in versions:
        summary = {
            "id": str(v.id),
            "version_tag": v.version_tag,
            "image_repository": v.image_repository,
            "image_digest": v.image_digest,
            "approval_channel": v.approval_channel,
        }
        if v.is_active_stable:
            stable_by_tool[v.tool_id] = summary
        if v.is_active_canary:
            canary_by_tool[v.tool_id] = summary

    pins = await resolve_active_tool_pins(db, use_canary=False)
    serialized_updates = [await _serialize_update(db, row) for row in updates]

    def _safe_actor_email(ev: UpdateAuditEvent) -> str | None:
        if allowed_actor_ids is None or ev.actor_user_id is None:
            return ev.actor_email
        if ev.actor_user_id in allowed_actor_ids:
            return ev.actor_email
        return "[redacted]"

    return UpdateLifecycleOverviewOut(
        streams=[s.value for s in UpdateStream],
        channels=[c.value for c in UpdateChannel],
        tools=[
            ToolCatalogOut(
                id=t.id,
                tool_slug=t.tool_slug,
                display_name=t.display_name,
                stream=t.stream,
                update_channel=t.update_channel,
                adapter_family=t.adapter_family,
                source_registry=t.source_registry,
                automerge_allowed=t.automerge_allowed,
                is_active=t.is_active,
                active_stable_version=stable_by_tool.get(t.id),
                active_canary_version=canary_by_tool.get(t.id),
                created_at=t.created_at,
                updated_at=t.updated_at,
            )
            for t in tools
        ],
        versions=[_version_to_out(v) for v in versions],
        updates=serialized_updates,
        feed_snapshots=[_feed_to_out(f) for f in feeds],
        audit_events=[
            UpdateAuditEventOut(
                id=a.id,
                update_id=a.update_id,
                tool_id=a.tool_id,
                tool_version_id=a.tool_version_id,
                feed_snapshot_id=a.feed_snapshot_id,
                action=a.action,
                actor_email=_safe_actor_email(a),
                reason=a.reason,
                details_json=a.details_json,
                occurred_at=a.occurred_at,
            )
            for a in audits
        ],
        active_pins=pins.provenance_manifest,
    )


@org_updates_router.get(
    "/overview",
    response_model=UpdateLifecycleOverviewOut,
)
async def get_updates_overview_route(
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> UpdateLifecycleOverviewOut:
    """Read-only org overview of active pins, streams, and org-safe audit events."""
    assert_permission(ctx.role, Permission.UPDATE_READ)
    org_member_ids = set(
        (
            await db.execute(
                select(Membership.user_id).where(
                    Membership.organization_id == ctx.org_id,
                    Membership.status == MembershipStatus.ACTIVE.value,
                )
            )
        )
        .scalars()
        .all()
    )
    return await _build_overview(db, allowed_actor_ids=org_member_ids)


@platform_updates_router.get(
    "/overview",
    response_model=UpdateLifecycleOverviewOut,
)
async def get_platform_updates_overview_route(
    _operator: Principal = Depends(_require_platform_update_operator),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> UpdateLifecycleOverviewOut:
    """Platform-operator overview of all four update streams, pins, and full audit trail."""
    return await _build_overview(db, allowed_actor_ids=None)


@platform_updates_router.post(
    "/detect",
    response_model=DetectLocksResponseOut,
)
async def detect_image_lock_updates_route(
    _rate_limited: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
    operator: Principal = Depends(_require_platform_update_operator),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> DetectLocksResponseOut:
    """Scan repository image-lock manifests for un-registered digest candidates."""
    candidates = await detect_candidates_from_image_locks(
        db, detected_from=f"api:{operator.user.email}"
    )
    return DetectLocksResponseOut(detected_count=len(candidates), candidates=candidates)


@platform_updates_router.post(
    "/candidates",
    response_model=ToolUpdateOut,
    status_code=status.HTTP_201_CREATED,
)
async def register_update_candidate_route(
    payload: CandidateRegisterRequest,
    _rate_limited: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
    operator: Principal = Depends(_require_platform_update_operator),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> ToolUpdateOut:
    """Register a digest-pinned candidate update."""
    _tool, _ver, update_row = await register_update_candidate(
        db,
        tool_slug=payload.tool_slug,
        version_tag=payload.version_tag,
        image_repository=payload.image_repository,
        image_digest=payload.image_digest,
        adapter_version=payload.adapter_version,
        change_type=payload.change_type,
        detected_from=payload.detected_from,
        release_notes_url=payload.release_notes_url,
        sbom_digest=payload.sbom_digest,
        signature_verified=payload.signature_verified,
        is_emergency=payload.is_emergency,
        emergency_justification=payload.emergency_justification,
        actor_user_id=operator.user.id,
        actor_email=operator.user.email,
    )
    return await _serialize_update(db, update_row)


@platform_updates_router.post(
    "/{update_id}/validate",
    response_model=ToolUpdateOut,
)
async def validate_update_candidate_route(
    update_id: uuid.UUID,
    payload: UpdateValidateRequest,
    _rate_limited: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
    operator: Principal = Depends(_require_platform_update_operator),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> ToolUpdateOut:
    """Execute Phase 10 server-side verification gates (or record operator failure overrides)."""
    if payload.tests:
        for item in payload.tests:
            if item.outcome.strip().lower() == UpdateTestOutcome.PASSED.value:
                raise ForbiddenError(
                    "Client-supplied PASSED gate attestations are forbidden; "
                    "execute server validation gates"
                )
        update_row = await record_validation_results(
            db,
            update_id=update_id,
            tests=[item.model_dump() for item in payload.tests],
            executed_by=operator.user.email,
            actor_user_id=operator.user.id,
            actor_email=operator.user.email,
        )
    else:
        update_row = await run_automated_validation_gates(
            db,
            update_id=update_id,
            executed_by=operator.user.email,
            actor_user_id=operator.user.id,
            actor_email=operator.user.email,
            simulate_failure_gate=payload.simulate_failure_gate,
            skip_regression_corpus=payload.skip_regression_corpus,
        )
    return await _serialize_update(db, update_row)


@platform_updates_router.post(
    "/{update_id}/approve",
    response_model=ToolUpdateOut,
)
async def approve_update_candidate_route(
    update_id: uuid.UUID,
    payload: UpdateApproveRequest,
    _rate_limited: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
    operator: Principal = Depends(_require_platform_update_operator),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> ToolUpdateOut:
    """Approve a validated candidate (or emergency security update with audit justification)."""
    update_row = await approve_update_candidate(
        db,
        update_id=update_id,
        actor_user_id=operator.user.id,
        actor_email=operator.user.email,
        is_emergency=payload.is_emergency,
        emergency_justification=payload.emergency_justification,
    )
    return await _serialize_update(db, update_row)


@platform_updates_router.post(
    "/{update_id}/promote",
    response_model=ToolUpdateOut,
)
async def promote_update_candidate_route(
    update_id: uuid.UUID,
    payload: UpdatePromoteRequest,
    _rate_limited: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
    operator: Principal = Depends(_require_platform_update_operator),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> ToolUpdateOut:
    """Promote an approved update to canary or stable channel."""
    update_row = await promote_update_candidate(
        db,
        update_id=update_id,
        target_channel=payload.target_channel,
        actor_user_id=operator.user.id,
        actor_email=operator.user.email,
        reason=payload.reason,
    )
    return await _serialize_update(db, update_row)


@platform_updates_router.post(
    "/tools/{tool_slug}/rollback",
    response_model=RollbackResponseOut,
)
async def rollback_tool_version_route(
    tool_slug: str,
    payload: ToolRollbackRequest,
    _rate_limited: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
    operator: Principal = Depends(_require_platform_update_operator),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> RollbackResponseOut:
    """Instant zero-rebuild rollback of active canary or stable version for a tool."""
    demoted, restored = await rollback_tool_version(
        db,
        tool_slug=tool_slug,
        reason=payload.reason,
        actor_user_id=operator.user.id,
        actor_email=operator.user.email,
        target_version_id=payload.target_version_id,
        channel=payload.channel,
    )
    return RollbackResponseOut(
        demoted_version=_version_to_out(demoted),
        restored_version=_version_to_out(restored) if restored else None,
    )


@platform_updates_router.post(
    "/feeds",
    response_model=FeedSnapshotOut,
    status_code=status.HTTP_201_CREATED,
)
async def register_feed_snapshot_route(
    payload: FeedSnapshotRegisterRequest,
    _rate_limited: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
    _operator: Principal = Depends(_require_platform_update_operator),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> FeedSnapshotOut:
    """Register a versioned vulnerability database or rule/template snapshot."""
    snap = await register_feed_snapshot(
        db,
        tool_slug=payload.tool_slug,
        feed_slug=payload.feed_slug,
        snapshot_tag=payload.snapshot_tag,
        archive_sha256=payload.archive_sha256,
        schema_version=payload.schema_version,
        record_count=payload.record_count,
        source_url=payload.source_url,
    )
    return _feed_to_out(snap)


@platform_updates_router.post(
    "/feeds/{snapshot_id}/promote",
    response_model=FeedSnapshotOut,
)
async def promote_feed_snapshot_route(
    snapshot_id: uuid.UUID,
    payload: FeedSnapshotPromoteRequest,
    _rate_limited: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
    operator: Principal = Depends(_require_platform_update_operator),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> FeedSnapshotOut:
    """Promote a feed snapshot to canary or stable."""
    snap = await promote_feed_snapshot(
        db,
        snapshot_id=snapshot_id,
        target_channel=payload.target_channel,
        actor_user_id=operator.user.id,
        actor_email=operator.user.email,
        reason=payload.reason,
    )
    return _feed_to_out(snap)


@platform_updates_router.post(
    "/feeds/{feed_slug}/rollback",
    response_model=FeedSnapshotOut,
)
async def rollback_feed_snapshot_route(
    feed_slug: str,
    payload: FeedSnapshotRollbackRequest,
    _rate_limited: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
    operator: Principal = Depends(_require_platform_update_operator),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> FeedSnapshotOut:
    """Instant rollback of an active stable feed snapshot to its previous snapshot."""
    _demoted, restored = await rollback_feed_snapshot(
        db,
        feed_slug=feed_slug,
        reason=payload.reason,
        actor_user_id=operator.user.id,
        actor_email=operator.user.email,
    )
    return _feed_to_out(restored)
