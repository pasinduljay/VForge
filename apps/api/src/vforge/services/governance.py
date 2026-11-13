"""Authorization workflow (separation of duties) and scan-profile governance services."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

from vforge_scope import DnsResolver, IntensityLevel
from sqlalchemy import and_, func, or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.auth.rbac import Permission, assert_permission
from vforge.config import Settings, get_settings
from vforge.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from vforge.models import (
    Asset,
    Authorization,
    AuthorizationStatus,
    Environment,
    RegistrationState,
    Role,
    ScanProfile,
    ScanProfileStatus,
)
from vforge.schemas import ScanProfileConfiguration
from vforge.security.signing import SnapshotSigner
from vforge.services.audit import record_audit_event
from vforge.services.scope import (
    create_signed_snapshot_for_authorization,
    validate_authorization_scope,
)


def _normalize_effective_status(auth: Authorization, now: datetime) -> Authorization:
    if auth.status == AuthorizationStatus.APPROVED.value and auth.expires_at <= now:
        auth.status = AuthorizationStatus.EXPIRED.value
    return auth


async def list_authorizations(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_role: Role,
    asset_id: uuid.UUID | None = None,
    status: AuthorizationStatus | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Authorization], int]:
    assert_permission(actor_role, Permission.AUTHORIZATION_READ)
    now = datetime.now(UTC)
    stmt = select(Authorization).where(Authorization.organization_id == org_id)
    count_stmt = (
        select(func.count())
        .select_from(Authorization)
        .where(Authorization.organization_id == org_id)
    )
    if asset_id is not None:
        stmt = stmt.where(Authorization.asset_id == asset_id)
        count_stmt = count_stmt.where(Authorization.asset_id == asset_id)
    if status is not None:
        if status == AuthorizationStatus.EXPIRED:
            cond = or_(
                Authorization.status == AuthorizationStatus.EXPIRED.value,
                and_(
                    Authorization.status == AuthorizationStatus.APPROVED.value,
                    Authorization.expires_at <= now,
                ),
            )
            stmt = stmt.where(cond)
            count_stmt = count_stmt.where(cond)
        elif status == AuthorizationStatus.APPROVED:
            cond = and_(
                Authorization.status == AuthorizationStatus.APPROVED.value,
                Authorization.expires_at > now,
            )
            stmt = stmt.where(cond)
            count_stmt = count_stmt.where(cond)
        else:
            stmt = stmt.where(Authorization.status == status.value)
            count_stmt = count_stmt.where(Authorization.status == status.value)

    total = int((await db.execute(count_stmt)).scalar_one())
    rows = list(
        (
            await db.execute(
                stmt.order_by(Authorization.created_at.desc()).limit(limit).offset(offset)
            )
        )
        .scalars()
        .all()
    )
    for item in rows:
        _normalize_effective_status(item, now)
    return rows, total


async def request_authorization(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    asset_id: uuid.UUID,
    requester_id: uuid.UUID,
    actor_role: Role,
    approved_testing_scope: dict[str, Any],
    approved_activities: list[str],
    allowed_ports: list[int] | None,
    permitted_intensity: IntensityLevel = IntensityLevel.PASSIVE,
    allow_private_networks: bool = False,
    authorization_reference: str,
    valid_from: datetime,
    expires_at: datetime,
    correlation_id: str | None,
    settings: Settings | None = None,
) -> Authorization:
    assert_permission(actor_role, Permission.AUTHORIZATION_REQUEST)
    if expires_at <= valid_from:
        raise ValidationError("expires_at must be strictly after valid_from")
    now = datetime.now(UTC)
    if expires_at <= now:
        raise ValidationError("expires_at must be in the future")

    asset_res = await db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.organization_id == org_id)
    )
    asset = asset_res.scalar_one_or_none()
    if asset is None:
        raise NotFoundError("Asset not found")
    if asset.registration_state == RegistrationState.DECOMMISSIONED.value:
        raise ConflictError("Cannot request authorization for a decommissioned asset")

    env_res = await db.execute(
        select(Environment).where(
            Environment.id == asset.environment_id,
            Environment.organization_id == org_id,
        )
    )
    env = env_res.scalar_one_or_none()
    if env is None:
        raise NotFoundError("Environment not found")

    cfg = settings or get_settings()
    validate_authorization_scope(
        asset=asset,
        approved_testing_scope=approved_testing_scope,
        approved_activities=approved_activities,
        allowed_ports=allowed_ports,
        allow_private_networks=allow_private_networks,
    )

    history_entry = {
        "event": "requested",
        "actor_id": str(requester_id),
        "timestamp": now.isoformat(),
        "reference": authorization_reference,
    }
    auth = Authorization(
        organization_id=org_id,
        project_id=env.project_id,
        environment_id=env.id,
        asset_id=asset_id,
        requested_by=requester_id,
        approved_testing_scope=approved_testing_scope,
        approved_activities=approved_activities,
        allowed_ports=allowed_ports,
        permitted_intensity=permitted_intensity.value,
        policy_version=cfg.policy_bundle_version,
        allow_private_networks=allow_private_networks,
        authorization_reference=authorization_reference.strip(),
        valid_from=valid_from,
        expires_at=expires_at,
        status=AuthorizationStatus.PENDING.value,
        audit_history=[history_entry],
    )
    db.add(auth)
    await db.flush()

    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=requester_id,
        correlation_id=correlation_id,
        action="authorization.requested",
        resource_type="authorization",
        resource_id=auth.id,
        metadata={
            "asset_id": str(asset_id),
            "project_id": str(env.project_id),
            "environment_id": str(env.id),
            "reference": auth.authorization_reference,
            "activities": approved_activities,
            "permitted_intensity": permitted_intensity.value,
            "policy_version": cfg.policy_bundle_version,
        },
    )
    return auth


async def update_authorization(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    authorization_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    approved_testing_scope: dict[str, Any] | None = None,
    approved_activities: list[str] | None = None,
    allowed_ports: list[int] | None = None,
    permitted_intensity: IntensityLevel | None = None,
    allow_private_networks: bool | None = None,
    authorization_reference: str | None = None,
    valid_from: datetime | None = None,
    expires_at: datetime | None = None,
    correlation_id: str | None = None,
    settings: Settings | None = None,
) -> Authorization:
    assert_permission(actor_role, Permission.AUTHORIZATION_REQUEST)
    auth = await get_authorization(
        db,
        org_id=org_id,
        authorization_id=authorization_id,
        actor_role=actor_role,
    )
    if auth.status in {AuthorizationStatus.REVOKED.value, AuthorizationStatus.EXPIRED.value}:
        raise ConflictError(f"Cannot modify authorization in status '{auth.status}'")

    asset = (
        await db.execute(
            select(Asset).where(Asset.id == auth.asset_id, Asset.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if asset is None:
        raise NotFoundError("Asset not found")

    cfg = settings or get_settings()
    now = datetime.now(UTC)

    next_scope = (
        approved_testing_scope
        if approved_testing_scope is not None
        else auth.approved_testing_scope
    )
    next_activities = (
        approved_activities if approved_activities is not None else auth.approved_activities
    )
    next_ports = allowed_ports if allowed_ports is not None else auth.allowed_ports
    next_private = (
        allow_private_networks
        if allow_private_networks is not None
        else auth.allow_private_networks
    )
    next_valid_from = valid_from if valid_from is not None else auth.valid_from
    next_expires_at = expires_at if expires_at is not None else auth.expires_at

    if next_expires_at <= next_valid_from:
        raise ValidationError("expires_at must be strictly after valid_from")
    if next_expires_at <= now:
        raise ValidationError("expires_at must be in the future")

    validate_authorization_scope(
        asset=asset,
        approved_testing_scope=next_scope,
        approved_activities=next_activities,
        allowed_ports=next_ports,
        allow_private_networks=next_private,
    )

    was_non_pending = auth.status != AuthorizationStatus.PENDING.value
    auth.approved_testing_scope = next_scope
    auth.approved_activities = next_activities
    auth.allowed_ports = next_ports
    if permitted_intensity is not None:
        auth.permitted_intensity = permitted_intensity.value
    auth.allow_private_networks = next_private
    if authorization_reference is not None:
        auth.authorization_reference = authorization_reference.strip()
    auth.valid_from = next_valid_from
    auth.expires_at = next_expires_at
    auth.policy_version = cfg.policy_bundle_version

    if was_non_pending:
        # Modifying scope or terms requires fresh second-person approval & new snapshot.
        auth.status = AuthorizationStatus.PENDING.value
        auth.approved_by = None
        auth.approved_at = None
        auth.decision_reason = None

    auth.audit_history = [
        *auth.audit_history,
        {
            "event": "updated",
            "actor_id": str(actor_id),
            "timestamp": now.isoformat(),
            "reapproval_required": was_non_pending,
        },
    ]
    await db.flush()
    await db.refresh(auth)

    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        action="authorization.updated",
        resource_type="authorization",
        resource_id=auth.id,
        metadata={
            "asset_id": str(auth.asset_id),
            "reapproval_required": was_non_pending,
            "policy_version": auth.policy_version,
        },
    )
    return auth


async def get_authorization(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    authorization_id: uuid.UUID,
    actor_role: Role,
) -> Authorization:
    assert_permission(actor_role, Permission.AUTHORIZATION_READ)
    res = await db.execute(
        select(Authorization).where(
            Authorization.id == authorization_id,
            Authorization.organization_id == org_id,
        )
    )
    auth = res.scalar_one_or_none()
    if auth is None:
        raise NotFoundError("Authorization not found")
    return _normalize_effective_status(auth, datetime.now(UTC))


async def approve_authorization(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    authorization_id: uuid.UUID,
    approver_id: uuid.UUID,
    actor_role: Role,
    reason: str | None,
    correlation_id: str | None,
    settings: Settings | None = None,
    dns_resolver: DnsResolver | None = None,
    signer: SnapshotSigner | None = None,
) -> Authorization:
    assert_permission(actor_role, Permission.AUTHORIZATION_APPROVE)
    auth = await get_authorization(
        db,
        org_id=org_id,
        authorization_id=authorization_id,
        actor_role=actor_role,
    )

    if auth.requested_by == approver_id:
        raise ForbiddenError(
            "Separation of duties violation: requester cannot approve their own authorization"
        )
    if auth.status != AuthorizationStatus.PENDING.value:
        raise ConflictError(f"Cannot approve authorization in status '{auth.status}'")

    now = datetime.now(UTC)
    if auth.expires_at <= now:
        auth.status = AuthorizationStatus.EXPIRED.value
        await db.flush()
        raise ConflictError("Authorization validity window has already expired")

    asset = (
        await db.execute(
            select(Asset).where(Asset.id == auth.asset_id, Asset.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if asset is None:
        raise NotFoundError("Asset not found")
    if asset.registration_state == RegistrationState.DECOMMISSIONED.value:
        raise ConflictError("Cannot approve authorization for a decommissioned asset")

    cfg = settings or get_settings()
    auth.approved_by = approver_id
    auth.approved_at = now
    auth.decision_reason = reason.strip() if reason else None
    auth.status = AuthorizationStatus.APPROVED.value
    auth.policy_version = cfg.policy_bundle_version

    snapshot = await create_signed_snapshot_for_authorization(
        db,
        auth=auth,
        asset=asset,
        actor_id=approver_id,
        correlation_id=correlation_id,
        settings=cfg,
        dns_resolver=dns_resolver,
        signer=signer,
    )

    auth.audit_history = [
        *auth.audit_history,
        {
            "event": "approved",
            "actor_id": str(approver_id),
            "timestamp": now.isoformat(),
            "reason": auth.decision_reason,
            "snapshot_id": str(snapshot.id),
            "snapshot_version": snapshot.snapshot_version,
        },
    ]
    await db.flush()
    await db.refresh(auth)

    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=approver_id,
        correlation_id=correlation_id,
        action="authorization.approved",
        resource_type="authorization",
        resource_id=auth.id,
        metadata={
            "asset_id": str(auth.asset_id),
            "requested_by": str(auth.requested_by),
            "snapshot_id": str(snapshot.id),
            "snapshot_version": snapshot.snapshot_version,
            "policy_version": auth.policy_version,
        },
    )
    return auth


async def reject_authorization(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    authorization_id: uuid.UUID,
    approver_id: uuid.UUID,
    actor_role: Role,
    reason: str | None,
    correlation_id: str | None,
) -> Authorization:
    assert_permission(actor_role, Permission.AUTHORIZATION_APPROVE)
    auth = await get_authorization(
        db,
        org_id=org_id,
        authorization_id=authorization_id,
        actor_role=actor_role,
    )
    if auth.status != AuthorizationStatus.PENDING.value:
        raise ConflictError(f"Cannot reject authorization in status '{auth.status}'")

    now = datetime.now(UTC)
    auth.approved_by = approver_id if approver_id != auth.requested_by else None
    auth.decision_reason = reason.strip() if reason else None
    auth.status = AuthorizationStatus.REJECTED.value
    auth.audit_history = [
        *auth.audit_history,
        {
            "event": "rejected",
            "actor_id": str(approver_id),
            "timestamp": now.isoformat(),
            "reason": auth.decision_reason,
        },
    ]
    await db.flush()
    await db.refresh(auth)

    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=approver_id,
        correlation_id=correlation_id,
        action="authorization.rejected",
        resource_type="authorization",
        resource_id=auth.id,
        metadata={"asset_id": str(auth.asset_id)},
    )
    return auth


async def revoke_authorization(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    authorization_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    reason: str,
    correlation_id: str | None,
) -> Authorization:
    assert_permission(actor_role, Permission.AUTHORIZATION_REVOKE)
    auth = await get_authorization(
        db,
        org_id=org_id,
        authorization_id=authorization_id,
        actor_role=actor_role,
    )
    if auth.status not in {
        AuthorizationStatus.PENDING.value,
        AuthorizationStatus.APPROVED.value,
    }:
        raise ConflictError(f"Cannot revoke authorization in status '{auth.status}'")

    now = datetime.now(UTC)
    auth.revoked_by = actor_id
    auth.revoked_at = now
    auth.revocation_reason = reason.strip()
    auth.status = AuthorizationStatus.REVOKED.value
    auth.audit_history = [
        *auth.audit_history,
        {
            "event": "revoked",
            "actor_id": str(actor_id),
            "timestamp": now.isoformat(),
            "reason": auth.revocation_reason,
        },
    ]
    await db.flush()
    await db.refresh(auth)

    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        action="authorization.revoked",
        resource_type="authorization",
        resource_id=auth.id,
        metadata={"asset_id": str(auth.asset_id), "reason": auth.revocation_reason},
    )
    return auth


# --- Scan Profiles ---


async def list_scan_profiles(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_role: Role,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[ScanProfile], int]:
    assert_permission(actor_role, Permission.SCAN_PROFILE_READ)
    count_res = await db.execute(
        select(func.count()).select_from(ScanProfile).where(ScanProfile.organization_id == org_id)
    )
    total = int(count_res.scalar_one())
    rows = list(
        (
            await db.execute(
                select(ScanProfile)
                .where(ScanProfile.organization_id == org_id)
                .order_by(ScanProfile.name.asc(), ScanProfile.version.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return rows, total


async def create_scan_profile(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    name: str,
    configuration: ScanProfileConfiguration,
    status: ScanProfileStatus,
    correlation_id: str | None,
) -> ScanProfile:
    assert_permission(actor_role, Permission.SCAN_PROFILE_MANAGE)
    clean_name = name.strip()

    max_ver_res = await db.execute(
        select(func.max(ScanProfile.version)).where(
            ScanProfile.organization_id == org_id,
            ScanProfile.name == clean_name,
        )
    )
    current_max = max_ver_res.scalar_one_or_none()
    next_version = int(current_max) + 1 if current_max is not None else 1

    profile = ScanProfile(
        organization_id=org_id,
        name=clean_name,
        version=next_version,
        configuration=configuration.model_dump(mode="json"),
        status=status.value,
    )
    db.add(profile)
    try:
        await db.flush()
    except IntegrityError as exc:
        raise ConflictError("Scan profile version conflict") from exc

    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        action="scan_profile.created",
        resource_type="scan_profile",
        resource_id=profile.id,
        metadata={"name": clean_name, "version": next_version, "status": status.value},
    )
    return profile


async def update_scan_profile(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    scan_profile_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    status: ScanProfileStatus | None,
    configuration: ScanProfileConfiguration | None,
    correlation_id: str | None,
) -> ScanProfile:
    assert_permission(actor_role, Permission.SCAN_PROFILE_MANAGE)
    res = await db.execute(
        select(ScanProfile).where(
            ScanProfile.id == scan_profile_id,
            ScanProfile.organization_id == org_id,
        )
    )
    profile = res.scalar_one_or_none()
    if profile is None:
        raise NotFoundError("Scan profile not found")

    if configuration is not None:
        profile.configuration = configuration.model_dump(mode="json")
    if status is not None:
        profile.status = status.value

    await db.flush()
    await db.refresh(profile)
    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        action="scan_profile.updated",
        resource_type="scan_profile",
        resource_id=profile.id,
        metadata={"name": profile.name, "version": profile.version, "status": profile.status},
    )
    return profile
