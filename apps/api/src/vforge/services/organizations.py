"""Organization and membership domain services."""

from __future__ import annotations

import uuid

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.auth.rbac import Permission, assert_permission
from vforge.db import set_db_context
from vforge.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from vforge.models import (
    AppUser,
    Membership,
    MembershipStatus,
    Organization,
    OrgStatus,
    Role,
    UserStatus,
)
from vforge.security.validators import validate_slug
from vforge.services.audit import record_audit_event


async def list_user_memberships(
    db: AsyncSession,
    *,
    user_id: uuid.UUID,
) -> list[tuple[Membership, Organization]]:
    """Return active memberships and organizations for `user_id`."""
    await set_db_context(db, user_id=user_id)
    stmt = (
        select(Membership, Organization)
        .join(Organization, Organization.id == Membership.organization_id)
        .where(
            Membership.user_id == user_id,
            Membership.status == MembershipStatus.ACTIVE.value,
        )
        .order_by(Organization.name.asc())
    )
    res = await db.execute(stmt)
    return [(row[0], row[1]) for row in res.all()]


async def create_organization(
    db: AsyncSession,
    *,
    user_id: uuid.UUID,
    name: str,
    slug: str,
    correlation_id: str | None,
) -> Organization:
    """Create a new organization and assign the creator as initial active owner."""
    clean_name = name.strip()
    if len(clean_name) < 2:
        raise ValidationError("Organization name must be at least 2 characters")
    clean_slug = validate_slug(slug)

    org_id = uuid.uuid4()
    await set_db_context(db, org_id=org_id, user_id=user_id)

    org = Organization(
        id=org_id,
        name=clean_name,
        slug=clean_slug,
        status=OrgStatus.ACTIVE.value,
    )
    db.add(org)
    try:
        await db.flush()
    except IntegrityError as exc:
        raise ConflictError("Organization slug already exists") from exc

    membership = Membership(
        organization_id=org.id,
        user_id=user_id,
        role=Role.OWNER.value,
        status=MembershipStatus.ACTIVE.value,
    )
    db.add(membership)
    await db.flush()

    await record_audit_event(
        db,
        organization_id=org.id,
        actor_id=user_id,
        correlation_id=correlation_id,
        action="organization.created",
        resource_type="organization",
        resource_id=org.id,
        metadata={"slug": clean_slug},
    )
    return org


async def get_organization(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_role: Role,
) -> Organization:
    """Fetch organization details under active tenant context."""
    assert_permission(actor_role, Permission.ORG_READ)
    res = await db.execute(select(Organization).where(Organization.id == org_id))
    org = res.scalar_one_or_none()
    if org is None:
        raise NotFoundError("Organization not found")
    return org


async def update_organization(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    name: str | None,
    status: OrgStatus | None,
    correlation_id: str | None,
) -> Organization:
    """Update organization attributes with RBAC and audit logging."""
    if status == OrgStatus.ARCHIVED:
        assert_permission(actor_role, Permission.ORG_DELETE)
    else:
        assert_permission(actor_role, Permission.ORG_UPDATE)

    res = await db.execute(select(Organization).where(Organization.id == org_id))
    org = res.scalar_one_or_none()
    if org is None:
        raise NotFoundError("Organization not found")

    changes: dict[str, str] = {}
    if name is not None:
        clean_name = name.strip()
        if len(clean_name) < 2:
            raise ValidationError("Organization name must be at least 2 characters")
        org.name = clean_name
        changes["name"] = clean_name
    if status is not None:
        org.status = status.value
        changes["status"] = status.value

    await db.flush()
    await db.refresh(org)
    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        action="organization.updated",
        resource_type="organization",
        resource_id=org_id,
        metadata=changes,
    )
    return org


async def list_memberships(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_role: Role,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[tuple[Membership, AppUser]], int]:
    """List memberships for an organization."""
    assert_permission(actor_role, Permission.MEMBERSHIP_READ)

    count_res = await db.execute(
        select(func.count()).select_from(Membership).where(Membership.organization_id == org_id)
    )
    total = int(count_res.scalar_one())

    stmt = (
        select(Membership, AppUser)
        .join(AppUser, AppUser.id == Membership.user_id)
        .where(Membership.organization_id == org_id)
        .order_by(Membership.created_at.asc())
        .limit(limit)
        .offset(offset)
    )
    res = await db.execute(stmt)
    return [(row[0], row[1]) for row in res.all()], total


async def add_membership(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    oidc_issuer: str,
    oidc_subject: str,
    email: str,
    display_name: str,
    role: Role,
    status: MembershipStatus,
    correlation_id: str | None,
) -> tuple[Membership, AppUser]:
    """Add or invite a user into an organization with role-escalation protections."""
    assert_permission(actor_role, Permission.MEMBERSHIP_MANAGE)
    if role == Role.OWNER and actor_role != Role.OWNER:
        raise ForbiddenError("Only an organization owner may assign the owner role")

    clean_issuer = oidc_issuer.strip().rstrip("/")
    clean_subject = oidc_subject.strip()
    if not clean_issuer or not clean_subject:
        raise ValidationError("oidc_issuer and oidc_subject are required")

    await set_db_context(
        db,
        org_id=org_id,
        user_id=actor_id,
        auth_lookup=(clean_issuer, clean_subject),
    )

    user_res = await db.execute(
        select(AppUser).where(
            AppUser.oidc_issuer == clean_issuer,
            AppUser.oidc_subject == clean_subject,
        )
    )
    target_user = user_res.scalar_one_or_none()
    if target_user is None:
        target_user = AppUser(
            oidc_issuer=clean_issuer,
            oidc_subject=clean_subject,
            email=email.strip().lower(),
            display_name=display_name.strip()[:200],
            status=UserStatus.ACTIVE.value,
        )
        db.add(target_user)
        await db.flush()

    membership = Membership(
        organization_id=org_id,
        user_id=target_user.id,
        role=role.value,
        status=status.value,
    )
    db.add(membership)
    try:
        await db.flush()
    except IntegrityError as exc:
        raise ConflictError("User already has a membership in this organization") from exc

    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        action="membership.created",
        resource_type="membership",
        resource_id=membership.id,
        metadata={
            "target_user_id": str(target_user.id),
            "role": role.value,
            "status": status.value,
        },
    )
    return membership, target_user


async def _count_active_owners(db: AsyncSession, org_id: uuid.UUID) -> int:
    res = await db.execute(
        select(func.count())
        .select_from(Membership)
        .where(
            Membership.organization_id == org_id,
            Membership.role == Role.OWNER.value,
            Membership.status == MembershipStatus.ACTIVE.value,
        )
    )
    return int(res.scalar_one())


async def update_membership(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    membership_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    new_role: Role | None,
    new_status: MembershipStatus | None,
    correlation_id: str | None,
) -> tuple[Membership, AppUser]:
    """Update a member's role or status with owner escalation and last-owner guards."""
    assert_permission(actor_role, Permission.MEMBERSHIP_MANAGE)

    res = await db.execute(
        select(Membership, AppUser)
        .join(AppUser, AppUser.id == Membership.user_id)
        .where(Membership.id == membership_id, Membership.organization_id == org_id)
    )
    row = res.first()
    if row is None:
        raise NotFoundError("Membership not found")
    membership, target_user = row[0], row[1]

    if (membership.role == Role.OWNER.value or new_role == Role.OWNER) and actor_role != Role.OWNER:
        raise ForbiddenError("Only an organization owner may modify or assign the owner role")

    was_active_owner = (
        membership.role == Role.OWNER.value and membership.status == MembershipStatus.ACTIVE.value
    )
    will_be_active_owner = (new_role or Role(membership.role)) == Role.OWNER and (
        new_status or MembershipStatus(membership.status)
    ) == MembershipStatus.ACTIVE
    if was_active_owner and not will_be_active_owner:
        if await _count_active_owners(db, org_id) <= 1:
            raise ConflictError("Cannot demote or suspend the last active organization owner")

    previous_role = membership.role
    previous_status = membership.status
    if new_role is not None:
        membership.role = new_role.value
    if new_status is not None:
        membership.status = new_status.value

    await db.flush()
    await db.refresh(membership)
    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        action="membership.updated",
        resource_type="membership",
        resource_id=membership.id,
        metadata={
            "previous_role": previous_role,
            "new_role": membership.role,
            "previous_status": previous_status,
            "new_status": membership.status,
        },
    )
    return membership, target_user


async def remove_membership(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    membership_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    correlation_id: str | None,
) -> None:
    """Remove a membership, protecting the last active owner."""
    assert_permission(actor_role, Permission.MEMBERSHIP_MANAGE)

    res = await db.execute(
        select(Membership).where(
            Membership.id == membership_id,
            Membership.organization_id == org_id,
        )
    )
    membership = res.scalar_one_or_none()
    if membership is None:
        raise NotFoundError("Membership not found")

    if membership.role == Role.OWNER.value and actor_role != Role.OWNER:
        raise ForbiddenError("Only an organization owner may remove an owner membership")

    if (
        membership.role == Role.OWNER.value
        and membership.status == MembershipStatus.ACTIVE.value
        and await _count_active_owners(db, org_id) <= 1
    ):
        raise ConflictError("Cannot remove the last active organization owner")

    await db.delete(membership)
    await db.flush()
    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        action="membership.removed",
        resource_type="membership",
        resource_id=membership_id,
        metadata={"removed_user_id": str(membership.user_id), "role": membership.role},
    )
