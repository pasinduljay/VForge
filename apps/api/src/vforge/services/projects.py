"""Project, environment, asset, and auth-profile domain services."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.auth.rbac import Permission, assert_permission
from vforge.errors import ConflictError, NotFoundError
from vforge.models import (
    Asset,
    AssetType,
    AuthProfile,
    AuthProfileStatus,
    AuthProfileType,
    Environment,
    EnvironmentStatus,
    EnvironmentType,
    Project,
    ProjectCriticality,
    ProjectStatus,
    RegistrationState,
    Role,
)
from vforge.security.validators import (
    normalize_asset_locator,
    validate_secret_manager_ref,
    validate_slug,
)
from vforge.services.audit import record_audit_event


async def list_projects(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_role: Role,
    status: ProjectStatus | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Project], int]:
    assert_permission(actor_role, Permission.PROJECT_READ)
    stmt = select(Project).where(Project.organization_id == org_id)
    count_stmt = select(func.count()).select_from(Project).where(Project.organization_id == org_id)
    if status is not None:
        stmt = stmt.where(Project.status == status.value)
        count_stmt = count_stmt.where(Project.status == status.value)

    total = int((await db.execute(count_stmt)).scalar_one())
    rows = list(
        (await db.execute(stmt.order_by(Project.created_at.desc()).limit(limit).offset(offset)))
        .scalars()
        .all()
    )
    return rows, total


async def create_project(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    name: str,
    slug: str,
    description: str | None,
    criticality: ProjectCriticality,
    correlation_id: str | None,
) -> Project:
    assert_permission(actor_role, Permission.PROJECT_CREATE)
    clean_slug = validate_slug(slug)

    project = Project(
        organization_id=org_id,
        name=name.strip(),
        slug=clean_slug,
        description=description.strip() if description else None,
        criticality=criticality.value,
        status=ProjectStatus.ACTIVE.value,
    )
    db.add(project)
    try:
        await db.flush()
    except IntegrityError as exc:
        raise ConflictError("Project slug already exists in this organization") from exc

    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        action="project.created",
        resource_type="project",
        resource_id=project.id,
        metadata={"slug": clean_slug, "criticality": criticality.value},
    )
    return project


async def get_project(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    actor_role: Role,
) -> Project:
    assert_permission(actor_role, Permission.PROJECT_READ)
    res = await db.execute(
        select(Project).where(Project.id == project_id, Project.organization_id == org_id)
    )
    project = res.scalar_one_or_none()
    if project is None:
        raise NotFoundError("Project not found")
    return project


async def update_project(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    name: str | None,
    description: str | None,
    criticality: ProjectCriticality | None,
    status: ProjectStatus | None,
    correlation_id: str | None,
) -> Project:
    assert_permission(actor_role, Permission.PROJECT_UPDATE)
    project = await get_project(db, org_id=org_id, project_id=project_id, actor_role=actor_role)

    if name is not None:
        project.name = name.strip()
    if description is not None:
        project.description = description.strip() or None
    if criticality is not None:
        project.criticality = criticality.value
    if status is not None:
        project.status = status.value

    await db.flush()
    await db.refresh(project)
    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        action="project.updated",
        resource_type="project",
        resource_id=project.id,
        metadata={"status": project.status, "criticality": project.criticality},
    )
    return project


async def delete_project(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    correlation_id: str | None,
) -> None:
    assert_permission(actor_role, Permission.PROJECT_DELETE)
    project = await get_project(db, org_id=org_id, project_id=project_id, actor_role=actor_role)
    try:
        async with db.begin_nested():
            await db.delete(project)
            await db.flush()
    except (IntegrityError, DBAPIError) as exc:
        raise ConflictError(
            "Project has immutable security audit or scan records and cannot be hard-deleted; "
            "archive the project (status='archived') instead."
        ) from exc
    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        action="project.deleted",
        resource_type="project",
        resource_id=project_id,
        metadata={"slug": project.slug},
    )


# --- Environments ---


async def list_environments(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    actor_role: Role,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Environment], int]:
    assert_permission(actor_role, Permission.ENVIRONMENT_READ)
    await get_project(db, org_id=org_id, project_id=project_id, actor_role=actor_role)

    count_res = await db.execute(
        select(func.count())
        .select_from(Environment)
        .where(Environment.organization_id == org_id, Environment.project_id == project_id)
    )
    total = int(count_res.scalar_one())

    rows = list(
        (
            await db.execute(
                select(Environment)
                .where(
                    Environment.organization_id == org_id,
                    Environment.project_id == project_id,
                )
                .order_by(Environment.created_at.asc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return rows, total


async def create_environment(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    name: str,
    environment_type: EnvironmentType,
    correlation_id: str | None,
) -> Environment:
    assert_permission(actor_role, Permission.ENVIRONMENT_MANAGE)
    await get_project(db, org_id=org_id, project_id=project_id, actor_role=actor_role)

    env = Environment(
        organization_id=org_id,
        project_id=project_id,
        name=name.strip(),
        environment_type=environment_type.value,
        status=EnvironmentStatus.ACTIVE.value,
    )
    db.add(env)
    try:
        await db.flush()
    except IntegrityError as exc:
        raise ConflictError("Environment name already exists in this project") from exc

    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        action="environment.created",
        resource_type="environment",
        resource_id=env.id,
        metadata={"project_id": str(project_id), "environment_type": environment_type.value},
    )
    return env


async def get_environment(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    environment_id: uuid.UUID,
    actor_role: Role,
) -> Environment:
    assert_permission(actor_role, Permission.ENVIRONMENT_READ)
    res = await db.execute(
        select(Environment).where(
            Environment.id == environment_id,
            Environment.organization_id == org_id,
        )
    )
    env = res.scalar_one_or_none()
    if env is None:
        raise NotFoundError("Environment not found")
    return env


async def update_environment(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    environment_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    name: str | None,
    environment_type: EnvironmentType | None,
    status: EnvironmentStatus | None,
    correlation_id: str | None,
) -> Environment:
    assert_permission(actor_role, Permission.ENVIRONMENT_MANAGE)
    env = await get_environment(
        db,
        org_id=org_id,
        environment_id=environment_id,
        actor_role=actor_role,
    )
    if name is not None:
        env.name = name.strip()
    if environment_type is not None:
        env.environment_type = environment_type.value
    if status is not None:
        env.status = status.value

    try:
        await db.flush()
    except IntegrityError as exc:
        raise ConflictError("Environment name already exists in this project") from exc
    await db.refresh(env)

    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        action="environment.updated",
        resource_type="environment",
        resource_id=env.id,
        metadata={"status": env.status, "environment_type": env.environment_type},
    )
    return env


# --- Assets ---


async def list_assets(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_role: Role,
    environment_id: uuid.UUID | None = None,
    asset_type: AssetType | None = None,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[Asset], int]:
    assert_permission(actor_role, Permission.ASSET_READ)
    stmt = select(Asset).where(Asset.organization_id == org_id)
    count_stmt = select(func.count()).select_from(Asset).where(Asset.organization_id == org_id)
    if environment_id is not None:
        stmt = stmt.where(Asset.environment_id == environment_id)
        count_stmt = count_stmt.where(Asset.environment_id == environment_id)
    if asset_type is not None:
        stmt = stmt.where(Asset.asset_type == asset_type.value)
        count_stmt = count_stmt.where(Asset.asset_type == asset_type.value)

    total = int((await db.execute(count_stmt)).scalar_one())
    rows = list(
        (await db.execute(stmt.order_by(Asset.created_at.desc()).limit(limit).offset(offset)))
        .scalars()
        .all()
    )
    return rows, total


async def create_asset(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    environment_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    asset_type: AssetType,
    locator: str,
    scope_metadata: dict[str, Any],
    registration_state: RegistrationState,
    correlation_id: str | None,
) -> Asset:
    assert_permission(actor_role, Permission.ASSET_MANAGE)
    await get_environment(
        db,
        org_id=org_id,
        environment_id=environment_id,
        actor_role=actor_role,
    )
    normalized = normalize_asset_locator(asset_type, locator)

    asset = Asset(
        organization_id=org_id,
        environment_id=environment_id,
        asset_type=asset_type.value,
        normalized_locator=normalized,
        scope_metadata=scope_metadata,
        registration_state=registration_state.value,
    )
    db.add(asset)
    try:
        await db.flush()
    except IntegrityError as exc:
        raise ConflictError("Asset already registered in this environment") from exc

    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        action="asset.registered",
        resource_type="asset",
        resource_id=asset.id,
        metadata={
            "environment_id": str(environment_id),
            "asset_type": asset_type.value,
            "normalized_locator": normalized,
        },
    )
    return asset


async def get_asset(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    asset_id: uuid.UUID,
    actor_role: Role,
) -> Asset:
    assert_permission(actor_role, Permission.ASSET_READ)
    res = await db.execute(
        select(Asset).where(Asset.id == asset_id, Asset.organization_id == org_id)
    )
    asset = res.scalar_one_or_none()
    if asset is None:
        raise NotFoundError("Asset not found")
    return asset


async def update_asset(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    asset_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    scope_metadata: dict[str, Any] | None,
    registration_state: RegistrationState | None,
    correlation_id: str | None,
) -> Asset:
    assert_permission(actor_role, Permission.ASSET_MANAGE)
    asset = await get_asset(db, org_id=org_id, asset_id=asset_id, actor_role=actor_role)
    if scope_metadata is not None:
        asset.scope_metadata = scope_metadata
    if registration_state is not None:
        asset.registration_state = registration_state.value
    asset.version += 1

    await db.flush()
    await db.refresh(asset)
    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        action="asset.updated",
        resource_type="asset",
        resource_id=asset.id,
        metadata={
            "registration_state": asset.registration_state,
            "asset_version": asset.version,
        },
    )
    return asset


# --- Auth Profiles ---


async def list_auth_profiles(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    environment_id: uuid.UUID,
    actor_role: Role,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[AuthProfile], int]:
    assert_permission(actor_role, Permission.AUTH_PROFILE_READ)
    await get_environment(
        db,
        org_id=org_id,
        environment_id=environment_id,
        actor_role=actor_role,
    )
    count_res = await db.execute(
        select(func.count())
        .select_from(AuthProfile)
        .where(
            AuthProfile.organization_id == org_id,
            AuthProfile.environment_id == environment_id,
        )
    )
    total = int(count_res.scalar_one())
    rows = list(
        (
            await db.execute(
                select(AuthProfile)
                .where(
                    AuthProfile.organization_id == org_id,
                    AuthProfile.environment_id == environment_id,
                )
                .order_by(AuthProfile.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return rows, total


async def create_auth_profile(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    environment_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    name: str,
    auth_type: AuthProfileType,
    secret_manager_ref: str,
    correlation_id: str | None,
) -> AuthProfile:
    assert_permission(actor_role, Permission.AUTH_PROFILE_MANAGE)
    await get_environment(
        db,
        org_id=org_id,
        environment_id=environment_id,
        actor_role=actor_role,
    )
    validated_ref = validate_secret_manager_ref(secret_manager_ref)

    profile = AuthProfile(
        organization_id=org_id,
        environment_id=environment_id,
        name=name.strip(),
        auth_type=auth_type.value,
        secret_manager_ref=validated_ref,
        status=AuthProfileStatus.ACTIVE.value,
    )
    db.add(profile)
    try:
        await db.flush()
    except IntegrityError as exc:
        raise ConflictError("Auth profile name already exists in this environment") from exc

    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        action="auth_profile.created",
        resource_type="auth_profile",
        resource_id=profile.id,
        metadata={"environment_id": str(environment_id), "auth_type": auth_type.value},
    )
    return profile


async def update_auth_profile(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    auth_profile_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    name: str | None,
    auth_type: AuthProfileType | None,
    secret_manager_ref: str | None,
    status: AuthProfileStatus | None,
    correlation_id: str | None,
) -> AuthProfile:
    assert_permission(actor_role, Permission.AUTH_PROFILE_MANAGE)
    res = await db.execute(
        select(AuthProfile).where(
            AuthProfile.id == auth_profile_id,
            AuthProfile.organization_id == org_id,
        )
    )
    profile = res.scalar_one_or_none()
    if profile is None:
        raise NotFoundError("Auth profile not found")

    if name is not None:
        profile.name = name.strip()
    if auth_type is not None:
        profile.auth_type = auth_type.value
    if secret_manager_ref is not None:
        profile.secret_manager_ref = validate_secret_manager_ref(secret_manager_ref)
    if status is not None:
        profile.status = status.value

    await db.flush()
    await db.refresh(profile)
    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        action="auth_profile.updated",
        resource_type="auth_profile",
        resource_id=profile.id,
        metadata={"status": profile.status, "auth_type": profile.auth_type},
    )
    return profile
