"""Projects, environments, assets, and authentication-profiles API endpoints."""

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
from vforge.models.enums import AssetType, ProjectStatus
from vforge.schemas import (
    AssetCreate,
    AssetOut,
    AssetUpdate,
    AuthProfileCreate,
    AuthProfileOut,
    AuthProfileUpdate,
    EnvironmentCreate,
    EnvironmentOut,
    EnvironmentUpdate,
    PaginatedResponse,
    ProjectCreate,
    ProjectOut,
    ProjectUpdate,
)
from vforge.services import projects as project_service

router = APIRouter(prefix="/api/v1/organizations/{org_id}", tags=["projects-assets"])


# --- Projects ---


@router.get("/projects", response_model=PaginatedResponse)
async def list_projects(
    status_filter: ProjectStatus | None = Query(default=None, alias="status"),  # noqa: B008
    limit: int = Query(default=50, ge=1, le=200),  # noqa: B008
    offset: int = Query(default=0, ge=0),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> PaginatedResponse:
    rows, total = await project_service.list_projects(
        db,
        org_id=ctx.org_id,
        actor_role=ctx.role,
        status=status_filter,
        limit=limit,
        offset=offset,
    )
    return PaginatedResponse(
        items=[ProjectOut.model_validate(item) for item in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/projects",
    response_model=ProjectOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def create_project(
    payload: ProjectCreate,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> ProjectOut:
    project = await project_service.create_project(
        db,
        org_id=ctx.org_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        name=payload.name,
        slug=payload.slug,
        description=payload.description,
        criticality=payload.criticality,
        correlation_id=ctx.correlation_id,
    )
    return ProjectOut.model_validate(project)


@router.get("/projects/{project_id}", response_model=ProjectOut)
async def get_project(
    project_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> ProjectOut:
    project = await project_service.get_project(
        db,
        org_id=ctx.org_id,
        project_id=project_id,
        actor_role=ctx.role,
    )
    return ProjectOut.model_validate(project)


@router.patch(
    "/projects/{project_id}",
    response_model=ProjectOut,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def update_project(
    project_id: uuid.UUID,
    payload: ProjectUpdate,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> ProjectOut:
    project = await project_service.update_project(
        db,
        org_id=ctx.org_id,
        project_id=project_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        name=payload.name,
        description=payload.description,
        criticality=payload.criticality,
        status=payload.status,
        correlation_id=ctx.correlation_id,
    )
    return ProjectOut.model_validate(project)


@router.delete(
    "/projects/{project_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def delete_project(
    project_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> None:
    await project_service.delete_project(
        db,
        org_id=ctx.org_id,
        project_id=project_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        correlation_id=ctx.correlation_id,
    )


# --- Environments ---


@router.get("/projects/{project_id}/environments", response_model=PaginatedResponse)
async def list_environments(
    project_id: uuid.UUID,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> PaginatedResponse:
    rows, total = await project_service.list_environments(
        db,
        org_id=ctx.org_id,
        project_id=project_id,
        actor_role=ctx.role,
        limit=limit,
        offset=offset,
    )
    return PaginatedResponse(
        items=[EnvironmentOut.model_validate(item) for item in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/projects/{project_id}/environments",
    response_model=EnvironmentOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_environment(
    project_id: uuid.UUID,
    payload: EnvironmentCreate,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> EnvironmentOut:
    env = await project_service.create_environment(
        db,
        org_id=ctx.org_id,
        project_id=project_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        name=payload.name,
        environment_type=payload.environment_type,
        correlation_id=ctx.correlation_id,
    )
    return EnvironmentOut.model_validate(env)


@router.get("/environments/{environment_id}", response_model=EnvironmentOut)
async def get_environment(
    environment_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> EnvironmentOut:
    env = await project_service.get_environment(
        db,
        org_id=ctx.org_id,
        environment_id=environment_id,
        actor_role=ctx.role,
    )
    return EnvironmentOut.model_validate(env)


@router.patch("/environments/{environment_id}", response_model=EnvironmentOut)
async def update_environment(
    environment_id: uuid.UUID,
    payload: EnvironmentUpdate,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> EnvironmentOut:
    env = await project_service.update_environment(
        db,
        org_id=ctx.org_id,
        environment_id=environment_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        name=payload.name,
        environment_type=payload.environment_type,
        status=payload.status,
        correlation_id=ctx.correlation_id,
    )
    return EnvironmentOut.model_validate(env)


# --- Assets ---


@router.get("/assets", response_model=PaginatedResponse)
async def list_org_assets(
    environment_id: uuid.UUID | None = Query(default=None),  # noqa: B008
    asset_type: AssetType | None = Query(default=None),  # noqa: B008
    limit: int = Query(default=50, ge=1, le=200),  # noqa: B008
    offset: int = Query(default=0, ge=0),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> PaginatedResponse:
    rows, total = await project_service.list_assets(
        db,
        org_id=ctx.org_id,
        actor_role=ctx.role,
        environment_id=environment_id,
        asset_type=asset_type,
        limit=limit,
        offset=offset,
    )
    return PaginatedResponse(
        items=[AssetOut.model_validate(item) for item in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/environments/{environment_id}/assets", response_model=PaginatedResponse)
async def list_environment_assets(
    environment_id: uuid.UUID,
    asset_type: AssetType | None = Query(default=None),  # noqa: B008
    limit: int = Query(default=50, ge=1, le=200),  # noqa: B008
    offset: int = Query(default=0, ge=0),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> PaginatedResponse:
    await project_service.get_environment(
        db,
        org_id=ctx.org_id,
        environment_id=environment_id,
        actor_role=ctx.role,
    )
    rows, total = await project_service.list_assets(
        db,
        org_id=ctx.org_id,
        actor_role=ctx.role,
        environment_id=environment_id,
        asset_type=asset_type,
        limit=limit,
        offset=offset,
    )
    return PaginatedResponse(
        items=[AssetOut.model_validate(item) for item in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/environments/{environment_id}/assets",
    response_model=AssetOut,
    status_code=status.HTTP_201_CREATED,
)
async def register_asset(
    environment_id: uuid.UUID,
    payload: AssetCreate,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> AssetOut:
    asset = await project_service.create_asset(
        db,
        org_id=ctx.org_id,
        environment_id=environment_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        asset_type=payload.asset_type,
        locator=payload.locator,
        scope_metadata=payload.scope_metadata,
        registration_state=payload.registration_state,
        correlation_id=ctx.correlation_id,
    )
    return AssetOut.model_validate(asset)


@router.get("/assets/{asset_id}", response_model=AssetOut)
async def get_asset(
    asset_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> AssetOut:
    asset = await project_service.get_asset(
        db,
        org_id=ctx.org_id,
        asset_id=asset_id,
        actor_role=ctx.role,
    )
    return AssetOut.model_validate(asset)


@router.patch("/assets/{asset_id}", response_model=AssetOut)
async def update_asset(
    asset_id: uuid.UUID,
    payload: AssetUpdate,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> AssetOut:
    asset = await project_service.update_asset(
        db,
        org_id=ctx.org_id,
        asset_id=asset_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        scope_metadata=payload.scope_metadata,
        registration_state=payload.registration_state,
        correlation_id=ctx.correlation_id,
    )
    return AssetOut.model_validate(asset)


# --- Authentication Profiles ---


@router.get("/environments/{environment_id}/auth-profiles", response_model=PaginatedResponse)
async def list_auth_profiles(
    environment_id: uuid.UUID,
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> PaginatedResponse:
    rows, total = await project_service.list_auth_profiles(
        db,
        org_id=ctx.org_id,
        environment_id=environment_id,
        actor_role=ctx.role,
        limit=limit,
        offset=offset,
    )
    return PaginatedResponse(
        items=[AuthProfileOut.model_validate(item) for item in rows],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/environments/{environment_id}/auth-profiles",
    response_model=AuthProfileOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_auth_profile(
    environment_id: uuid.UUID,
    payload: AuthProfileCreate,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> AuthProfileOut:
    profile = await project_service.create_auth_profile(
        db,
        org_id=ctx.org_id,
        environment_id=environment_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        name=payload.name,
        auth_type=payload.auth_type,
        secret_manager_ref=payload.secret_manager_ref,
        correlation_id=ctx.correlation_id,
    )
    return AuthProfileOut.model_validate(profile)


@router.patch("/auth-profiles/{auth_profile_id}", response_model=AuthProfileOut)
async def update_auth_profile(
    auth_profile_id: uuid.UUID,
    payload: AuthProfileUpdate,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> AuthProfileOut:
    profile = await project_service.update_auth_profile(
        db,
        org_id=ctx.org_id,
        auth_profile_id=auth_profile_id,
        actor_id=ctx.user.id,
        actor_role=ctx.role,
        name=payload.name,
        auth_type=payload.auth_type,
        secret_manager_ref=payload.secret_manager_ref,
        status=payload.status,
        correlation_id=ctx.correlation_id,
    )
    return AuthProfileOut.model_validate(profile)
