"""Control-plane API routes for Phase 15 Optional Isolated AI Red-Team Sandbox."""

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
from vforge.errors import ConflictError, ForbiddenError
from vforge.redteam.service import (
    approve_or_reject_redteam_session,
    complete_or_terminate_redteam_session,
    create_redteam_benchmark,
    execute_redteam_tool_call,
    get_redteam_overview,
    record_redteam_observation,
    request_redteam_session,
    review_redteam_observation,
    start_redteam_session,
)
from vforge.schemas import (
    RedTeamBenchmarkCreateRequest,
    RedTeamBenchmarkOut,
    RedTeamEventOut,
    RedTeamObservationCreateRequest,
    RedTeamObservationOut,
    RedTeamObservationReviewRequest,
    RedTeamOverviewOut,
    RedTeamSessionCloseRequest,
    RedTeamSessionCreateRequest,
    RedTeamSessionDecisionRequest,
    RedTeamSessionOut,
    RedTeamToolCallOut,
    RedTeamToolCallRequest,
)

router = APIRouter(prefix="/api/v1/organizations/{org_id}/redteam", tags=["redteam"])


@router.get("/overview", response_model=RedTeamOverviewOut)
async def redteam_overview(
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> RedTeamOverviewOut:
    assert_permission(ctx.role, Permission.REDTEAM_READ)
    overview = await get_redteam_overview(
        db,
        organization_id=ctx.org_id,
        settings=settings,
        actor_id=ctx.user.id,
        actor_role=ctx.role.value,
    )
    return RedTeamOverviewOut(
        organization_id=overview["organization_id"],
        execution_mode=overview["execution_mode"],
        sandbox_isolation=overview["sandbox_isolation"],
        lab_isolation=overview["lab_isolation"],
        allowed_tools=overview["allowed_tools"],
        forbidden_tools=overview["forbidden_tools"],
        sessions=[RedTeamSessionOut.model_validate(s) for s in overview["sessions"]],
        observations=[RedTeamObservationOut.model_validate(o) for o in overview["observations"]],
        events=[RedTeamEventOut.model_validate(e) for e in overview["events"]],
        benchmarks=[RedTeamBenchmarkOut.model_validate(b) for b in overview["benchmarks"]],
    )


@router.post(
    "/sessions",
    response_model=RedTeamSessionOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def create_redteam_session_endpoint(
    payload: RedTeamSessionCreateRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> RedTeamSessionOut:
    assert_permission(ctx.role, Permission.REDTEAM_REQUEST)
    session = await request_redteam_session(
        db,
        organization_id=ctx.org_id,
        title=payload.title,
        objective=payload.objective,
        engine=payload.engine,
        tool_allowlist=payload.tool_allowlist,
        target_urls=payload.target_urls,
        max_duration_seconds=payload.max_duration_seconds,
        max_tool_calls=payload.max_tool_calls,
        max_tokens=payload.max_tokens,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
        actor_role=ctx.role.value,
        settings=settings,
    )
    out = RedTeamSessionOut.model_validate(session)
    await db.commit()
    return out


@router.post(
    "/sessions/{session_id}/decision",
    response_model=RedTeamSessionOut,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def decide_redteam_session_endpoint(
    session_id: uuid.UUID,
    payload: RedTeamSessionDecisionRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> RedTeamSessionOut:
    assert_permission(ctx.role, Permission.REDTEAM_APPROVE)
    try:
        session = await approve_or_reject_redteam_session(
            db,
            organization_id=ctx.org_id,
            session_id=session_id,
            decision=payload.decision,
            approval_ttl_minutes=payload.approval_ttl_minutes,
            reason=payload.reason,
            actor_id=ctx.user.id,
            actor_email=ctx.user.email,
            actor_role=ctx.role.value,
            settings=settings,
        )
    except ForbiddenError:
        await db.commit()
        raise
    out = RedTeamSessionOut.model_validate(session)
    await db.commit()
    return out


@router.post(
    "/sessions/{session_id}/start",
    response_model=RedTeamSessionOut,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def start_redteam_session_endpoint(
    session_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> RedTeamSessionOut:
    assert_permission(ctx.role, Permission.REDTEAM_EXECUTE)
    try:
        session = await start_redteam_session(
            db,
            organization_id=ctx.org_id,
            session_id=session_id,
            actor_id=ctx.user.id,
            actor_email=ctx.user.email,
            actor_role=ctx.role.value,
            settings=settings,
        )
    except ConflictError:
        await db.commit()
        raise
    out = RedTeamSessionOut.model_validate(session)
    await db.commit()
    return out


@router.post(
    "/sessions/{session_id}/tool-calls",
    response_model=RedTeamToolCallOut,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def execute_redteam_tool_call_endpoint(
    session_id: uuid.UUID,
    payload: RedTeamToolCallRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> RedTeamToolCallOut:
    assert_permission(ctx.role, Permission.REDTEAM_EXECUTE)
    try:
        result = await execute_redteam_tool_call(
            db,
            organization_id=ctx.org_id,
            session_id=session_id,
            tool_name=payload.tool_name,
            target_url=payload.target_url,
            input_summary=payload.input_summary,
            estimated_tokens=payload.estimated_tokens,
            actor_id=ctx.user.id,
            actor_email=ctx.user.email,
            actor_role=ctx.role.value,
            settings=settings,
        )
    except (ForbiddenError, ConflictError):
        await db.commit()
        raise
    out = RedTeamToolCallOut.model_validate(result)
    await db.commit()
    return out


@router.post(
    "/sessions/{session_id}/observations",
    response_model=RedTeamObservationOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def record_redteam_observation_endpoint(
    session_id: uuid.UUID,
    payload: RedTeamObservationCreateRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> RedTeamObservationOut:
    assert_permission(ctx.role, Permission.REDTEAM_EXECUTE)
    try:
        obs = await record_redteam_observation(
            db,
            organization_id=ctx.org_id,
            session_id=session_id,
            title=payload.title,
            category=payload.category,
            severity=payload.severity,
            evidence_summary=payload.evidence_summary,
            actor_id=ctx.user.id,
            actor_email=ctx.user.email,
            actor_role=ctx.role.value,
            settings=settings,
        )
    except (ForbiddenError, ConflictError):
        await db.commit()
        raise
    out = RedTeamObservationOut.model_validate(obs)
    await db.commit()
    return out


@router.post(
    "/observations/{observation_id}/review",
    response_model=RedTeamObservationOut,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def review_redteam_observation_endpoint(
    observation_id: uuid.UUID,
    payload: RedTeamObservationReviewRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> RedTeamObservationOut:
    assert_permission(ctx.role, Permission.REDTEAM_REVIEW)
    try:
        obs = await review_redteam_observation(
            db,
            organization_id=ctx.org_id,
            observation_id=observation_id,
            decision=payload.decision,
            review_note=payload.review_note,
            actor_id=ctx.user.id,
            actor_email=ctx.user.email,
            actor_role=ctx.role.value,
            settings=settings,
        )
    except ForbiddenError:
        await db.commit()
        raise
    out = RedTeamObservationOut.model_validate(obs)
    await db.commit()
    return out


@router.post(
    "/sessions/{session_id}/close",
    response_model=RedTeamSessionOut,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def close_redteam_session_endpoint(
    session_id: uuid.UUID,
    payload: RedTeamSessionCloseRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> RedTeamSessionOut:
    assert_permission(ctx.role, Permission.REDTEAM_EXECUTE)
    try:
        session = await complete_or_terminate_redteam_session(
            db,
            organization_id=ctx.org_id,
            session_id=session_id,
            final_status=payload.final_status,
            end_reason=payload.end_reason,
            cleanup_attested=payload.cleanup_attested,
            cleanup_summary=payload.cleanup_summary,
            actor_id=ctx.user.id,
            actor_email=ctx.user.email,
            actor_role=ctx.role.value,
            settings=settings,
        )
    except (ForbiddenError, ConflictError):
        await db.commit()
        raise
    out = RedTeamSessionOut.model_validate(session)
    await db.commit()
    return out


@router.post(
    "/sessions/{session_id}/benchmarks",
    response_model=RedTeamBenchmarkOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def create_redteam_benchmark_endpoint(
    session_id: uuid.UUID,
    payload: RedTeamBenchmarkCreateRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> RedTeamBenchmarkOut:
    assert_permission(ctx.role, Permission.REDTEAM_REVIEW)
    benchmark = await create_redteam_benchmark(
        db,
        organization_id=ctx.org_id,
        session_id=session_id,
        ground_truth_slugs=payload.ground_truth_slugs,
        ai_detected_slugs=payload.ai_detected_slugs,
        zap_detected_slugs=payload.zap_detected_slugs,
        nuclei_detected_slugs=payload.nuclei_detected_slugs,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
        actor_role=ctx.role.value,
        settings=settings,
    )
    out = RedTeamBenchmarkOut.model_validate(benchmark)
    await db.commit()
    return out
