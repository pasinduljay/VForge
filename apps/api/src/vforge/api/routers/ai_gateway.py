"""Control-plane API routes for Phase 12 AI Provider Governance & Multi-Agent Workflows."""

from __future__ import annotations

import logging
import uuid

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.ai_gateway.rag import retrieve_tenant_knowledge
from vforge.ai_gateway.service import (
    configure_provider,
    decide_tool_proposal,
    execute_ai_task,
    get_ai_governance_overview,
    index_knowledge_document,
    list_model_catalog,
    record_blocked_ai_attempt,
    record_feedback_label,
    record_model_evaluation,
    set_provider_retention_consent,
)
from vforge.api.deps import (
    TenantContext,
    enforce_sensitive_rate_limit,
    get_db,
    get_tenant_context,
)
from vforge.auth.rbac import Permission, assert_permission
from vforge.config import Settings, get_settings
from vforge.db import set_db_context
from vforge.errors import VForgeError
from vforge.schemas import (
    AiAuditEventOut,
    AiFeedbackCreateRequest,
    AiFeedbackOut,
    AiGovernanceOverviewOut,
    AiModelCatalogOut,
    AiProviderConfigCreateRequest,
    AiProviderConfigOut,
    AiRetentionConsentRequest,
    AiRunOut,
    AiTaskExecuteRequest,
    AiTaskExecuteResponse,
    AiTaskRequestOut,
    AiToolProposalDecisionRequest,
    AiToolProposalOut,
    KnowledgeDocumentCreateRequest,
    KnowledgeDocumentOut,
    KnowledgeSearchHitOut,
    ModelEvaluationCreateRequest,
    ModelEvaluationOut,
)

router = APIRouter(prefix="/api/v1/organizations/{org_id}/ai", tags=["ai-governance"])


@router.get("/overview", response_model=AiGovernanceOverviewOut)
async def ai_overview(
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> AiGovernanceOverviewOut:
    assert_permission(ctx.role, Permission.AI_READ)
    overview = await get_ai_governance_overview(db, organization_id=ctx.org_id)
    return AiGovernanceOverviewOut(
        model_catalog=[AiModelCatalogOut.model_validate(m) for m in overview["model_catalog"]],
        provider_configs=[
            AiProviderConfigOut.model_validate(p) for p in overview["provider_configs"]
        ],
        recent_runs=[AiRunOut.model_validate(r) for r in overview["recent_runs"]],
        tool_proposals=[AiToolProposalOut.model_validate(p) for p in overview["tool_proposals"]],
        knowledge_documents=[
            KnowledgeDocumentOut.model_validate(d) for d in overview["knowledge_documents"]
        ],
        evaluations=[ModelEvaluationOut.model_validate(e) for e in overview["evaluations"]],
        audit_events=[AiAuditEventOut.model_validate(a) for a in overview["audit_events"]],
    )


@router.get("/catalog", response_model=list[AiModelCatalogOut])
async def ai_model_catalog(
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> list[AiModelCatalogOut]:
    assert_permission(ctx.role, Permission.AI_READ)
    rows = await list_model_catalog(db)
    return [AiModelCatalogOut.model_validate(row) for row in rows]


@router.post(
    "/providers",
    response_model=AiProviderConfigOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def create_provider_config(
    payload: AiProviderConfigCreateRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> AiProviderConfigOut:
    assert_permission(ctx.role, Permission.AI_MANAGE)
    cfg = await configure_provider(
        db,
        organization_id=ctx.org_id,
        provider_class=payload.provider_class,
        display_name=payload.display_name,
        endpoint_url=payload.endpoint_url,
        secret_ref=payload.secret_ref,
        local_only_mode=payload.local_only_mode,
        allowed_models=payload.allowed_models,
        monthly_budget_usd=payload.monthly_budget_usd,
        max_tokens_per_request=payload.max_tokens_per_request,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
    )
    out = AiProviderConfigOut.model_validate(cfg)
    await db.commit()
    return out


@router.post(
    "/providers/{provider_id}/consent",
    response_model=AiProviderConfigOut,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def update_provider_retention_consent(
    provider_id: uuid.UUID,
    payload: AiRetentionConsentRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> AiProviderConfigOut:
    assert_permission(ctx.role, Permission.AI_MANAGE)
    cfg = await set_provider_retention_consent(
        db,
        organization_id=ctx.org_id,
        provider_config_id=provider_id,
        approved=payload.approved,
        local_only_mode=payload.local_only_mode,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
    )
    out = AiProviderConfigOut.model_validate(cfg)
    await db.commit()
    return out


@router.post(
    "/tasks/execute",
    response_model=AiTaskExecuteResponse,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def execute_task_route(
    payload: AiTaskExecuteRequest,
    request: Request,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> AiTaskExecuteResponse:
    assert_permission(ctx.role, Permission.AI_INVOKE)
    try:
        result = await execute_ai_task(
            db,
            organization_id=ctx.org_id,
            task_type=payload.task_type,
            role_name=payload.role_name,
            raw_prompt=payload.raw_prompt,
            model_slug=payload.model_slug,
            prior_model_slug=payload.prior_model_slug,
            provider_config_ids=payload.provider_config_ids,
            fallback_model_slugs=payload.fallback_model_slugs,
            requested_classification=payload.requested_classification,
            consent_acknowledged=payload.consent_acknowledged,
            require_local_only=payload.require_local_only,
            rag_query=payload.rag_query,
            proposed_tools=[item.model_dump() for item in payload.proposed_tools],
            max_tokens=payload.max_tokens,
            actor_id=ctx.user.id,
            actor_email=ctx.user.email,
            actor_role=ctx.role.value,
            correlation_id=ctx.correlation_id,
            settings=settings,
        )
    except VForgeError as exc:
        session_factory = getattr(request.app.state, "session_factory", None)
        if session_factory is not None:
            try:
                async with session_factory() as audit_db:
                    async with audit_db.begin():
                        await set_db_context(audit_db, user_id=ctx.user.id, org_id=ctx.org_id)
                        await record_blocked_ai_attempt(
                            audit_db,
                            organization_id=ctx.org_id,
                            task_type=payload.task_type,
                            role_name=payload.role_name,
                            raw_prompt=payload.raw_prompt,
                            requested_classification=payload.requested_classification,
                            consent_acknowledged=payload.consent_acknowledged,
                            provider_config_id=None,
                            model_slug=payload.model_slug,
                            block_reason=exc.message,
                            actor_id=ctx.user.id,
                            actor_email=ctx.user.email,
                        )
            except Exception:
                logging.getLogger(__name__).warning(
                    "Failed to persist blocked AI attempt audit org=%s", ctx.org_id, exc_info=True
                )
        raise
    out = AiTaskExecuteResponse(
        task_request=AiTaskRequestOut.model_validate(result["task_request"]),
        run=AiRunOut.model_validate(result["run"]),
        tool_proposals=[
            AiToolProposalOut.model_validate(item) for item in result["tool_proposals"]
        ],
        rag_hits=[KnowledgeSearchHitOut.model_validate(hit) for hit in result["rag_hits"]],
    )
    await db.commit()
    return out


@router.post(
    "/tool-proposals/{proposal_id}/decide",
    response_model=AiToolProposalOut,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def decide_tool_proposal_route(
    proposal_id: uuid.UUID,
    payload: AiToolProposalDecisionRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> AiToolProposalOut:
    assert_permission(ctx.role, Permission.AI_MANAGE)
    prop = await decide_tool_proposal(
        db,
        organization_id=ctx.org_id,
        proposal_id=proposal_id,
        decision=payload.decision,
        comment=payload.comment,
        decided_by=ctx.user.id,
        decided_email=ctx.user.email,
        approver_role=ctx.role.value,
        settings=settings,
    )
    out = AiToolProposalOut.model_validate(prop)
    await db.commit()
    return out


@router.post(
    "/knowledge/documents",
    response_model=KnowledgeDocumentOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def index_knowledge_route(
    payload: KnowledgeDocumentCreateRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> KnowledgeDocumentOut:
    assert_permission(ctx.role, Permission.AI_MANAGE)
    doc = await index_knowledge_document(
        db,
        organization_id=ctx.org_id,
        slug=payload.slug,
        title=payload.title,
        source_type=payload.source_type,
        source_uri=payload.source_uri,
        content=payload.content,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
    )
    out = KnowledgeDocumentOut.model_validate(doc)
    await db.commit()
    return out


@router.get("/knowledge/search", response_model=list[KnowledgeSearchHitOut])
async def search_knowledge_route(
    q: str = Query(min_length=2, max_length=400),
    limit: int = Query(default=5, ge=1, le=20),
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> list[KnowledgeSearchHitOut]:
    assert_permission(ctx.role, Permission.AI_READ)
    hits = await retrieve_tenant_knowledge(db, organization_id=ctx.org_id, query=q, limit=limit)
    return [KnowledgeSearchHitOut.model_validate(hit) for hit in hits]


@router.post(
    "/feedback",
    response_model=AiFeedbackOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def create_feedback_route(
    payload: AiFeedbackCreateRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> AiFeedbackOut:
    assert_permission(ctx.role, Permission.AI_INVOKE)
    fb = await record_feedback_label(
        db,
        organization_id=ctx.org_id,
        ai_run_id=payload.ai_run_id,
        label=payload.label,
        notes=payload.notes,
        cross_tenant_sharing_enabled=payload.cross_tenant_sharing_enabled,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
    )
    out = AiFeedbackOut.model_validate(fb)
    await db.commit()
    return out


@router.post(
    "/evaluations",
    response_model=ModelEvaluationOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def create_evaluation_route(
    payload: ModelEvaluationCreateRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> ModelEvaluationOut:
    assert_permission(ctx.role, Permission.AI_MANAGE)
    ev = await record_model_evaluation(
        db,
        organization_id=ctx.org_id,
        model_slug=payload.model_slug,
        suite_name=payload.suite_name,
        sample_count=payload.sample_count,
        true_positive_rate=payload.true_positive_rate,
        false_positive_rate=payload.false_positive_rate,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
    )
    out = ModelEvaluationOut.model_validate(ev)
    await db.commit()
    return out
