"""Control-plane API routes for Phase 11 Rule & Skill Studio."""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, Header, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.api.deps import (
    TenantContext,
    enforce_sensitive_rate_limit,
    get_db,
    get_tenant_context,
)
from vforge.auth.rbac import Permission, assert_permission
from vforge.config import Settings, get_settings
from vforge.errors import ForbiddenError
from vforge.models.enums import StudioActorType, StudioEngine
from vforge.schemas import (
    AiCandidateGenerateRequest,
    AssessmentSkillCreateRequest,
    AssessmentSkillOut,
    RuleFixtureRunOut,
    RulePackCreateRequest,
    RulePackOut,
    RulePackVersionCreateRequest,
    RulePackVersionOut,
    SkillVersionCreateRequest,
    SkillVersionOut,
    StudioAuditEventOut,
    StudioOverviewOut,
    StudioPromoteRequest,
    StudioReviewRequest,
    StudioRollbackRequest,
    StudioRuleOut,
)
from vforge.studio.service import (
    create_rule_pack,
    create_rule_pack_version,
    create_skill,
    create_skill_version,
    generate_ai_candidate_version,
    get_studio_overview,
    promote_rule_pack_version,
    promote_skill_version,
    review_rule_pack_version,
    review_skill_version,
    rollback_rule_pack,
    rollback_skill,
    run_version_fixtures,
    sign_rule_pack_version,
    sign_skill_version,
    submit_rule_pack_version_for_review,
    submit_skill_version_for_review,
)
from vforge.studio.validators import generate_native_rule_skeleton

router = APIRouter(prefix="/api/v1/organizations/{org_id}/studio", tags=["studio"])


def _resolve_actor_type(actor_header: str | None, user: Any | None = None) -> str:
    """Resolve actor provenance using server-verified user identity plus restrictive header."""
    oidc_subject = str(getattr(user, "oidc_subject", "") or "").lower()
    email = str(getattr(user, "email", "") or "").lower()
    if oidc_subject.startswith(("ai-", "ai_agent:", "agent:")) or "ai-agent" in email:
        return StudioActorType.AI_AGENT.value
    if not actor_header:
        return StudioActorType.HUMAN.value
    cleaned = actor_header.strip().lower()
    if cleaned in {"ai", "ai_agent", "agent", "llm"}:
        return StudioActorType.AI_AGENT.value
    if cleaned == StudioActorType.HUMAN.value:
        return StudioActorType.HUMAN.value
    raise ForbiddenError("Invalid or restricted studio actor type header")


def _to_rule_out(rule: Any) -> StudioRuleOut:
    return StudioRuleOut(
        id=rule.id,
        rule_key=rule.rule_key,
        title=rule.title,
        engine=rule.engine,
        native_format=rule.native_format,
        risk_class=rule.risk_class,
        severity=rule.severity,
        confidence=rule.confidence,
        cwe_id=rule.cwe_id,
        rationale=rule.rationale,
        target_context=rule.target_context,
        network_requirements=rule.network_requirements,
        known_limitations=rule.known_limitations,
        timeout_seconds=rule.timeout_seconds,
        memory_budget_mb=rule.memory_budget_mb,
        native_content=rule.native_content,
        content_sha256=rule.content_sha256,
        expected_evidence_fields=list(rule.expected_evidence_fields or []),
        positive_fixtures=list(rule.positive_fixtures_json or []),
        negative_fixtures=list(rule.negative_fixtures_json or []),
        near_miss_fixtures=list(rule.near_miss_fixtures_json or []),
        static_validation_passed=rule.static_validation_passed,
        static_validation_errors=list(rule.static_validation_errors or []),
        created_at=rule.created_at,
    )


def _to_fixture_run_out(fr: Any) -> RuleFixtureRunOut:
    return RuleFixtureRunOut(
        id=fr.id,
        rule_pack_version_id=fr.rule_pack_version_id,
        corpus_ref=fr.corpus_ref,
        corpus_sha256=fr.corpus_sha256,
        executed_by=fr.executed_by,
        actor_type=fr.actor_type,
        total_positive=fr.total_positive,
        passed_positive=fr.passed_positive,
        total_negative=fr.total_negative,
        passed_negative=fr.passed_negative,
        total_near_miss=fr.total_near_miss,
        passed_near_miss=fr.passed_near_miss,
        false_positives=fr.false_positives,
        false_negatives=fr.false_negatives,
        total_duration_ms=fr.total_duration_ms,
        regression_passed=fr.regression_passed,
        rule_results_json=list(fr.rule_results_json or []),
        created_at=fr.created_at,
    )


def _to_pack_version_out(ver: Any) -> RulePackVersionOut:
    return RulePackVersionOut(
        id=ver.id,
        rule_pack_id=ver.rule_pack_id,
        version=ver.version,
        semver_change_type=ver.semver_change_type,
        channel=ver.channel,
        review_status=ver.review_status,
        creation_method=ver.creation_method,
        author_id=ver.author_id,
        author_actor_type=ver.author_actor_type,
        reviewer_id=ver.reviewer_id,
        approved_at=ver.approved_at,
        rejection_reason=ver.rejection_reason,
        compatibility_json=dict(ver.compatibility_json or {}),
        validation_summary_json=dict(ver.validation_summary_json or {}),
        ai_provenance_json=dict(ver.ai_provenance_json or {}),
        manifest_sha256=ver.manifest_sha256,
        signing_key_id=ver.signing_key_id,
        signed_by=ver.signed_by,
        signed_at=ver.signed_at,
        is_active_canary=ver.is_active_canary,
        is_active_stable=ver.is_active_stable,
        fixture_regression_passed=ver.fixture_regression_passed,
        true_positive_count=ver.true_positive_count,
        false_positive_count=ver.false_positive_count,
        false_negative_count=ver.false_negative_count,
        rules=[_to_rule_out(r) for r in (ver.rules or [])],
        fixture_runs=[_to_fixture_run_out(fr) for fr in (ver.fixture_runs or [])],
        created_at=ver.created_at,
    )


def _to_skill_version_out(sv: Any) -> SkillVersionOut:
    return SkillVersionOut(
        id=sv.id,
        skill_id=sv.skill_id,
        version=sv.version,
        intent_description=sv.intent_description,
        allowed_capabilities=list(sv.allowed_capabilities or []),
        forbidden_actions=list(sv.forbidden_actions or []),
        supported_agent_versions=list(sv.supported_agent_versions or []),
        playbook_steps_json=list(sv.playbook_steps_json or []),
        creation_method=sv.creation_method,
        author_id=sv.author_id,
        author_actor_type=sv.author_actor_type,
        review_status=sv.review_status,
        reviewer_id=sv.reviewer_id,
        approved_at=sv.approved_at,
        rejection_reason=sv.rejection_reason,
        content_sha256=sv.content_sha256,
        signing_key_id=sv.signing_key_id,
        signed_by=sv.signed_by,
        signed_at=sv.signed_at,
        channel=sv.channel,
        is_active_canary=sv.is_active_canary,
        is_active_stable=sv.is_active_stable,
        created_at=sv.created_at,
    )


@router.get("/overview", response_model=StudioOverviewOut)
async def studio_overview_route(
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
) -> StudioOverviewOut:
    assert_permission(ctx.role, Permission.STUDIO_READ)
    data = await get_studio_overview(db, organization_id=ctx.org_id)
    return StudioOverviewOut(
        supported_engines=["opengrep", "nuclei", "checkov", "gitleaks", "zap", "nmap"],
        rule_packs=[
            RulePackOut(
                id=p.id,
                organization_id=p.organization_id,
                slug=p.slug,
                title=p.title,
                description=p.description,
                owner_team=p.owner_team,
                created_by=p.created_by,
                is_active=p.is_active,
                versions=[_to_pack_version_out(v) for v in (p.versions or [])],
                created_at=p.created_at,
                updated_at=p.updated_at,
            )
            for p in data["rule_packs"]
        ],
        skills=[
            AssessmentSkillOut(
                id=s.id,
                organization_id=s.organization_id,
                slug=s.slug,
                title=s.title,
                description=s.description,
                owner_team=s.owner_team,
                created_by=s.created_by,
                is_active=s.is_active,
                versions=[_to_skill_version_out(v) for v in (s.versions or [])],
                created_at=s.created_at,
                updated_at=s.updated_at,
            )
            for s in data["skills"]
        ],
        audit_events=[
            StudioAuditEventOut(
                id=ev.id,
                entity_type=ev.entity_type,
                entity_id=ev.entity_id,
                action=ev.action,
                actor_email=ev.actor_email,
                actor_type=ev.actor_type,
                previous_state=ev.previous_state,
                new_state=ev.new_state,
                details_json=dict(ev.details_json or {}),
                occurred_at=ev.occurred_at,
            )
            for ev in data["audit_events"]
        ],
    )


@router.get("/skeleton/{engine}")
async def studio_rule_skeleton_route(
    engine: StudioEngine,
    rule_key: str = Query(default="vf-custom-rule-001", min_length=3, max_length=120),  # noqa: B008
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
) -> dict[str, str]:
    assert_permission(ctx.role, Permission.STUDIO_READ)
    return generate_native_rule_skeleton(engine.value, rule_key)


@router.post("/rule-packs", response_model=RulePackOut, status_code=status.HTTP_201_CREATED)
async def create_rule_pack_route(
    payload: RulePackCreateRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    _: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
) -> RulePackOut:
    assert_permission(ctx.role, Permission.STUDIO_AUTHOR)
    pack = await create_rule_pack(
        db,
        organization_id=ctx.org_id,
        slug=payload.slug,
        title=payload.title,
        description=payload.description,
        owner_team=payload.owner_team,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
    )
    out = RulePackOut(
        id=pack.id,
        organization_id=pack.organization_id,
        slug=pack.slug,
        title=pack.title,
        description=pack.description,
        owner_team=pack.owner_team,
        created_by=pack.created_by,
        is_active=pack.is_active,
        versions=[],
        created_at=pack.created_at,
        updated_at=pack.updated_at,
    )
    await db.commit()
    return out


@router.post(
    "/rule-packs/{pack_id}/versions",
    response_model=RulePackVersionOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_rule_pack_version_route(
    pack_id: uuid.UUID,
    payload: RulePackVersionCreateRequest,
    x_vforge_actor_type: str | None = Header(default=None),
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    _: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
) -> RulePackVersionOut:
    assert_permission(ctx.role, Permission.STUDIO_AUTHOR)
    ver = await create_rule_pack_version(
        db,
        organization_id=ctx.org_id,
        rule_pack_id=pack_id,
        version=payload.version,
        semver_change_type=payload.semver_change_type,
        compatibility=payload.compatibility,
        rules_payload=[r.model_dump() for r in payload.rules],
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
        actor_type=_resolve_actor_type(x_vforge_actor_type, ctx.user),
    )
    out = _to_pack_version_out(ver)
    await db.commit()
    return out


@router.post(
    "/rule-packs/{pack_id}/ai-draft",
    response_model=RulePackVersionOut,
    status_code=status.HTTP_201_CREATED,
)
async def generate_ai_draft_route(
    pack_id: uuid.UUID,
    payload: AiCandidateGenerateRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    _: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
) -> RulePackVersionOut:
    assert_permission(ctx.role, Permission.STUDIO_AUTHOR)
    ver = await generate_ai_candidate_version(
        db,
        organization_id=ctx.org_id,
        rule_pack_id=pack_id,
        version=payload.version,
        engine=payload.engine,
        rule_key=payload.rule_key,
        title=payload.title,
        cwe_id=payload.cwe_id,
        target_context=payload.target_context,
        untrusted_source_snippet=payload.untrusted_source_snippet,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
    )
    out = _to_pack_version_out(ver)
    await db.commit()
    return out


@router.post(
    "/rule-pack-versions/{version_id}/run-fixtures",
    response_model=RuleFixtureRunOut,
)
async def run_fixtures_route(
    version_id: uuid.UUID,
    corpus_ref: str = Query(default="inline-pack-corpus", min_length=1, max_length=200),  # noqa: B008
    x_vforge_actor_type: str | None = Header(default=None),
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    _: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
) -> RuleFixtureRunOut:
    assert_permission(ctx.role, Permission.STUDIO_AUTHOR)
    fr = await run_version_fixtures(
        db,
        organization_id=ctx.org_id,
        version_id=version_id,
        corpus_ref=corpus_ref,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
        actor_type=_resolve_actor_type(x_vforge_actor_type, ctx.user),
    )
    out = _to_fixture_run_out(fr)
    await db.commit()
    return out


@router.post(
    "/rule-pack-versions/{version_id}/submit-review",
    response_model=RulePackVersionOut,
)
async def submit_pack_review_route(
    version_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    _: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
) -> RulePackVersionOut:
    assert_permission(ctx.role, Permission.STUDIO_AUTHOR)
    ver = await submit_rule_pack_version_for_review(
        db,
        organization_id=ctx.org_id,
        version_id=version_id,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
    )
    out = _to_pack_version_out(ver)
    await db.commit()
    return out


@router.post(
    "/rule-pack-versions/{version_id}/review",
    response_model=RulePackVersionOut,
)
async def review_pack_version_route(
    version_id: uuid.UUID,
    payload: StudioReviewRequest,
    x_vforge_actor_type: str | None = Header(default=None),
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    _: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
) -> RulePackVersionOut:
    actor_type = _resolve_actor_type(x_vforge_actor_type, ctx.user)
    if actor_type != StudioActorType.HUMAN.value:
        raise ForbiddenError("AI agents cannot review or approve rule packs")
    assert_permission(ctx.role, Permission.STUDIO_REVIEW)
    ver = await review_rule_pack_version(
        db,
        organization_id=ctx.org_id,
        version_id=version_id,
        decision=payload.decision,
        comment=payload.comment,
        reviewer_id=ctx.user.id,
        reviewer_email=ctx.user.email,
        actor_type=actor_type,
    )
    out = _to_pack_version_out(ver)
    await db.commit()
    return out


@router.post(
    "/rule-pack-versions/{version_id}/sign",
    response_model=RulePackVersionOut,
)
async def sign_pack_version_route(
    version_id: uuid.UUID,
    x_vforge_actor_type: str | None = Header(default=None),
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
    _: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
) -> RulePackVersionOut:
    actor_type = _resolve_actor_type(x_vforge_actor_type, ctx.user)
    if actor_type != StudioActorType.HUMAN.value:
        raise ForbiddenError("AI agents cannot cryptographically sign rule packs")
    assert_permission(ctx.role, Permission.STUDIO_PROMOTE)
    ver = await sign_rule_pack_version(
        db,
        organization_id=ctx.org_id,
        version_id=version_id,
        signer_id=ctx.user.id,
        signer_email=ctx.user.email,
        actor_type=actor_type,
        settings=settings,
    )
    out = _to_pack_version_out(ver)
    await db.commit()
    return out


@router.post(
    "/rule-pack-versions/{version_id}/promote",
    response_model=RulePackVersionOut,
)
async def promote_pack_version_route(
    version_id: uuid.UUID,
    payload: StudioPromoteRequest,
    x_vforge_actor_type: str | None = Header(default=None),
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
    _: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
) -> RulePackVersionOut:
    actor_type = _resolve_actor_type(x_vforge_actor_type, ctx.user)
    if actor_type != StudioActorType.HUMAN.value:
        raise ForbiddenError("AI agents cannot promote rule packs")
    assert_permission(ctx.role, Permission.STUDIO_PROMOTE)
    ver = await promote_rule_pack_version(
        db,
        organization_id=ctx.org_id,
        version_id=version_id,
        target_channel=payload.target_channel,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
        actor_type=actor_type,
        settings=settings,
    )
    out = _to_pack_version_out(ver)
    await db.commit()
    return out


@router.post(
    "/rule-packs/{pack_id}/rollback",
    response_model=RulePackVersionOut,
)
async def rollback_pack_route(
    pack_id: uuid.UUID,
    payload: StudioRollbackRequest,
    x_vforge_actor_type: str | None = Header(default=None),
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
    _: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
) -> RulePackVersionOut:
    actor_type = _resolve_actor_type(x_vforge_actor_type, ctx.user)
    if actor_type != StudioActorType.HUMAN.value:
        raise ForbiddenError("AI agents cannot roll back or quarantine rule packs")
    assert_permission(ctx.role, Permission.STUDIO_PROMOTE)
    ver = await rollback_rule_pack(
        db,
        organization_id=ctx.org_id,
        rule_pack_id=pack_id,
        target_channel=payload.target_channel,
        reason=payload.reason,
        quarantine=payload.quarantine,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
        actor_type=actor_type,
        settings=settings,
    )
    out = _to_pack_version_out(ver)
    await db.commit()
    return out


@router.post("/skills", response_model=AssessmentSkillOut, status_code=status.HTTP_201_CREATED)
async def create_skill_route(
    payload: AssessmentSkillCreateRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    _: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
) -> AssessmentSkillOut:
    assert_permission(ctx.role, Permission.STUDIO_AUTHOR)
    skill = await create_skill(
        db,
        organization_id=ctx.org_id,
        slug=payload.slug,
        title=payload.title,
        description=payload.description,
        owner_team=payload.owner_team,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
    )
    out = AssessmentSkillOut(
        id=skill.id,
        organization_id=skill.organization_id,
        slug=skill.slug,
        title=skill.title,
        description=skill.description,
        owner_team=skill.owner_team,
        created_by=skill.created_by,
        is_active=skill.is_active,
        versions=[],
        created_at=skill.created_at,
        updated_at=skill.updated_at,
    )
    await db.commit()
    return out


@router.post(
    "/skills/{skill_id}/versions",
    response_model=SkillVersionOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_skill_version_route(
    skill_id: uuid.UUID,
    payload: SkillVersionCreateRequest,
    x_vforge_actor_type: str | None = Header(default=None),
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    _: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
) -> SkillVersionOut:
    assert_permission(ctx.role, Permission.STUDIO_AUTHOR)
    sv = await create_skill_version(
        db,
        organization_id=ctx.org_id,
        skill_id=skill_id,
        version=payload.version,
        intent_description=payload.intent_description,
        allowed_capabilities=payload.allowed_capabilities,
        forbidden_actions=payload.forbidden_actions,
        supported_agent_versions=payload.supported_agent_versions,
        playbook_steps=payload.playbook_steps_json,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
        actor_type=_resolve_actor_type(x_vforge_actor_type, ctx.user),
    )
    out = _to_skill_version_out(sv)
    await db.commit()
    return out


@router.post("/skill-versions/{version_id}/submit-review", response_model=SkillVersionOut)
async def submit_skill_review_route(
    version_id: uuid.UUID,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    _: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
) -> SkillVersionOut:
    assert_permission(ctx.role, Permission.STUDIO_AUTHOR)
    sv = await submit_skill_version_for_review(
        db,
        organization_id=ctx.org_id,
        version_id=version_id,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
    )
    out = _to_skill_version_out(sv)
    await db.commit()
    return out


@router.post("/skill-versions/{version_id}/review", response_model=SkillVersionOut)
async def review_skill_version_route(
    version_id: uuid.UUID,
    payload: StudioReviewRequest,
    x_vforge_actor_type: str | None = Header(default=None),
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    _: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
) -> SkillVersionOut:
    actor_type = _resolve_actor_type(x_vforge_actor_type, ctx.user)
    if actor_type != StudioActorType.HUMAN.value:
        raise ForbiddenError("AI agents cannot approve or reject assessment skills")
    assert_permission(ctx.role, Permission.STUDIO_REVIEW)
    sv = await review_skill_version(
        db,
        organization_id=ctx.org_id,
        version_id=version_id,
        decision=payload.decision,
        comment=payload.comment,
        reviewer_id=ctx.user.id,
        reviewer_email=ctx.user.email,
        actor_type=actor_type,
    )
    out = _to_skill_version_out(sv)
    await db.commit()
    return out


@router.post("/skill-versions/{version_id}/sign", response_model=SkillVersionOut)
async def sign_skill_version_route(
    version_id: uuid.UUID,
    x_vforge_actor_type: str | None = Header(default=None),
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
    _: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
) -> SkillVersionOut:
    actor_type = _resolve_actor_type(x_vforge_actor_type, ctx.user)
    if actor_type != StudioActorType.HUMAN.value:
        raise ForbiddenError("AI agents cannot sign assessment skills")
    assert_permission(ctx.role, Permission.STUDIO_PROMOTE)
    sv = await sign_skill_version(
        db,
        organization_id=ctx.org_id,
        version_id=version_id,
        signer_id=ctx.user.id,
        signer_email=ctx.user.email,
        actor_type=actor_type,
        settings=settings,
    )
    out = _to_skill_version_out(sv)
    await db.commit()
    return out


@router.post("/skill-versions/{version_id}/promote", response_model=SkillVersionOut)
async def promote_skill_version_route(
    version_id: uuid.UUID,
    payload: StudioPromoteRequest,
    x_vforge_actor_type: str | None = Header(default=None),
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
    _: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
) -> SkillVersionOut:
    actor_type = _resolve_actor_type(x_vforge_actor_type, ctx.user)
    if actor_type != StudioActorType.HUMAN.value:
        raise ForbiddenError("AI agents cannot promote assessment skills")
    assert_permission(ctx.role, Permission.STUDIO_PROMOTE)
    sv = await promote_skill_version(
        db,
        organization_id=ctx.org_id,
        version_id=version_id,
        target_channel=payload.target_channel,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
        actor_type=actor_type,
        settings=settings,
    )
    out = _to_skill_version_out(sv)
    await db.commit()
    return out


@router.post("/skills/{skill_id}/rollback", response_model=SkillVersionOut)
async def rollback_skill_route(
    skill_id: uuid.UUID,
    payload: StudioRollbackRequest,
    x_vforge_actor_type: str | None = Header(default=None),
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
    _: None = Depends(enforce_sensitive_rate_limit),  # noqa: B008
) -> SkillVersionOut:
    actor_type = _resolve_actor_type(x_vforge_actor_type, ctx.user)
    if actor_type != StudioActorType.HUMAN.value:
        raise ForbiddenError("AI agents cannot roll back assessment skills")
    assert_permission(ctx.role, Permission.STUDIO_PROMOTE)
    sv = await rollback_skill(
        db,
        organization_id=ctx.org_id,
        skill_id=skill_id,
        target_channel=payload.target_channel,
        reason=payload.reason,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
        actor_type=actor_type,
        settings=settings,
    )
    out = _to_skill_version_out(sv)
    await db.commit()
    return out
