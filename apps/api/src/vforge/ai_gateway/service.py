"""Phase 12 Runtime AI Provider Gateway service, failover, retention gates & OPA tool broker."""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.ai_gateway.classification import classify_and_redact_payload
from vforge.ai_gateway.providers import (
    ModelRequest,
    ModelResponse,
    ProviderInvocationError,
    build_provider_adapter,
    validate_provider_endpoint_url,
    validate_secret_reference,
)
from vforge.ai_gateway.rag import index_knowledge_document, retrieve_tenant_knowledge
from vforge.ai_gateway.roles import FORBIDDEN_PRIVILEGED_TOOL_ACTIONS, get_role_profile
from vforge.config import Settings, get_settings
from vforge.errors import (
    ConflictError,
    ForbiddenError,
    VForgeError,
    NotFoundError,
    ValidationError,
)
from vforge.models.ai_governance import (
    AiAuditEvent,
    AiFeedbackLabel,
    AiModelCatalog,
    AiProviderConfig,
    AiRun,
    AiTaskRequest,
    AiToolApproval,
    AiToolProposal,
    KnowledgeDocument,
    ModelEvaluationRun,
)
from vforge.models.enums import (
    AiAuditAction,
    AiProviderClass,
    AiTaskStatus,
    AiToolProposalStatus,
)

logger = logging.getLogger(__name__)


def _record_ai_audit(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    action: AiAuditAction,
    actor_id: uuid.UUID,
    actor_email: str,
    provider_class: str | None = None,
    model_slug: str | None = None,
    data_classification: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    db.add(
        AiAuditEvent(
            id=uuid.uuid4(),
            organization_id=organization_id,
            action=action.value,
            actor_id=actor_id,
            actor_email=actor_email,
            provider_class=provider_class,
            model_slug=model_slug,
            data_classification=data_classification,
            details_json=details or {},
        )
    )


async def list_model_catalog(db: AsyncSession) -> list[AiModelCatalog]:
    rows = (
        (
            await db.execute(
                select(AiModelCatalog)
                .where(AiModelCatalog.is_active.is_(True))
                .order_by(AiModelCatalog.provider_class, AiModelCatalog.model_slug)
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


async def configure_provider(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    provider_class: str,
    display_name: str,
    endpoint_url: str | None,
    secret_ref: str | None,
    local_only_mode: bool,
    allowed_models: list[str],
    monthly_budget_usd: float,
    max_tokens_per_request: int,
    actor_id: uuid.UUID,
    actor_email: str,
) -> AiProviderConfig:
    """Create or register a tenant-scoped AI provider config storing credential refs only."""
    if provider_class not in {m.value for m in AiProviderClass}:
        raise ValidationError(f"Unsupported AI provider_class '{provider_class}'")
    validate_secret_reference(
        secret_ref,
        provider_class=provider_class,
        organization_id=organization_id,
    )
    validate_provider_endpoint_url(endpoint_url, provider_class=provider_class)

    clean_models = [m.strip() for m in allowed_models if m.strip()]
    if not clean_models:
        raise ValidationError("At least one allowlisted model slug is required per provider")
    catalog_rows = (
        (
            await db.execute(
                select(AiModelCatalog.model_slug).where(
                    AiModelCatalog.model_slug.in_(clean_models),
                    AiModelCatalog.provider_class == provider_class,
                    AiModelCatalog.is_active.is_(True),
                )
            )
        )
        .scalars()
        .all()
    )
    missing = sorted(set(clean_models) - set(catalog_rows))
    if missing:
        raise ValidationError(
            f"Models not found or mismatched provider_class '{provider_class}': {missing}"
        )

    cfg = AiProviderConfig(
        id=uuid.uuid4(),
        organization_id=organization_id,
        provider_class=provider_class,
        display_name=display_name.strip(),
        endpoint_url=endpoint_url.strip() if endpoint_url else None,
        secret_ref=secret_ref.strip() if secret_ref else None,
        local_only_mode=local_only_mode,
        is_enabled=True,
        allowed_models_json=clean_models,
        monthly_budget_usd=monthly_budget_usd,
        max_tokens_per_request=max_tokens_per_request,
        retention_consent_approved=False,
        created_by=actor_id,
    )
    try:
        async with db.begin_nested():
            db.add(cfg)
            await db.flush()
    except IntegrityError as exc:
        raise ConflictError(
            f"AI provider display_name '{display_name.strip()}' already exists for organization"
        ) from exc
    _record_ai_audit(
        db,
        organization_id=organization_id,
        action=AiAuditAction.PROVIDER_CONFIGURED,
        actor_id=actor_id,
        actor_email=actor_email,
        provider_class=provider_class,
        details={
            "provider_config_id": str(cfg.id),
            "display_name": cfg.display_name,
            "local_only_mode": local_only_mode,
            "allowed_models": clean_models,
            "monthly_budget_usd": monthly_budget_usd,
        },
    )
    await db.flush()
    return cfg


async def set_provider_retention_consent(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    provider_config_id: uuid.UUID,
    approved: bool,
    local_only_mode: bool | None = None,
    actor_id: uuid.UUID,
    actor_email: str,
) -> AiProviderConfig:
    """Explicit admin consent for non-ZDR retention providers (e.g., 30-day retained models)."""
    cfg = (
        await db.execute(
            select(AiProviderConfig)
            .where(
                AiProviderConfig.organization_id == organization_id,
                AiProviderConfig.id == provider_config_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if cfg is None:
        raise NotFoundError("AI provider config not found")

    now = datetime.now(UTC)
    cfg.retention_consent_approved = approved
    cfg.retention_consent_approved_by = actor_id if approved else None
    cfg.retention_consent_approved_at = now if approved else None
    if local_only_mode is not None:
        cfg.local_only_mode = local_only_mode
    cfg.updated_at = now
    await db.flush()

    _record_ai_audit(
        db,
        organization_id=organization_id,
        action=AiAuditAction.RETENTION_CONSENT_UPDATED,
        actor_id=actor_id,
        actor_email=actor_email,
        provider_class=cfg.provider_class,
        details={
            "provider_config_id": str(cfg.id),
            "retention_consent_approved": approved,
            "local_only_mode": cfg.local_only_mode,
        },
    )
    await db.flush()
    return cfg


async def _current_month_spend_usd(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    provider_config_id: uuid.UUID,
) -> float:
    month_start = datetime.now(UTC).replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    total = (
        await db.execute(
            select(func.coalesce(func.sum(AiRun.estimated_cost_usd), 0.0)).where(
                AiRun.organization_id == organization_id,
                AiRun.provider_config_id == provider_config_id,
                AiRun.created_at >= month_start,
            )
        )
    ).scalar_one()
    return float(total or 0.0)


async def _validate_provider_egress_policy(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    cfg: AiProviderConfig,
    catalog: AiModelCatalog,
    classification_value: str,
    consent_acknowledged: bool,
    require_local_only: bool,
    org_local_only_enforced: bool,
    max_tokens: int,
    estimated_input_tokens: int,
) -> None:
    if not cfg.is_enabled:
        raise ForbiddenError(f"AI provider config '{cfg.display_name}' is disabled")
    if catalog.provider_class != cfg.provider_class:
        raise ValidationError(
            f"Model '{catalog.model_slug}' belongs to '{catalog.provider_class}', "
            f"not '{cfg.provider_class}'"
        )
    if not cfg.allowed_models_json or catalog.model_slug not in cfg.allowed_models_json:
        raise ForbiddenError(
            f"Model '{catalog.model_slug}' is not allowlisted for provider '{cfg.display_name}'"
        )
    if (cfg.local_only_mode or require_local_only or org_local_only_enforced) and (
        not catalog.is_local
    ):
        raise ForbiddenError(
            f"Local-only policy blocks external egress to model '{catalog.model_slug}'"
        )
    if (
        (
            catalog.requires_retention_consent
            and classification_value in {"confidential", "restricted"}
        )
        or (not catalog.is_local and classification_value == "restricted")
    ) and (not cfg.retention_consent_approved or not consent_acknowledged):
        raise ForbiddenError(
            f"Model '{catalog.model_slug}' requires explicit admin retention consent and "
            "operator acknowledgment before external egress of confidential/restricted or "
            f"{catalog.retention_days}-day retained payloads"
        )
    if max_tokens > cfg.max_tokens_per_request:
        raise ForbiddenError(
            f"Requested max_tokens ({max_tokens}) exceeds provider limit "
            f"({cfg.max_tokens_per_request})"
        )
    # Price worst-case upper bound using full requested max_tokens
    est_cost = (estimated_input_tokens / 1000.0) * catalog.cost_per_1k_input_usd + (
        max_tokens / 1000.0
    ) * catalog.cost_per_1k_output_usd
    spent = await _current_month_spend_usd(
        db, organization_id=organization_id, provider_config_id=cfg.id
    )
    if spent + est_cost > cfg.monthly_budget_usd:
        raise ForbiddenError(
            f"Monthly AI budget (${cfg.monthly_budget_usd:.2f}) exceeded for '{cfg.display_name}'"
        )


async def evaluate_tool_proposal_with_opa(
    *,
    settings: Settings,
    organization_id: uuid.UUID,
    user_id: uuid.UUID,
    role: str,
    tool_action: str,
    opa_action: str = "ai:invoke",
    requested_by: uuid.UUID | None = None,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> tuple[bool, str]:
    """Fail-closed OPA check on every AI-proposed or human-approved tool invocation."""
    normalized_action = tool_action.strip().lower()
    if not normalized_action or normalized_action in FORBIDDEN_PRIVILEGED_TOOL_ACTIONS:
        return False, f"Tool action '{normalized_action}' is permanently forbidden for AI agents"

    endpoint = f"{settings.opa_url.rstrip('/')}/v1/data/vforge/authz/allow"
    resource: dict[str, Any] = {
        "organization_id": str(organization_id),
        "tool_action": normalized_action,
    }
    if requested_by is not None:
        resource["requested_by"] = str(requested_by)

    opa_input = {
        "action": opa_action,
        "subject": {
            "id": str(user_id),
            "role": role,
            "organization_id": str(organization_id),
            "authenticated": True,
        },
        "resource": resource,
    }
    try:
        async with httpx.AsyncClient(timeout=5.0, transport=opa_transport) as client:
            resp = await client.post(endpoint, json={"input": opa_input})
    except httpx.HTTPError:
        return False, "OPA policy engine unreachable; failing closed"
    if resp.status_code != 200:
        return False, f"OPA returned HTTP {resp.status_code}; failing closed"
    try:
        allowed = bool(resp.json().get("result", False))
    except ValueError:
        return False, "OPA returned malformed JSON; failing closed"
    if not allowed:
        return False, f"OPA denied tool action '{tool_action}'"
    return True, f"OPA permitted bounded proposal '{tool_action}' pending human approval"


async def execute_ai_task(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    task_type: str,
    role_name: str,
    raw_prompt: str,
    model_slug: str,
    provider_config_ids: list[uuid.UUID],
    fallback_model_slugs: dict[uuid.UUID, str] | None = None,
    requested_classification: str | None = None,
    consent_acknowledged: bool = False,
    require_local_only: bool = False,
    rag_query: str | None = None,
    proposed_tools: list[dict[str, Any]] | None = None,
    max_tokens: int = 2048,
    prior_model_slug: str | None = None,
    actor_id: uuid.UUID,
    actor_email: str,
    actor_role: str,
    correlation_id: str | None = None,
    settings: Settings | None = None,
    provider_transports: dict[uuid.UUID, httpx.AsyncBaseTransport] | None = None,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Run governed multi-agent inference with pre-egress gates, RAG, failover, and OPA tools."""
    cfg_settings = settings or get_settings()
    try:
        role_profile = get_role_profile(role_name)
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc

    if not provider_config_ids:
        raise ValidationError("At least one configured provider_config_id must be supplied")
    if (
        role_profile.require_independent_model
        and prior_model_slug
        and prior_model_slug.strip().lower() == model_slug.strip().lower()
    ):
        raise ForbiddenError(
            f"Role '{role_name}' requires an independent model different from '{prior_model_slug}'"
        )

    # Classify, redact secrets/PII, and isolate untrusted blocks before any AI call
    cls_res = classify_and_redact_payload(
        raw_prompt, requested_classification=requested_classification
    )

    dedup_ids: list[uuid.UUID] = []
    for pid in provider_config_ids:
        if pid not in dedup_ids:
            dedup_ids.append(pid)

    configs = {
        c.id: c
        for c in (
            await db.execute(
                select(AiProviderConfig)
                .where(
                    AiProviderConfig.organization_id == organization_id,
                    AiProviderConfig.id.in_(dedup_ids),
                )
                .order_by(AiProviderConfig.id)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    }
    if len(configs) != len(dedup_ids):
        missing = [str(p) for p in dedup_ids if p not in configs]
        raise NotFoundError(f"Unknown AI provider config(s) for organization: {missing}")

    # Enforce org-wide local_only_mode if any active config locks tenant to local-only
    org_local_count = (
        await db.execute(
            select(func.count(AiProviderConfig.id)).where(
                AiProviderConfig.organization_id == organization_id,
                AiProviderConfig.local_only_mode.is_(True),
                AiProviderConfig.is_enabled.is_(True),
            )
        )
    ).scalar_one()
    org_local_only_enforced = int(org_local_count or 0) > 0

    task_req = AiTaskRequest(
        id=uuid.uuid4(),
        organization_id=organization_id,
        task_type=task_type.strip(),
        role_name=role_name,
        data_classification=cls_res.classification.value,
        redaction_applied=cls_res.redaction_applied,
        prompt_injection_detected=cls_res.prompt_injection_detected,
        consent_acknowledged=consent_acknowledged,
        provider_config_id=dedup_ids[0],
        model_slug=model_slug,
        input_snapshot_sha256=cls_res.raw_sha256,
        input_summary_redacted=cls_res.redacted_text[:1000],
        status=AiTaskStatus.PENDING.value,
        requested_by=actor_id,
    )
    db.add(task_req)
    await db.flush()

    rag_hits = await retrieve_tenant_knowledge(
        db,
        organization_id=organization_id,
        query=rag_query or cls_res.redacted_text[:400],
        limit=4,
    )
    rag_texts: list[str] = []
    effective_classification = cls_res.classification.value
    effective_redacted = cls_res.redaction_applied
    effective_injection = cls_res.prompt_injection_detected
    rank = {"public": 0, "internal": 1, "confidential": 2, "restricted": 3}
    for hit in rag_hits:
        rag_cls = classify_and_redact_payload(
            f"[{hit['source_type']}:{hit['slug']}] {hit['excerpt']}",
            wrapper_tag="untrusted_rag_context",
        )
        rag_texts.append(rag_cls.wrapped_untrusted_text)
        if rank[rag_cls.classification.value] > rank[effective_classification]:
            effective_classification = rag_cls.classification.value
        effective_redacted = effective_redacted or rag_cls.redaction_applied
        effective_injection = effective_injection or rag_cls.prompt_injection_detected

    task_req.data_classification = effective_classification
    task_req.redaction_applied = effective_redacted
    task_req.prompt_injection_detected = effective_injection

    prompt_chars = len(cls_res.wrapped_untrusted_text) + sum(len(x) for x in rag_texts)
    est_in_tokens = max(32, prompt_chars // 4)
    chosen_cfg: AiProviderConfig | None = None
    chosen_catalog: AiModelCatalog | None = None
    model_response: ModelResponse | None = None
    fallback_triggered = False
    last_runtime_error: str | None = None

    for idx, pid in enumerate(dedup_ids):
        p_cfg = configs[pid]
        candidate_model = (
            model_slug if idx == 0 else (fallback_model_slugs or {}).get(pid, model_slug)
        )
        cat_row = (
            await db.execute(
                select(AiModelCatalog).where(
                    AiModelCatalog.model_slug == candidate_model,
                    AiModelCatalog.is_active.is_(True),
                )
            )
        ).scalar_one_or_none()
        if cat_row is None:
            if idx == 0:
                task_req.status = AiTaskStatus.BLOCKED.value
                task_req.block_reason = f"Unknown or inactive catalog model '{candidate_model}'"
                await db.flush()
                raise ValidationError(task_req.block_reason)
            continue

        try:
            await _validate_provider_egress_policy(
                db,
                organization_id=organization_id,
                cfg=p_cfg,
                catalog=cat_row,
                classification_value=effective_classification,
                consent_acknowledged=consent_acknowledged,
                require_local_only=require_local_only,
                org_local_only_enforced=org_local_only_enforced,
                max_tokens=max_tokens,
                estimated_input_tokens=est_in_tokens,
            )
        except ForbiddenError as exc:
            # Never bypass policy denials on primary provider via fallback
            if idx == 0:
                task_req.status = AiTaskStatus.BLOCKED.value
                task_req.block_reason = exc.message
                logger.warning(
                    "Blocked AI task egress org=%s role=%s model=%s reason=%s",
                    organization_id,
                    role_name,
                    candidate_model,
                    exc.message,
                )
                raise
            last_runtime_error = exc.message
            continue

        adapter = build_provider_adapter(
            provider_class=p_cfg.provider_class,
            model_slug=cat_row.model_slug,
            endpoint_url=p_cfg.endpoint_url,
            secret_ref=p_cfg.secret_ref,
            is_local=cat_row.is_local,
            transport=(provider_transports or {}).get(pid),
        )
        req = ModelRequest(
            task_type=task_type,
            role_name=role_name,
            prompt_template_version=role_profile.prompt_template_version,
            system_directive=role_profile.system_directive,
            wrapped_user_prompt=cls_res.wrapped_untrusted_text,
            rag_context=rag_texts,
            model_slug=cat_row.model_slug,
            max_tokens=max_tokens,
            correlation_id=correlation_id,
            proposed_tools=proposed_tools or [],
        )
        try:
            model_response = await adapter.generate_structured(req)
            chosen_cfg = p_cfg
            chosen_catalog = cat_row
            fallback_triggered = idx > 0
            break
        except ProviderInvocationError as exc:
            last_runtime_error = str(exc)
            logger.warning(
                "AI provider invocation failed org=%s provider=%s err=%s",
                organization_id,
                p_cfg.display_name,
                exc,
            )
            continue

    if model_response is None or chosen_cfg is None or chosen_catalog is None:
        task_req.status = AiTaskStatus.FAILED.value
        task_req.block_reason = last_runtime_error or "All configured AI providers failed"
        await db.flush()
        raise VForgeError(
            f"All AI providers unavailable or failed: {task_req.block_reason}",
            error_code="ai_provider_unavailable",
        )

    actual_cost = (
        model_response.token_input_count / 1000.0
    ) * chosen_catalog.cost_per_1k_input_usd + (
        model_response.token_output_count / 1000.0
    ) * chosen_catalog.cost_per_1k_output_usd

    out_canonical = json.dumps(model_response.structured_output, sort_keys=True)
    out_sha = hashlib.sha256(out_canonical.encode("utf-8")).hexdigest()

    run = AiRun(
        id=uuid.uuid4(),
        organization_id=organization_id,
        task_request_id=task_req.id,
        provider_config_id=chosen_cfg.id,
        role_name=role_name,
        provider_class=chosen_cfg.provider_class,
        model_slug=chosen_catalog.model_slug,
        prompt_template_version=role_profile.prompt_template_version,
        fallback_triggered=fallback_triggered,
        input_sha256=cls_res.raw_sha256,
        output_sha256=out_sha,
        structured_output_json=model_response.structured_output,
        rationale_summary=model_response.rationale_summary,
        uncertainty_notes=model_response.uncertainty_notes,
        token_input_count=model_response.token_input_count,
        token_output_count=model_response.token_output_count,
        estimated_cost_usd=round(actual_cost, 6),
        latency_ms=model_response.latency_ms,
        status=AiTaskStatus.COMPLETED.value,
    )
    db.add(run)
    task_req.status = AiTaskStatus.COMPLETED.value
    await db.flush()

    created_proposals: list[AiToolProposal] = []
    for prop in model_response.proposed_tools:
        action = str(prop.get("tool_action", "")).strip().lower()
        target_type = str(prop.get("target_resource_type", "unknown")).strip()[:64]
        target_id = str(prop.get("target_resource_id", "none")).strip()[:128]
        raw_args = prop.get("arguments_json")
        args = dict(raw_args) if isinstance(raw_args, dict) else {}

        if not action or action not in role_profile.allowed_tool_actions:
            opa_allowed, opa_reason = (
                False,
                f"Tool action '{action}' is outside role '{role_name}' allowlist",
            )
        else:
            opa_allowed, opa_reason = await evaluate_tool_proposal_with_opa(
                settings=cfg_settings,
                organization_id=organization_id,
                user_id=actor_id,
                role=actor_role,
                tool_action=action,
                opa_action="ai:invoke",
                opa_transport=opa_transport,
            )

        prop_row = AiToolProposal(
            id=uuid.uuid4(),
            organization_id=organization_id,
            ai_run_id=run.id,
            tool_action=action,
            target_resource_type=target_type,
            target_resource_id=target_id,
            arguments_json=args,
            opa_allowed=opa_allowed,
            opa_decision_reason=opa_reason,
            status=(
                AiToolProposalStatus.PENDING_HUMAN_APPROVAL.value
                if opa_allowed
                else AiToolProposalStatus.OPA_DENIED.value
            ),
        )
        db.add(prop_row)
        created_proposals.append(prop_row)
        _record_ai_audit(
            db,
            organization_id=organization_id,
            action=AiAuditAction.TOOL_PROPOSED,
            actor_id=actor_id,
            actor_email=actor_email,
            provider_class=chosen_cfg.provider_class,
            model_slug=chosen_catalog.model_slug,
            data_classification=cls_res.classification.value,
            details={
                "tool_action": action,
                "opa_allowed": opa_allowed,
                "reason": opa_reason,
            },
        )

    if fallback_triggered:
        _record_ai_audit(
            db,
            organization_id=organization_id,
            action=AiAuditAction.PROVIDER_FAILOVER,
            actor_id=actor_id,
            actor_email=actor_email,
            provider_class=chosen_cfg.provider_class,
            model_slug=chosen_catalog.model_slug,
            data_classification=effective_classification,
            details={
                "task_request_id": str(task_req.id),
                "fallback_provider": chosen_cfg.display_name,
            },
        )

    _record_ai_audit(
        db,
        organization_id=organization_id,
        action=AiAuditAction.TASK_EXECUTED,
        actor_id=actor_id,
        actor_email=actor_email,
        provider_class=chosen_cfg.provider_class,
        model_slug=chosen_catalog.model_slug,
        data_classification=effective_classification,
        details={
            "task_request_id": str(task_req.id),
            "run_id": str(run.id),
            "redaction_applied": effective_redacted,
            "prompt_injection_detected": effective_injection,
            "rag_hits": len(rag_hits),
        },
    )
    await db.flush()
    return {
        "task_request": task_req,
        "run": run,
        "tool_proposals": created_proposals,
        "rag_hits": rag_hits,
    }


async def decide_tool_proposal(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    proposal_id: uuid.UUID,
    decision: str,
    comment: str,
    decided_by: uuid.UUID,
    decided_email: str,
    approver_role: str = "admin",
    settings: Settings | None = None,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> AiToolProposal:
    """Human-in-the-loop SoD + live OPA approval or rejection of an AI tool proposal."""
    if decision not in {"approved", "rejected"}:
        raise ValidationError("decision must be 'approved' or 'rejected'")

    prop = (
        await db.execute(
            select(AiToolProposal)
            .where(
                AiToolProposal.organization_id == organization_id,
                AiToolProposal.id == proposal_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if prop is None:
        raise NotFoundError("AI tool proposal not found")
    if not prop.opa_allowed or prop.status == AiToolProposalStatus.OPA_DENIED.value:
        raise ForbiddenError("OPA-denied AI tool proposals cannot be approved")
    if prop.status != AiToolProposalStatus.PENDING_HUMAN_APPROVAL.value:
        raise ConflictError(f"Tool proposal already decided ({prop.status})")

    run = (
        await db.execute(
            select(AiRun).where(
                AiRun.organization_id == organization_id,
                AiRun.id == prop.ai_run_id,
            )
        )
    ).scalar_one()
    task_req = (
        await db.execute(
            select(AiTaskRequest).where(
                AiTaskRequest.organization_id == organization_id,
                AiTaskRequest.id == run.task_request_id,
            )
        )
    ).scalar_one()

    if decision == "approved":
        if task_req.requested_by == decided_by:
            raise ForbiddenError(
                "Segregation of Duties forbids approving your own AI task tool proposal"
            )
        opa_ok, opa_reason = await evaluate_tool_proposal_with_opa(
            settings=settings or get_settings(),
            organization_id=organization_id,
            user_id=decided_by,
            role=approver_role,
            tool_action=prop.tool_action,
            opa_action="ai:manage",
            requested_by=task_req.requested_by,
            opa_transport=opa_transport,
        )
        if not opa_ok:
            raise ForbiddenError(f"OPA denied tool proposal approval: {opa_reason}")

    prop.status = (
        AiToolProposalStatus.APPROVED.value
        if decision == "approved"
        else AiToolProposalStatus.REJECTED.value
    )
    db.add(
        AiToolApproval(
            id=uuid.uuid4(),
            organization_id=organization_id,
            proposal_id=prop.id,
            decision=decision,
            decided_by=decided_by,
            decided_email=decided_email,
            comment=comment.strip(),
        )
    )
    _record_ai_audit(
        db,
        organization_id=organization_id,
        action=AiAuditAction.TOOL_DECIDED,
        actor_id=decided_by,
        actor_email=decided_email,
        details={
            "proposal_id": str(prop.id),
            "tool_action": prop.tool_action,
            "decision": decision,
        },
    )
    await db.flush()
    return prop


async def record_feedback_label(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    ai_run_id: uuid.UUID,
    label: str,
    notes: str,
    cross_tenant_sharing_enabled: bool,
    actor_id: uuid.UUID,
    actor_email: str,
) -> AiFeedbackLabel:
    if cross_tenant_sharing_enabled:
        raise ForbiddenError(
            "Cross-tenant AI learning/sharing is disabled by organizational data governance policy"
        )
    run = (
        await db.execute(
            select(AiRun).where(AiRun.organization_id == organization_id, AiRun.id == ai_run_id)
        )
    ).scalar_one_or_none()
    if run is None:
        raise NotFoundError("AI run not found")

    fb = AiFeedbackLabel(
        id=uuid.uuid4(),
        organization_id=organization_id,
        ai_run_id=ai_run_id,
        label=label.strip(),
        notes=notes.strip(),
        de_identified=True,
        cross_tenant_sharing_enabled=False,
        labeled_by=actor_id,
    )
    db.add(fb)
    _record_ai_audit(
        db,
        organization_id=organization_id,
        action=AiAuditAction.FEEDBACK_RECORDED,
        actor_id=actor_id,
        actor_email=actor_email,
        model_slug=run.model_slug,
        details={"ai_run_id": str(ai_run_id), "label": fb.label},
    )
    await db.flush()
    return fb


async def record_model_evaluation(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    model_slug: str,
    suite_name: str,
    sample_count: int,
    true_positive_rate: float,
    false_positive_rate: float,
    actor_id: uuid.UUID,
    actor_email: str,
) -> ModelEvaluationRun:
    clean_slug = model_slug.strip()
    cat_row = (
        await db.execute(
            select(AiModelCatalog.id).where(
                AiModelCatalog.model_slug == clean_slug,
                AiModelCatalog.is_active.is_(True),
            )
        )
    ).scalar_one_or_none()
    if cat_row is None:
        raise ValidationError(f"Model '{clean_slug}' does not exist in active AiModelCatalog")

    passed = true_positive_rate >= 0.8 and false_positive_rate <= 0.1 and sample_count >= 10
    ev = ModelEvaluationRun(
        id=uuid.uuid4(),
        organization_id=organization_id,
        model_slug=clean_slug,
        suite_name=suite_name.strip(),
        sample_count=sample_count,
        true_positive_rate=true_positive_rate,
        false_positive_rate=false_positive_rate,
        regression_passed=passed,
        evaluated_by=actor_id,
    )
    db.add(ev)
    _record_ai_audit(
        db,
        organization_id=organization_id,
        action=AiAuditAction.EVALUATION_RUN,
        actor_id=actor_id,
        actor_email=actor_email,
        model_slug=ev.model_slug,
        details={"suite": ev.suite_name, "regression_passed": passed},
    )
    await db.flush()
    return ev


async def get_ai_governance_overview(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
) -> dict[str, Any]:
    catalog = await list_model_catalog(db)
    providers = (
        (
            await db.execute(
                select(AiProviderConfig)
                .where(AiProviderConfig.organization_id == organization_id)
                .order_by(AiProviderConfig.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    runs = (
        (
            await db.execute(
                select(AiRun)
                .where(AiRun.organization_id == organization_id)
                .order_by(AiRun.created_at.desc())
                .limit(20)
            )
        )
        .scalars()
        .all()
    )
    proposals = (
        (
            await db.execute(
                select(AiToolProposal)
                .where(AiToolProposal.organization_id == organization_id)
                .order_by(AiToolProposal.created_at.desc())
                .limit(25)
            )
        )
        .scalars()
        .all()
    )
    docs = (
        (
            await db.execute(
                select(KnowledgeDocument)
                .where(KnowledgeDocument.organization_id == organization_id)
                .order_by(KnowledgeDocument.created_at.desc())
                .limit(20)
            )
        )
        .scalars()
        .all()
    )
    evals = (
        (
            await db.execute(
                select(ModelEvaluationRun)
                .where(ModelEvaluationRun.organization_id == organization_id)
                .order_by(ModelEvaluationRun.created_at.desc())
                .limit(15)
            )
        )
        .scalars()
        .all()
    )
    audits = (
        (
            await db.execute(
                select(AiAuditEvent)
                .where(AiAuditEvent.organization_id == organization_id)
                .order_by(AiAuditEvent.occurred_at.desc())
                .limit(30)
            )
        )
        .scalars()
        .all()
    )
    return {
        "model_catalog": catalog,
        "provider_configs": list(providers),
        "recent_runs": list(runs),
        "tool_proposals": list(proposals),
        "knowledge_documents": list(docs),
        "evaluations": list(evals),
        "audit_events": list(audits),
    }


async def record_blocked_ai_attempt(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    task_type: str,
    role_name: str,
    raw_prompt: str,
    requested_classification: str | None,
    consent_acknowledged: bool,
    provider_config_id: uuid.UUID | None,
    model_slug: str,
    block_reason: str,
    actor_id: uuid.UUID,
    actor_email: str,
) -> None:
    """Persist an immutable TASK_BLOCKED request and audit event in its own transaction."""
    cls_res = classify_and_redact_payload(
        raw_prompt, requested_classification=requested_classification
    )
    req_row = AiTaskRequest(
        id=uuid.uuid4(),
        organization_id=organization_id,
        task_type=task_type.strip(),
        role_name=role_name.strip(),
        data_classification=cls_res.classification.value,
        redaction_applied=cls_res.redaction_applied,
        prompt_injection_detected=cls_res.prompt_injection_detected,
        consent_acknowledged=consent_acknowledged,
        provider_config_id=provider_config_id,
        model_slug=model_slug.strip(),
        input_snapshot_sha256=cls_res.raw_sha256,
        input_summary_redacted=cls_res.redacted_text[:1000],
        status=AiTaskStatus.BLOCKED.value,
        block_reason=block_reason[:1000],
        requested_by=actor_id,
    )
    db.add(req_row)
    _record_ai_audit(
        db,
        organization_id=organization_id,
        action=AiAuditAction.TASK_BLOCKED,
        actor_id=actor_id,
        actor_email=actor_email,
        model_slug=model_slug.strip(),
        data_classification=cls_res.classification.value,
        details={
            "task_request_id": str(req_row.id),
            "role_name": role_name.strip(),
            "reason": block_reason[:400],
        },
    )
    await db.flush()


__all__ = [
    "configure_provider",
    "decide_tool_proposal",
    "evaluate_tool_proposal_with_opa",
    "execute_ai_task",
    "get_ai_governance_overview",
    "index_knowledge_document",
    "list_model_catalog",
    "record_blocked_ai_attempt",
    "record_feedback_label",
    "record_model_evaluation",
    "retrieve_tenant_knowledge",
    "set_provider_retention_consent",
]
