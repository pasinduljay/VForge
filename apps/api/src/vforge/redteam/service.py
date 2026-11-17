"""Phase 15 Isolated AI Red-Team Sandbox service: sessions, budgets, review & benchmarks."""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
from vforge_scanners.redaction import redact_text_secrets
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.ai_gateway.classification import classify_and_redact_payload
from vforge.config import Settings
from vforge.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from vforge.lab.safety import verify_lab_compose_isolation
from vforge.models.redteam import (
    RedTeamBenchmark,
    RedTeamEvent,
    RedTeamObservation,
    RedTeamSession,
)
from vforge.redteam.policy import (
    ALLOWED_TOOL_CATALOG,
    FORBIDDEN_TOOLS,
    TARGETED_TOOLS,
    assert_url_within_session_targets,
    compute_benchmark_metrics,
    normalize_slug_list,
    target_host_label,
    validate_session_targets,
    validate_tool_allowlist,
    verify_redteam_compose_isolation,
)

_ALLOWED_ENGINES = frozenset({"strix", "pentagi"})
_ALLOWED_SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})


def redact_text(value: str) -> str:
    """Scrub secrets and tokens using both scanner redaction and AI gateway classification."""
    first = redact_text_secrets(value) or ""
    return classify_and_redact_payload(first).redacted_text


async def evaluate_redteam_action_with_opa(
    *,
    settings: Settings,
    organization_id: uuid.UUID,
    user_id: uuid.UUID,
    role: str,
    action: str,
    actor_type: str = "human",
    requested_by: str = "",
    recorded_by: str = "",
    redteam_tool: str = "",
    external_network_requested: bool = False,
    auto_confirm_requested: bool = False,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> tuple[bool, str]:
    """Evaluate OPA `vforge/authz/allow` for Phase 15 AI red-team actions (fail closed)."""
    url = f"{settings.opa_url.rstrip('/')}/v1/data/vforge/authz/allow"
    payload = {
        "input": {
            "action": action,
            "subject": {
                "id": str(user_id),
                "role": role,
                "organization_id": str(organization_id),
                "authenticated": True,
                "actor_type": actor_type,
            },
            "resource": {
                "organization_id": str(organization_id),
                "requested_by": requested_by,
                "recorded_by": recorded_by,
                "redteam_tool": redteam_tool,
                "external_network_requested": external_network_requested,
                "auto_confirm_requested": auto_confirm_requested,
            },
        }
    }
    try:
        async with httpx.AsyncClient(timeout=5.0, transport=opa_transport) as client:
            resp = await client.post(url, json=payload)
            resp.raise_for_status()
            body = resp.json()
    except (httpx.HTTPError, ValueError) as exc:
        return False, f"OPA evaluation failed closed ({type(exc).__name__})"

    if not isinstance(body, dict) or body.get("result") is not True:
        return False, "OPA policy denied redteam action"
    return True, "OPA policy allowed redteam action"


async def _enforce_opa_if_configured(
    *,
    settings: Settings | None,
    organization_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: str | None,
    action: str,
    actor_type: str = "human",
    requested_by: str = "",
    recorded_by: str = "",
    redteam_tool: str = "",
    external_network_requested: bool = False,
    auto_confirm_requested: bool = False,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> None:
    if settings is None:
        return
    allowed, reason = await evaluate_redteam_action_with_opa(
        settings=settings,
        organization_id=organization_id,
        user_id=actor_id,
        role=actor_role or "",
        action=action,
        actor_type=actor_type,
        requested_by=requested_by,
        recorded_by=recorded_by,
        redteam_tool=redteam_tool,
        external_network_requested=external_network_requested,
        auto_confirm_requested=auto_confirm_requested,
        opa_transport=opa_transport,
    )
    if not allowed:
        raise ForbiddenError(f"OPA denied '{action}': {reason}")


def _record_redteam_event(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    session_id: uuid.UUID,
    event_type: str,
    outcome: str,
    actor_id: uuid.UUID | None,
    actor_email: str | None,
    tool_name: str | None = None,
    target_host: str | None = None,
    details: dict[str, Any] | None = None,
) -> RedTeamEvent:
    ev = RedTeamEvent(
        id=uuid.uuid4(),
        organization_id=organization_id,
        session_id=session_id,
        event_type=event_type[:48],
        outcome=outcome,
        actor_id=actor_id,
        actor_email=actor_email[:320] if actor_email else None,
        tool_name=tool_name[:64] if tool_name else None,
        target_host=target_host[:255] if target_host else None,
        details_json=details or {},
    )
    db.add(ev)
    return ev


async def request_redteam_session(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    title: str,
    objective: str,
    engine: str,
    tool_allowlist: list[str],
    target_urls: list[str],
    max_duration_seconds: int = 900,
    max_tool_calls: int = 25,
    max_tokens: int = 50000,
    actor_id: uuid.UUID,
    actor_email: str,
    actor_role: str | None = None,
    settings: Settings | None = None,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> RedTeamSession:
    """Create a pending (`requested`) AI red-team session bound strictly to isolated lab targets."""
    cleaned_title = redact_text(title.strip())
    cleaned_objective = redact_text(objective.strip())
    if len(cleaned_title) < 4 or len(cleaned_title) > 160:
        raise ValidationError("Session title must be between 4 and 160 characters")
    if len(cleaned_objective) < 10 or len(cleaned_objective) > 1000:
        raise ValidationError("Session objective must be between 10 and 1000 characters")

    norm_engine = engine.strip().lower()
    if norm_engine not in _ALLOWED_ENGINES:
        raise ValidationError(
            f"Unsupported engine '{engine}'. Must be one of {sorted(_ALLOWED_ENGINES)}"
        )

    if not (60 <= max_duration_seconds <= 3600):
        raise ValidationError("max_duration_seconds must be between 60 and 3600")
    if not (1 <= max_tool_calls <= 500):
        raise ValidationError("max_tool_calls must be between 1 and 500")
    if not (1000 <= max_tokens <= 2_000_000):
        raise ValidationError("max_tokens must be between 1000 and 2000000")

    validated_tools = validate_tool_allowlist(tool_allowlist)
    validated_targets = validate_session_targets(target_urls)

    sandbox_iso = verify_redteam_compose_isolation()
    if not sandbox_iso["verified"]:
        raise ForbiddenError(
            f"Red-team sandbox isolation check failed: {'; '.join(sandbox_iso['violations'])}"
        )
    lab_iso = verify_lab_compose_isolation()
    if not lab_iso["verified"]:
        raise ForbiddenError(
            f"Learning lab isolation check failed: {'; '.join(lab_iso['violations'])}"
        )

    for tool_name in validated_tools:
        await _enforce_opa_if_configured(
            settings=settings,
            organization_id=organization_id,
            actor_id=actor_id,
            actor_role=actor_role,
            action="redteam:request",
            redteam_tool=tool_name,
            opa_transport=opa_transport,
        )

    session = RedTeamSession(
        id=uuid.uuid4(),
        organization_id=organization_id,
        title=cleaned_title,
        objective=cleaned_objective,
        engine=norm_engine,
        status="requested",
        tool_allowlist=validated_tools,
        target_urls=validated_targets,
        max_duration_seconds=max_duration_seconds,
        max_tool_calls=max_tool_calls,
        max_tokens=max_tokens,
        tool_calls_used=0,
        tokens_used=0,
        requested_by=actor_id,
        cleanup_attested=False,
    )
    db.add(session)
    await db.flush()

    _record_redteam_event(
        db,
        organization_id=organization_id,
        session_id=session.id,
        event_type="session.requested",
        outcome="allowed",
        actor_id=actor_id,
        actor_email=actor_email,
        details={
            "engine": norm_engine,
            "tool_allowlist": validated_tools,
            "target_hosts": [target_host_label(u) for u in validated_targets],
            "max_duration_seconds": max_duration_seconds,
            "max_tool_calls": max_tool_calls,
            "max_tokens": max_tokens,
        },
    )
    await db.flush()
    return session


async def approve_or_reject_redteam_session(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    session_id: uuid.UUID,
    decision: str,
    approval_ttl_minutes: int = 30,
    reason: str = "",
    actor_id: uuid.UUID,
    actor_email: str,
    actor_role: str | None = None,
    settings: Settings | None = None,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> RedTeamSession:
    """Enforce per-session human approval (with strict Segregation of Duties) before execution."""
    norm_decision = decision.strip().lower()
    if norm_decision not in {"approve", "reject"}:
        raise ValidationError("decision must be 'approve' or 'reject'")
    if not (5 <= approval_ttl_minutes <= 240):
        raise ValidationError("approval_ttl_minutes must be between 5 and 240")

    res = await db.execute(
        select(RedTeamSession)
        .where(
            RedTeamSession.organization_id == organization_id,
            RedTeamSession.id == session_id,
        )
        .with_for_update()
    )
    session = res.scalar_one_or_none()
    if session is None:
        raise NotFoundError("Red-team session not found")

    if session.status != "requested":
        raise ConflictError(
            f"Session is in status '{session.status}' and cannot be approved or rejected"
        )

    if session.requested_by == actor_id:
        _record_redteam_event(
            db,
            organization_id=organization_id,
            session_id=session.id,
            event_type="session.approval_sod_violation",
            outcome="denied",
            actor_id=actor_id,
            actor_email=actor_email,
            details={"reason": "Requester attempted to approve or reject own red-team session"},
        )
        await db.flush()
        raise ForbiddenError(
            "Segregation of duties violation: requester cannot approve or reject their own session"
        )

    await _enforce_opa_if_configured(
        settings=settings,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        action="redteam:approve",
        requested_by=str(session.requested_by),
        opa_transport=opa_transport,
    )

    now = datetime.now(UTC)
    cleaned_reason = redact_text(reason.strip())[:200] if reason.strip() else None
    if norm_decision == "approve":
        session.status = "approved"
        session.approved_by = actor_id
        session.approved_at = now
        session.approval_expires_at = now + timedelta(minutes=approval_ttl_minutes)
        event_type = "session.approved"
    else:
        session.status = "rejected"
        session.ended_at = now
        session.end_reason = cleaned_reason or "Rejected by reviewer"
        session.cleanup_attested = True
        session.cleanup_summary = (
            "Session rejected prior to sandbox execution; no container started."
        )
        event_type = "session.rejected"

    _record_redteam_event(
        db,
        organization_id=organization_id,
        session_id=session.id,
        event_type=event_type,
        outcome="allowed",
        actor_id=actor_id,
        actor_email=actor_email,
        details={
            "decision": norm_decision,
            "approval_ttl_minutes": approval_ttl_minutes if norm_decision == "approve" else 0,
            "reason": cleaned_reason or "",
        },
    )
    await db.flush()
    return session


async def start_redteam_session(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    session_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_email: str,
    actor_role: str | None = None,
    settings: Settings | None = None,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> RedTeamSession:
    """Transition an approved, non-expired session into `running` after re-verifying isolation."""
    await _enforce_opa_if_configured(
        settings=settings,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        action="redteam:execute",
        opa_transport=opa_transport,
    )

    sandbox_iso = verify_redteam_compose_isolation()
    if not sandbox_iso["verified"]:
        raise ForbiddenError(
            f"Red-team sandbox isolation check failed: {'; '.join(sandbox_iso['violations'])}"
        )
    lab_iso = verify_lab_compose_isolation()
    if not lab_iso["verified"]:
        raise ForbiddenError(
            f"Learning lab isolation check failed: {'; '.join(lab_iso['violations'])}"
        )

    res = await db.execute(
        select(RedTeamSession)
        .where(
            RedTeamSession.organization_id == organization_id,
            RedTeamSession.id == session_id,
        )
        .with_for_update()
    )
    session = res.scalar_one_or_none()
    if session is None:
        raise NotFoundError("Red-team session not found")

    if session.status != "approved" or session.approved_by is None:
        raise ConflictError(
            f"Session must be in 'approved' state before starting (current: '{session.status}')"
        )

    now = datetime.now(UTC)
    if session.approval_expires_at is not None and now >= session.approval_expires_at:
        session.status = "expired"
        session.ended_at = now
        session.end_reason = "Human approval window expired prior to session start"
        session.cleanup_attested = True
        session.cleanup_summary = "Approval expired before start; ephemeral sandbox never launched."
        _record_redteam_event(
            db,
            organization_id=organization_id,
            session_id=session.id,
            event_type="session.approval_expired",
            outcome="denied",
            actor_id=actor_id,
            actor_email=actor_email,
            details={"approval_expires_at": session.approval_expires_at.isoformat()},
        )
        await db.flush()
        raise ConflictError("Session approval has expired; request a new session")

    session.status = "running"
    session.started_at = now
    _record_redteam_event(
        db,
        organization_id=organization_id,
        session_id=session.id,
        event_type="session.started",
        outcome="allowed",
        actor_id=actor_id,
        actor_email=actor_email,
        details={
            "engine": session.engine,
            "started_at": now.isoformat(),
            "max_duration_seconds": session.max_duration_seconds,
        },
    )
    await db.flush()
    return session


async def execute_redteam_tool_call(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    session_id: uuid.UUID,
    tool_name: str,
    target_url: str | None = None,
    input_summary: str = "",
    estimated_tokens: int = 500,
    actor_id: uuid.UUID,
    actor_email: str,
    actor_role: str | None = None,
    settings: Settings | None = None,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Execute a bounded tool call inside a running session, enforcing tool/target/budget gates."""
    if estimated_tokens < 1 or estimated_tokens > 200_000:
        raise ValidationError("estimated_tokens must be between 1 and 200000")

    res = await db.execute(
        select(RedTeamSession)
        .where(
            RedTeamSession.organization_id == organization_id,
            RedTeamSession.id == session_id,
        )
        .with_for_update()
    )
    session = res.scalar_one_or_none()
    if session is None:
        raise NotFoundError("Red-team session not found")

    if session.status != "running" or session.started_at is None:
        raise ConflictError(
            f"Tool calls require a 'running' session (current status: '{session.status}')"
        )

    now = datetime.now(UTC)
    elapsed_seconds = (now - session.started_at).total_seconds()
    if elapsed_seconds > session.max_duration_seconds:
        session.status = "expired"
        session.ended_at = now
        session.end_reason = (
            f"Session exceeded max_duration_seconds ({session.max_duration_seconds}s)"
        )
        session.cleanup_attested = True
        session.cleanup_summary = (
            "Auto-expired by wall-clock lifetime guard; ephemeral sandbox state discarded."
        )
        _record_redteam_event(
            db,
            organization_id=organization_id,
            session_id=session.id,
            event_type="session.lifetime_expired",
            outcome="denied",
            actor_id=actor_id,
            actor_email=actor_email,
            tool_name=tool_name.strip().lower()[:64] if tool_name else None,
            details={
                "elapsed_seconds": round(elapsed_seconds, 2),
                "max_duration_seconds": session.max_duration_seconds,
            },
        )
        await db.flush()
        raise ConflictError("Session wall-clock lifetime expired; session has been terminated")

    norm_tool = tool_name.strip().lower()
    redacted_input = redact_text(input_summary.strip())[:400]

    # 1. Forbidden / unknown / unapproved tool checks
    if (
        not norm_tool
        or norm_tool in FORBIDDEN_TOOLS
        or norm_tool not in ALLOWED_TOOL_CATALOG
        or norm_tool not in session.tool_allowlist
    ):
        _record_redteam_event(
            db,
            organization_id=organization_id,
            session_id=session.id,
            event_type="tool_call.denied_tool",
            outcome="denied",
            actor_id=actor_id,
            actor_email=actor_email,
            tool_name=norm_tool or "empty",
            details={
                "reason": "Tool is forbidden or outside the session tool_allowlist",
                "session_tool_allowlist": session.tool_allowlist,
            },
        )
        await db.flush()
        raise ForbiddenError(
            f"Tool '{norm_tool}' is forbidden or not in the approved session tool_allowlist"
        )

    # 2. OPA authorization check
    await _enforce_opa_if_configured(
        settings=settings,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        action="redteam:execute",
        redteam_tool=norm_tool,
        opa_transport=opa_transport,
    )

    # 3. Target URL validation for network-targeted tools (or whenever target_url is supplied)
    validated_target: str | None = None
    host_label: str | None = None
    if norm_tool in TARGETED_TOOLS or (target_url is not None and target_url.strip()):
        if not target_url or not target_url.strip():
            raise ValidationError(f"Tool '{norm_tool}' requires a target_url")
        try:
            validated_target = assert_url_within_session_targets(
                target_url.strip(), session.target_urls
            )
            host_label = target_host_label(validated_target)
        except (ForbiddenError, ValidationError) as exc:
            _record_redteam_event(
                db,
                organization_id=organization_id,
                session_id=session.id,
                event_type="tool_call.denied_target",
                outcome="denied",
                actor_id=actor_id,
                actor_email=actor_email,
                tool_name=norm_tool,
                details={"reason": str(exc)},
            )
            await db.flush()
            if isinstance(exc, ForbiddenError):
                raise
            raise ForbiddenError(f"Target rejected by sandbox policy: {exc}") from exc

    # 4. Budget enforcement (max_tool_calls & max_tokens)
    next_calls = session.tool_calls_used + 1
    next_tokens = session.tokens_used + estimated_tokens
    if next_calls > session.max_tool_calls or next_tokens > session.max_tokens:
        _record_redteam_event(
            db,
            organization_id=organization_id,
            session_id=session.id,
            event_type="tool_call.budget_exceeded",
            outcome="denied",
            actor_id=actor_id,
            actor_email=actor_email,
            tool_name=norm_tool,
            target_host=host_label,
            details={
                "tool_calls_used": session.tool_calls_used,
                "max_tool_calls": session.max_tool_calls,
                "tokens_used": session.tokens_used,
                "estimated_tokens": estimated_tokens,
                "max_tokens": session.max_tokens,
            },
        )
        await db.flush()
        raise ConflictError("Session tool-call or token budget exceeded")

    session.tool_calls_used = next_calls
    session.tokens_used = next_tokens

    ev = _record_redteam_event(
        db,
        organization_id=organization_id,
        session_id=session.id,
        event_type="tool_call.executed",
        outcome="allowed",
        actor_id=actor_id,
        actor_email=actor_email,
        tool_name=norm_tool,
        target_host=host_label,
        details={
            "input_summary": redacted_input,
            "estimated_tokens": estimated_tokens,
            "tool_calls_used": session.tool_calls_used,
            "tokens_used": session.tokens_used,
            "sandbox_mode": "isolated_lab_simulation",
        },
    )
    await db.flush()
    return {
        "event_id": ev.id,
        "session_id": session.id,
        "tool_name": norm_tool,
        "target_host": host_label,
        "outcome": "allowed",
        "tool_calls_used": session.tool_calls_used,
        "max_tool_calls": session.max_tool_calls,
        "tokens_used": session.tokens_used,
        "max_tokens": session.max_tokens,
        "classification": "hypothesis_only",
        "output_summary": (
            f"[{session.engine}:{norm_tool}] Executed in isolated lab sandbox"
            + (f" against {host_label}" if host_label else "")
            + ". Output remains unverified until human review."
        ),
    }


async def record_redteam_observation(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    session_id: uuid.UUID,
    title: str,
    category: str,
    severity: str,
    evidence_summary: str,
    actor_id: uuid.UUID,
    actor_email: str,
    actor_role: str | None = None,
    settings: Settings | None = None,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> RedTeamObservation:
    """Record an AI-originated observation strictly as `hypothesis` (never auto-confirmed)."""
    await _enforce_opa_if_configured(
        settings=settings,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        action="redteam:execute",
        redteam_tool="note_hypothesis",
        opa_transport=opa_transport,
    )

    res = await db.execute(
        select(RedTeamSession)
        .where(
            RedTeamSession.organization_id == organization_id,
            RedTeamSession.id == session_id,
        )
        .with_for_update()
    )
    session = res.scalar_one_or_none()
    if session is None:
        raise NotFoundError("Red-team session not found")
    if session.status not in {"running", "completed"}:
        raise ConflictError(
            "Observations can only be recorded on running or completed sessions "
            f"(current: '{session.status}')"
        )

    if session.status == "running" and session.started_at is not None:
        now = datetime.now(UTC)
        elapsed_seconds = (now - session.started_at).total_seconds()
        if elapsed_seconds > session.max_duration_seconds:
            session.status = "expired"
            session.ended_at = now
            session.end_reason = (
                f"Session exceeded max_duration_seconds ({session.max_duration_seconds}s)"
            )
            session.cleanup_attested = True
            session.cleanup_summary = (
                "Auto-expired by wall-clock lifetime guard; ephemeral sandbox state discarded."
            )
            _record_redteam_event(
                db,
                organization_id=organization_id,
                session_id=session.id,
                event_type="session.lifetime_expired",
                outcome="denied",
                actor_id=actor_id,
                actor_email=actor_email,
                tool_name="note_hypothesis",
                details={
                    "elapsed_seconds": round(elapsed_seconds, 2),
                    "max_duration_seconds": session.max_duration_seconds,
                },
            )
            await db.flush()
            raise ConflictError("Session wall-clock lifetime expired; session has been terminated")

    if "note_hypothesis" not in session.tool_allowlist:
        _record_redteam_event(
            db,
            organization_id=organization_id,
            session_id=session.id,
            event_type="observation.denied_tool",
            outcome="denied",
            actor_id=actor_id,
            actor_email=actor_email,
            tool_name="note_hypothesis",
            details={
                "reason": "Tool 'note_hypothesis' is outside the session tool_allowlist",
                "session_tool_allowlist": session.tool_allowlist,
            },
        )
        await db.flush()
        raise ForbiddenError("Tool 'note_hypothesis' is not in the approved session tool_allowlist")

    cleaned_title = redact_text(title.strip())
    cleaned_category = redact_text(category.strip().lower())
    norm_severity = severity.strip().lower()
    cleaned_evidence = redact_text(evidence_summary.strip())

    if len(cleaned_title) < 4 or len(cleaned_title) > 200:
        raise ValidationError("Observation title must be between 4 and 200 characters")
    if len(cleaned_category) < 2 or len(cleaned_category) > 64:
        raise ValidationError("Observation category must be between 2 and 64 characters")
    if norm_severity not in _ALLOWED_SEVERITIES:
        raise ValidationError(f"Severity must be one of {sorted(_ALLOWED_SEVERITIES)}")
    if len(cleaned_evidence) < 10 or len(cleaned_evidence) > 4000:
        raise ValidationError("evidence_summary must be between 10 and 4000 characters")

    evidence_sha256 = hashlib.sha256(cleaned_evidence.encode("utf-8")).hexdigest()
    obs = RedTeamObservation(
        id=uuid.uuid4(),
        organization_id=organization_id,
        session_id=session.id,
        title=cleaned_title,
        category=cleaned_category,
        severity=norm_severity,
        classification="hypothesis",
        evidence_summary=cleaned_evidence,
        evidence_sha256=evidence_sha256,
        source="ai_agent",
        recorded_by=actor_id,
    )
    db.add(obs)
    _record_redteam_event(
        db,
        organization_id=organization_id,
        session_id=session.id,
        event_type="observation.recorded_hypothesis",
        outcome="allowed",
        actor_id=actor_id,
        actor_email=actor_email,
        tool_name="note_hypothesis",
        details={
            "observation_id": str(obs.id),
            "classification": "hypothesis",
            "severity": norm_severity,
            "evidence_sha256": evidence_sha256,
        },
    )
    await db.flush()
    return obs


async def review_redteam_observation(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    observation_id: uuid.UUID,
    decision: str,
    review_note: str,
    actor_id: uuid.UUID,
    actor_email: str,
    actor_role: str | None = None,
    settings: Settings | None = None,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> RedTeamObservation:
    """Confirm or reject an AI hypothesis via an independent human reviewer (SoD enforced)."""
    norm_decision = decision.strip().lower()
    if norm_decision not in {"confirmed", "rejected"}:
        raise ValidationError("decision must be 'confirmed' or 'rejected'")

    cleaned_note = redact_text(review_note.strip())
    if len(cleaned_note) < 12 or len(cleaned_note) > 2000:
        raise ValidationError("review_note must be between 12 and 2000 characters")

    res = await db.execute(
        select(RedTeamObservation)
        .where(
            RedTeamObservation.organization_id == organization_id,
            RedTeamObservation.id == observation_id,
        )
        .with_for_update()
    )
    obs = res.scalar_one_or_none()
    if obs is None:
        raise NotFoundError("Red-team observation not found")

    if obs.classification != "hypothesis":
        raise ConflictError(
            f"Observation is already finalized as '{obs.classification}' and cannot be re-decided"
        )

    if obs.recorded_by == actor_id:
        _record_redteam_event(
            db,
            organization_id=organization_id,
            session_id=obs.session_id,
            event_type="observation.review_sod_violation",
            outcome="denied",
            actor_id=actor_id,
            actor_email=actor_email,
            details={
                "observation_id": str(obs.id),
                "reason": "Recorder attempted to confirm or reject their own AI hypothesis",
            },
        )
        await db.flush()
        raise ForbiddenError(
            "Segregation of duties violation: observation recorder cannot review "
            "their own hypothesis"
        )

    await _enforce_opa_if_configured(
        settings=settings,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        action="redteam:review",
        recorded_by=str(obs.recorded_by),
        opa_transport=opa_transport,
    )

    now = datetime.now(UTC)
    obs.classification = norm_decision
    obs.reviewed_by = actor_id
    obs.reviewed_at = now
    obs.review_note = cleaned_note

    _record_redteam_event(
        db,
        organization_id=organization_id,
        session_id=obs.session_id,
        event_type=f"observation.{norm_decision}",
        outcome="completed",
        actor_id=actor_id,
        actor_email=actor_email,
        details={
            "observation_id": str(obs.id),
            "classification": norm_decision,
            "evidence_sha256": obs.evidence_sha256,
        },
    )
    await db.flush()
    return obs


async def complete_or_terminate_redteam_session(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    session_id: uuid.UUID,
    final_status: str = "completed",
    end_reason: str = "",
    cleanup_attested: bool = False,
    cleanup_summary: str = "",
    actor_id: uuid.UUID,
    actor_email: str,
    actor_role: str | None = None,
    settings: Settings | None = None,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> RedTeamSession:
    """Close a running or approved session with mandatory ephemeral sandbox cleanup attestation."""
    norm_status = final_status.strip().lower()
    if norm_status not in {"completed", "terminated"}:
        raise ValidationError("final_status must be 'completed' or 'terminated'")
    if not cleanup_attested:
        raise ValidationError(
            "cleanup_attested=True is required to attest that ephemeral sandbox state was wiped"
        )

    await _enforce_opa_if_configured(
        settings=settings,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        action="redteam:execute",
        opa_transport=opa_transport,
    )

    res = await db.execute(
        select(RedTeamSession)
        .where(
            RedTeamSession.organization_id == organization_id,
            RedTeamSession.id == session_id,
        )
        .with_for_update()
    )
    session = res.scalar_one_or_none()
    if session is None:
        raise NotFoundError("Red-team session not found")

    if session.status not in {"running", "approved"}:
        raise ConflictError(
            f"Only 'running' or 'approved' sessions can be closed (current: '{session.status}')"
        )
    if norm_status == "completed" and session.status != "running":
        raise ConflictError("Only a 'running' session can transition to 'completed'")

    now = datetime.now(UTC)
    if (
        session.status == "approved"
        and session.approval_expires_at is not None
        and now >= session.approval_expires_at
    ):
        session.status = "expired"
        session.ended_at = now
        session.end_reason = "Human approval window expired prior to session close"
        session.cleanup_attested = True
        session.cleanup_summary = "Approval expired before start; ephemeral sandbox never launched."
        _record_redteam_event(
            db,
            organization_id=organization_id,
            session_id=session.id,
            event_type="session.approval_expired",
            outcome="denied",
            actor_id=actor_id,
            actor_email=actor_email,
            details={"approval_expires_at": session.approval_expires_at.isoformat()},
        )
        await db.flush()
        raise ConflictError("Session approval has expired; session marked expired")

    if session.status == "running" and session.started_at is not None:
        elapsed_seconds = (now - session.started_at).total_seconds()
        if elapsed_seconds > session.max_duration_seconds:
            session.status = "expired"
            session.ended_at = now
            session.end_reason = (
                f"Session exceeded max_duration_seconds ({session.max_duration_seconds}s)"
            )
            session.cleanup_attested = True
            session.cleanup_summary = (
                "Auto-expired by wall-clock lifetime guard; ephemeral sandbox state discarded."
            )
            _record_redteam_event(
                db,
                organization_id=organization_id,
                session_id=session.id,
                event_type="session.lifetime_expired",
                outcome="denied",
                actor_id=actor_id,
                actor_email=actor_email,
                details={
                    "elapsed_seconds": round(elapsed_seconds, 2),
                    "max_duration_seconds": session.max_duration_seconds,
                },
            )
            await db.flush()
            raise ConflictError("Session wall-clock lifetime expired; session marked expired")

    cleaned_reason = (
        redact_text(end_reason.strip())[:200]
        if end_reason.strip()
        else (
            "Completed bounded assessment"
            if norm_status == "completed"
            else "Terminated by operator"
        )
    )
    cleaned_cleanup = (
        redact_text(cleanup_summary.strip())[:1000]
        if cleanup_summary.strip()
        else ("Ephemeral tmpfs wiped and isolated sandbox container stopped.")
    )

    session.status = norm_status
    session.ended_at = now
    session.end_reason = cleaned_reason
    session.cleanup_attested = True
    session.cleanup_summary = cleaned_cleanup

    _record_redteam_event(
        db,
        organization_id=organization_id,
        session_id=session.id,
        event_type=f"session.{norm_status}",
        outcome="completed",
        actor_id=actor_id,
        actor_email=actor_email,
        details={
            "end_reason": cleaned_reason,
            "cleanup_attested": True,
            "tool_calls_used": session.tool_calls_used,
            "tokens_used": session.tokens_used,
        },
    )
    await db.flush()
    return session


async def create_redteam_benchmark(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    session_id: uuid.UUID,
    ground_truth_slugs: list[str],
    ai_detected_slugs: list[str],
    zap_detected_slugs: list[str],
    nuclei_detected_slugs: list[str],
    actor_id: uuid.UUID,
    actor_email: str,
    actor_role: str | None = None,
    settings: Settings | None = None,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> RedTeamBenchmark:
    """Create an immutable benchmark comparison of AI red-team vs ZAP and Nuclei on lab slugs."""
    await _enforce_opa_if_configured(
        settings=settings,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        action="redteam:review",
        opa_transport=opa_transport,
    )

    res = await db.execute(
        select(RedTeamSession).where(
            RedTeamSession.organization_id == organization_id,
            RedTeamSession.id == session_id,
        )
    )
    session = res.scalar_one_or_none()
    if session is None:
        raise NotFoundError("Red-team session not found")

    truth = normalize_slug_list(ground_truth_slugs, label="ground_truth_slugs")
    ai_slugs = normalize_slug_list(ai_detected_slugs, label="ai_detected_slugs")
    zap_slugs = normalize_slug_list(zap_detected_slugs, label="zap_detected_slugs")
    nuc_slugs = normalize_slug_list(nuclei_detected_slugs, label="nuclei_detected_slugs")

    metrics = compute_benchmark_metrics(
        ground_truth=truth,
        ai_detected=ai_slugs,
        zap_detected=zap_slugs,
        nuclei_detected=nuc_slugs,
    )

    benchmark = RedTeamBenchmark(
        id=uuid.uuid4(),
        organization_id=organization_id,
        session_id=session.id,
        ground_truth_slugs=truth,
        ai_detected_slugs=ai_slugs,
        zap_detected_slugs=zap_slugs,
        nuclei_detected_slugs=nuc_slugs,
        metrics_json=metrics,
        data_provenance="operator_supplied_unverified",
        created_by=actor_id,
    )
    db.add(benchmark)
    _record_redteam_event(
        db,
        organization_id=organization_id,
        session_id=session.id,
        event_type="benchmark.recorded",
        outcome="completed",
        actor_id=actor_id,
        actor_email=actor_email,
        details={
            "benchmark_id": str(benchmark.id),
            "ground_truth_count": metrics["ground_truth_count"],
            "recall": metrics["recall"],
        },
    )
    await db.flush()
    return benchmark


async def get_redteam_overview(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    settings: Settings | None = None,
    actor_id: uuid.UUID | None = None,
    actor_role: str | None = None,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Return full AI red-team sandbox posture, sessions, observations, events, and benchmarks."""
    if actor_id is not None:
        await _enforce_opa_if_configured(
            settings=settings,
            organization_id=organization_id,
            actor_id=actor_id,
            actor_role=actor_role,
            action="redteam:read",
            opa_transport=opa_transport,
        )

    sessions_res = await db.execute(
        select(RedTeamSession)
        .where(RedTeamSession.organization_id == organization_id)
        .order_by(RedTeamSession.created_at.desc())
        .limit(50)
    )
    sessions = list(sessions_res.scalars().all())

    obs_res = await db.execute(
        select(RedTeamObservation)
        .where(RedTeamObservation.organization_id == organization_id)
        .order_by(RedTeamObservation.created_at.desc())
        .limit(100)
    )
    observations = list(obs_res.scalars().all())

    ev_res = await db.execute(
        select(RedTeamEvent)
        .where(RedTeamEvent.organization_id == organization_id)
        .order_by(RedTeamEvent.occurred_at.desc())
        .limit(100)
    )
    events = list(ev_res.scalars().all())

    bench_res = await db.execute(
        select(RedTeamBenchmark)
        .where(RedTeamBenchmark.organization_id == organization_id)
        .order_by(RedTeamBenchmark.created_at.desc())
        .limit(50)
    )
    benchmarks = list(bench_res.scalars().all())

    return {
        "organization_id": organization_id,
        "execution_mode": "isolated_lab_only_human_approved",
        "sandbox_isolation": verify_redteam_compose_isolation(),
        "lab_isolation": verify_lab_compose_isolation(),
        "allowed_tools": [
            {"name": k, "description": v, "requires_target_url": k in TARGETED_TOOLS}
            for k, v in ALLOWED_TOOL_CATALOG.items()
        ],
        "forbidden_tools": sorted(FORBIDDEN_TOOLS),
        "sessions": sessions,
        "observations": observations,
        "events": events,
        "benchmarks": benchmarks,
    }
