"""Phase 13 Isolated Learning Lab service: workspaces, resets, safe validation & self-scans."""

from __future__ import annotations

import hashlib
import json
import re
import secrets
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.ai_gateway.classification import classify_and_redact_payload
from vforge.config import Settings
from vforge.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from vforge.lab.safety import (
    evaluate_lab_action_with_opa,
    validate_lab_target_url,
    validate_safe_action_and_tool,
    verify_lab_compose_isolation,
)
from vforge.models import (
    LabAuditEvent,
    LabChallenge,
    LabChallengeProgress,
    LabSelfScan,
    LabValidationRun,
    LabWorkspace,
)
from vforge.models.enums import LabAuditAction, LabProgressStatus, LabWorkspaceState

_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")
_ALLOWED_SELF_SCAN_COMPONENTS = frozenset(
    {
        "control_plane_api",
        "control_plane_web",
        "scanner_contracts",
        "runner_agent",
        "opa_policies",
    }
)
_SHA256_HEX_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


async def _enforce_opa_if_configured(
    *,
    settings: Settings | None,
    organization_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: str | None,
    action: str,
    lab_action_type: str = "",
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> None:
    """Enforce fail-closed OPA authorization whenever runtime Settings are provided."""
    if settings is None:
        return
    allowed, reason = await evaluate_lab_action_with_opa(
        settings=settings,
        organization_id=organization_id,
        user_id=actor_id,
        role=actor_role or "",
        action=action,
        lab_action_type=lab_action_type,
        opa_transport=opa_transport,
    )
    if not allowed:
        raise ForbiddenError(f"OPA denied '{action}': {reason}")


def _build_disposable_identities(prefix: str, epoch: int) -> list[dict[str, str]]:
    """Generate clean, deterministic disposable lab identities scoped to a reset epoch."""
    return [
        {
            "handle": f"{prefix}-e{epoch}-alice@disposable.lab.vforge.local",
            "role": "standard_user",
            "epoch": str(epoch),
            "credential_hint": f"disposable-epoch-{epoch}-{secrets.token_hex(4)}",
        },
        {
            "handle": f"{prefix}-e{epoch}-bob@disposable.lab.vforge.local",
            "role": "peer_user",
            "epoch": str(epoch),
            "credential_hint": f"disposable-epoch-{epoch}-{secrets.token_hex(4)}",
        },
    ]


def _record_lab_audit(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    workspace_id: uuid.UUID | None,
    action: LabAuditAction,
    actor_id: uuid.UUID,
    actor_email: str,
    target_url: str | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    db.add(
        LabAuditEvent(
            id=uuid.uuid4(),
            organization_id=organization_id,
            workspace_id=workspace_id,
            action=action.value,
            actor_id=actor_id,
            actor_email=actor_email,
            target_url=target_url,
            details_json=details or {},
        )
    )


async def list_challenges(db: AsyncSession) -> list[LabChallenge]:
    """Return active curated beginner-to-expert challenges ordered cleanly by track difficulty."""
    rows = (
        (await db.execute(select(LabChallenge).where(LabChallenge.is_active.is_(True))))
        .scalars()
        .all()
    )
    order = {"beginner": 0, "intermediate": 1, "advanced": 2, "expert_practice": 3}
    return sorted(rows, key=lambda c: (order.get(c.track_level, 99), c.slug))


async def provision_lab_workspace(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    environment_slug: str,
    display_name: str,
    consent_to_persist_progress: bool,
    disposable_account_prefix: str = "lab",
    actor_id: uuid.UUID,
    actor_email: str,
    actor_role: str | None = None,
    settings: Settings | None = None,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> LabWorkspace:
    """Provision an egress-denied isolated tenant lab workspace with disposable identities."""
    await _enforce_opa_if_configured(
        settings=settings,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        action="lab:manage",
        opa_transport=opa_transport,
    )
    clean_slug = environment_slug.strip().lower()
    if not _SLUG_RE.fullmatch(clean_slug):
        raise ValidationError(
            "environment_slug must match lowercase alphanumeric/hyphen identifier (3-64 chars)"
        )
    clean_prefix = disposable_account_prefix.strip().lower()
    if not _SLUG_RE.fullmatch(clean_prefix):
        raise ValidationError(
            "disposable_account_prefix must match ^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$"
        )

    ws = LabWorkspace(
        id=uuid.uuid4(),
        organization_id=organization_id,
        environment_slug=clean_slug,
        display_name=display_name.strip(),
        isolation_network_name="vforge_lab_internal",
        egress_denied=True,
        public_exposure_blocked=True,
        consent_to_persist_progress=consent_to_persist_progress,
        disposable_account_prefix=clean_prefix,
        reset_epoch=1,
        state=LabWorkspaceState.READY.value,
        disposable_identities_json=_build_disposable_identities(clean_prefix, 1),
        created_by=actor_id,
    )
    try:
        async with db.begin_nested():
            db.add(ws)
            await db.flush()
    except IntegrityError as exc:
        raise ConflictError(
            f"Lab workspace slug '{clean_slug}' already exists for organization"
        ) from exc

    _record_lab_audit(
        db,
        organization_id=organization_id,
        workspace_id=ws.id,
        action=LabAuditAction.WORKSPACE_PROVISIONED,
        actor_id=actor_id,
        actor_email=actor_email,
        details={
            "environment_slug": ws.environment_slug,
            "consent_to_persist_progress": consent_to_persist_progress,
            "egress_denied": True,
        },
    )
    await db.flush()
    return ws


async def update_lab_consent(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    workspace_id: uuid.UUID,
    consent_to_persist_progress: bool,
    actor_id: uuid.UUID,
    actor_email: str,
    actor_role: str | None = None,
    settings: Settings | None = None,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> LabWorkspace:
    """Explicitly grant or revoke consent to persist challenge progress for this workspace."""
    await _enforce_opa_if_configured(
        settings=settings,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        action="lab:manage",
        opa_transport=opa_transport,
    )
    ws = (
        await db.execute(
            select(LabWorkspace)
            .where(
                LabWorkspace.id == workspace_id,
                LabWorkspace.organization_id == organization_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if ws is None:
        raise NotFoundError("Lab workspace not found")
    ws.consent_to_persist_progress = consent_to_persist_progress
    cleared_rows = 0
    if not consent_to_persist_progress:
        prior_rows = (
            (
                await db.execute(
                    select(LabChallengeProgress).where(
                        LabChallengeProgress.organization_id == organization_id,
                        LabChallengeProgress.workspace_id == ws.id,
                    )
                )
            )
            .scalars()
            .all()
        )
        for row in prior_rows:
            row.status = LabProgressStatus.NOT_STARTED.value
            row.validated_evidence_json = {}
            row.remediation_notes = ""
            row.retest_passed = False
            row.attempts_count = 0
            row.updated_by = actor_id
            cleared_rows += 1
    _record_lab_audit(
        db,
        organization_id=organization_id,
        workspace_id=ws.id,
        action=LabAuditAction.CONSENT_UPDATED,
        actor_id=actor_id,
        actor_email=actor_email,
        details={
            "consent_to_persist_progress": consent_to_persist_progress,
            "progress_rows_cleared": cleared_rows,
        },
    )
    await db.flush()
    return ws


async def reset_lab_workspace(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    workspace_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_email: str,
    actor_role: str | None = None,
    settings: Settings | None = None,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> LabWorkspace:
    """Reset workspace state, bump epoch, rotate disposable accounts, and clear progress."""
    await _enforce_opa_if_configured(
        settings=settings,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        action="lab:manage",
        opa_transport=opa_transport,
    )
    ws = (
        await db.execute(
            select(LabWorkspace)
            .where(
                LabWorkspace.id == workspace_id,
                LabWorkspace.organization_id == organization_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if ws is None:
        raise NotFoundError("Lab workspace not found")

    ws.reset_epoch += 1
    ws.state = LabWorkspaceState.READY.value
    ws.last_reset_at = datetime.now(UTC)
    ws.disposable_identities_json = _build_disposable_identities(
        ws.disposable_account_prefix, ws.reset_epoch
    )

    progress_rows = (
        (
            await db.execute(
                select(LabChallengeProgress).where(
                    LabChallengeProgress.organization_id == organization_id,
                    LabChallengeProgress.workspace_id == ws.id,
                )
            )
        )
        .scalars()
        .all()
    )
    for row in progress_rows:
        row.status = LabProgressStatus.NOT_STARTED.value
        row.reset_epoch = ws.reset_epoch
        row.validated_evidence_json = {}
        row.remediation_notes = ""
        row.retest_passed = False
        row.attempts_count = 0
        row.updated_by = actor_id

    _record_lab_audit(
        db,
        organization_id=organization_id,
        workspace_id=ws.id,
        action=LabAuditAction.WORKSPACE_RESET,
        actor_id=actor_id,
        actor_email=actor_email,
        details={
            "reset_epoch": ws.reset_epoch,
            "progress_rows_reset": len(progress_rows),
        },
    )
    await db.flush()
    return ws


async def validate_challenge_safely(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    workspace_id: uuid.UUID,
    challenge_id: uuid.UUID,
    target_url: str,
    tool_slug: str,
    action_type: str,
    disposable_identity_used: str,
    observed_evidence: str,
    actor_id: uuid.UUID,
    actor_email: str,
    actor_role: str,
    settings: Settings,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> tuple[LabValidationRun, LabChallengeProgress | None]:
    """Execute a bounded, non-destructive proof-of-concept validation or remediation retest."""
    ws = (
        await db.execute(
            select(LabWorkspace)
            .where(
                LabWorkspace.id == workspace_id,
                LabWorkspace.organization_id == organization_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if ws is None:
        raise NotFoundError("Lab workspace not found")

    ch = (
        await db.execute(
            select(LabChallenge).where(
                LabChallenge.id == challenge_id,
                LabChallenge.is_active.is_(True),
            )
        )
    ).scalar_one_or_none()
    if ch is None:
        raise NotFoundError("Lab challenge not found")

    # 1. Fail-closed OPA exploitation boundary check
    opa_allowed, opa_reason = await evaluate_lab_action_with_opa(
        settings=settings,
        organization_id=organization_id,
        user_id=actor_id,
        role=actor_role,
        action="lab:practice",
        lab_action_type=action_type,
        opa_transport=opa_transport,
    )
    if not opa_allowed:
        raise ForbiddenError(f"OPA denied lab action '{action_type}': {opa_reason}")

    # 2. Validate isolated lab target + non-destructive action + challenge tool allowlist
    clean_url = validate_lab_target_url(target_url, permitted_target=ch.permitted_target)
    norm_action, norm_tool = validate_safe_action_and_tool(
        action_type=action_type,
        tool_slug=tool_slug,
        permitted_tools=list(ch.permitted_tools_json or []),
    )

    # 3. Require epoch-matched disposable identity (blocks real/prod credential use)
    clean_ident = disposable_identity_used.strip().lower()
    valid_handles = {
        str(item.get("handle", "")).strip().lower()
        for item in (ws.disposable_identities_json or [])
    }
    if clean_ident not in valid_handles:
        raise ForbiddenError(
            "Validation must use an active disposable identity for workspace reset_epoch "
            f"{ws.reset_epoch}"
        )

    # 4. Redact secrets before storing evidence/URL & require real observation text
    safe_stored_url = classify_and_redact_payload(clean_url).redacted_text[:255]
    redacted_ev = classify_and_redact_payload(observed_evidence.strip()).redacted_text[:2000]
    if len(redacted_ev) < 12:
        raise ValidationError(
            "observed_evidence must capture real non-empty proof (>= 12 chars); "
            "synthetic pass generation is forbidden"
        )
    ev_sha = hashlib.sha256(redacted_ev.encode("utf-8")).hexdigest()

    is_retest = norm_action == "remediation_retest"
    existing_progress = (
        (
            await db.execute(
                select(LabChallengeProgress).where(
                    LabChallengeProgress.organization_id == organization_id,
                    LabChallengeProgress.workspace_id == ws.id,
                    LabChallengeProgress.challenge_id == ch.id,
                )
            )
        ).scalar_one_or_none()
        if ws.consent_to_persist_progress
        else None
    )

    if is_retest and (
        existing_progress is None
        or existing_progress.status
        not in {LabProgressStatus.REMEDIATED.value, LabProgressStatus.RETESTED.value}
    ):
        raise ValidationError(
            "Remediation exercise notes must be recorded before executing a remediation_retest"
        )

    run = LabValidationRun(
        id=uuid.uuid4(),
        organization_id=organization_id,
        workspace_id=ws.id,
        challenge_id=ch.id,
        reset_epoch=ws.reset_epoch,
        tool_slug=norm_tool,
        target_url=safe_stored_url,
        disposable_identity_used=clean_ident,
        action_type=norm_action,
        safety_boundary_verified=True,
        evidence_summary_redacted=redacted_ev,
        evidence_sha256=ev_sha,
        finding_confirmed=not is_retest,
        remediation_verified=is_retest,
        status="completed",
        executed_by=actor_id,
    )
    db.add(run)

    # 5. Persist progress strictly ONLY if org has explicitly consented
    updated_progress: LabChallengeProgress | None = None
    if ws.consent_to_persist_progress:
        if existing_progress is None:
            existing_progress = LabChallengeProgress(
                id=uuid.uuid4(),
                organization_id=organization_id,
                workspace_id=ws.id,
                challenge_id=ch.id,
                status=(
                    LabProgressStatus.RETESTED.value
                    if is_retest
                    else LabProgressStatus.VALIDATED.value
                ),
                consent_granted=True,
                reset_epoch=ws.reset_epoch,
                validated_evidence_json={
                    "last_run_id": str(run.id),
                    "tool_slug": norm_tool,
                    "evidence_sha256": ev_sha,
                    "summary": redacted_ev[:500],
                },
                remediation_notes="",
                retest_passed=is_retest,
                attempts_count=1,
                updated_by=actor_id,
            )
            db.add(existing_progress)
        else:
            existing_progress.reset_epoch = ws.reset_epoch
            existing_progress.attempts_count += 1
            existing_progress.updated_by = actor_id
            existing_progress.validated_evidence_json = {
                "last_run_id": str(run.id),
                "tool_slug": norm_tool,
                "evidence_sha256": ev_sha,
                "summary": redacted_ev[:500],
            }
            if is_retest:
                existing_progress.status = LabProgressStatus.RETESTED.value
                existing_progress.retest_passed = True
            else:
                existing_progress.status = LabProgressStatus.VALIDATED.value
                existing_progress.retest_passed = False
        updated_progress = existing_progress

    _record_lab_audit(
        db,
        organization_id=organization_id,
        workspace_id=ws.id,
        action=(
            LabAuditAction.CHALLENGE_RETESTED if is_retest else LabAuditAction.CHALLENGE_VALIDATED
        ),
        actor_id=actor_id,
        actor_email=actor_email,
        target_url=safe_stored_url,
        details={
            "challenge_slug": ch.slug,
            "action_type": norm_action,
            "tool_slug": norm_tool,
            "reset_epoch": ws.reset_epoch,
            "consent_persisted": ws.consent_to_persist_progress,
        },
    )
    await db.flush()
    return run, updated_progress


async def record_challenge_remediation(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    workspace_id: uuid.UUID,
    challenge_id: uuid.UUID,
    remediation_notes: str,
    actor_id: uuid.UUID,
    actor_email: str,
    actor_role: str | None = None,
    settings: Settings | None = None,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> LabChallengeProgress:
    """Record practitioner remediation notes before running remediation retest."""
    await _enforce_opa_if_configured(
        settings=settings,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        action="lab:practice",
        lab_action_type="remediation_retest",
        opa_transport=opa_transport,
    )
    ws = (
        await db.execute(
            select(LabWorkspace).where(
                LabWorkspace.id == workspace_id,
                LabWorkspace.organization_id == organization_id,
            )
        )
    ).scalar_one_or_none()
    if ws is None:
        raise NotFoundError("Lab workspace not found")
    if not ws.consent_to_persist_progress:
        raise ForbiddenError(
            "Organization consent_to_persist_progress is required to store challenge remediation"
        )

    progress = (
        await db.execute(
            select(LabChallengeProgress)
            .where(
                LabChallengeProgress.organization_id == organization_id,
                LabChallengeProgress.workspace_id == ws.id,
                LabChallengeProgress.challenge_id == challenge_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if progress is None or progress.status not in {
        LabProgressStatus.VALIDATED.value,
        LabProgressStatus.REMEDIATED.value,
        LabProgressStatus.RETESTED.value,
    }:
        raise ValidationError("Challenge must be validated safely before recording remediation")

    clean_notes = classify_and_redact_payload(remediation_notes.strip()).redacted_text
    if len(clean_notes) < 10:
        raise ValidationError("remediation_notes must describe concrete fix details (min 10 chars)")
    progress.remediation_notes = clean_notes
    progress.status = LabProgressStatus.REMEDIATED.value
    progress.retest_passed = False
    progress.updated_by = actor_id

    _record_lab_audit(
        db,
        organization_id=organization_id,
        workspace_id=ws.id,
        action=LabAuditAction.CHALLENGE_REMEDIATED,
        actor_id=actor_id,
        actor_email=actor_email,
        details={"challenge_id": str(challenge_id), "reset_epoch": ws.reset_epoch},
    )
    await db.flush()
    return progress


def _resolve_lock_dir(explicit: Path | None) -> Path | None:
    if explicit is not None:
        return explicit
    for candidate in (Path("/opt/lifecycle/image-lock"), Path("lifecycle/image-lock")):
        if candidate.is_dir():
            return candidate
    for parent in Path(__file__).resolve().parents:
        repo_candidate = parent / "lifecycle" / "image-lock"
        if repo_candidate.is_dir():
            return repo_candidate
    return None


def _inspect_raw_image_locks(lock_dir: Path | None, clean_comp: str) -> list[dict[str, Any]]:
    """Inspect raw JSON lockfiles honestly without aborting on unpinned/bad entries."""
    resolved = _resolve_lock_dir(lock_dir)
    if resolved is None or not resolved.is_dir():
        return [
            {
                "id": "SELF-PIN-MISSING",
                "severity": "critical",
                "component": clean_comp,
                "summary": "Image lock directory missing or unmounted — cannot verify pins",
                "status": "open",
            }
        ]
    lock_files = sorted(p for p in resolved.glob("*.json") if p.name != "schema.json")
    if not lock_files:
        return [
            {
                "id": "SELF-PIN-EMPTY",
                "severity": "critical",
                "component": clean_comp,
                "summary": "Zero image lock JSON manifests found — cannot verify pins",
                "status": "open",
            }
        ]

    findings: list[dict[str, Any]] = []
    for lf in lock_files:
        try:
            payload = json.loads(lf.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            findings.append(
                {
                    "id": f"SELF-PIN-PARSE-{len(findings) + 1:03d}",
                    "severity": "high",
                    "component": clean_comp,
                    "summary": f"Malformed lock manifest '{lf.name}': {exc}",
                    "status": "open",
                }
            )
            continue
        raw_entries: Any = (
            payload
            if isinstance(payload, list)
            else payload.get("tools") or payload.get("images") or []
        )
        if not isinstance(raw_entries, list):
            continue
        for idx, entry in enumerate(raw_entries):
            if not isinstance(entry, dict):
                continue
            ident = str(entry.get("tool_id") or entry.get("name") or f"{lf.name}#{idx}")
            tag = str(
                entry.get("tag") or entry.get("tool_version") or entry.get("version_tag") or ""
            ).strip()
            digest = str(entry.get("digest") or "").strip().lower()
            if not tag or tag.lower() == "latest" or not _SHA256_HEX_RE.fullmatch(digest):
                findings.append(
                    {
                        "id": f"SELF-PIN-UNSAFE-{len(findings) + 1:03d}",
                        "severity": "critical",
                        "component": clean_comp,
                        "summary": f"Unpinned or invalid digest in '{lf.name}' entry '{ident}'",
                        "status": "open",
                    }
                )
    return findings


def _find_compose_file(candidates: tuple[Path, ...]) -> Path | None:
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    for parent in Path(__file__).resolve().parents:
        for cand in candidates:
            if not cand.is_absolute():
                joined = parent / cand
                if joined.is_file():
                    return joined
    return None


async def run_vforge_self_scan(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    target_component: str,
    profile_name: str,
    actor_id: uuid.UUID,
    actor_email: str,
    actor_role: str | None = None,
    settings: Settings | None = None,
    opa_transport: httpx.AsyncBaseTransport | None = None,
    compose_path: Path | None = None,
    lock_dir: Path | None = None,
) -> LabSelfScan:
    """Run honest self-verification posture checks across VForge control-plane artifacts."""
    await _enforce_opa_if_configured(
        settings=settings,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        action="lab:manage",
        opa_transport=opa_transport,
    )
    clean_comp = target_component.strip()
    if clean_comp not in _ALLOWED_SELF_SCAN_COMPONENTS:
        raise ValidationError(
            f"Unsupported self-scan component '{clean_comp}'. Allowed: "
            f"{sorted(_ALLOWED_SELF_SCAN_COMPONENTS)}"
        )

    findings: list[dict[str, Any]] = []
    checks_executed = 0

    # Check 1: Lab topology egress & pin isolation
    compose_report = verify_lab_compose_isolation(compose_path=compose_path)
    checks_executed += 1
    if not compose_report["verified"]:
        for v in compose_report["violations"]:
            findings.append(
                {
                    "id": f"SELF-LAB-{len(findings) + 1:03d}",
                    "severity": "high",
                    "component": clean_comp,
                    "summary": v,
                    "status": "open",
                }
            )

    # Check 2: Raw JSON lockfile digest inspection (never fails open or crashes 422 on defects)
    checks_executed += 1
    findings.extend(_inspect_raw_image_locks(lock_dir, clean_comp))

    # Check 3: Control-plane & component-specific artifact verification
    ctrl_compose = _find_compose_file(
        (Path("/opt/infrastructure/docker-compose.yml"), Path("docker-compose.yml"))
    )
    checks_executed += 1
    if ctrl_compose is None:
        findings.append(
            {
                "id": f"SELF-CTRL-MISSING-{len(findings) + 1:03d}",
                "severity": "medium",
                "component": clean_comp,
                "summary": "Control-plane docker-compose.yml unmounted — check incomplete",
                "status": "open",
            }
        )
    else:
        raw_ctrl = ctrl_compose.read_text(encoding="utf-8")
        if "/var/run/docker.sock" in raw_ctrl or "privileged: true" in raw_ctrl:
            findings.append(
                {
                    "id": f"SELF-CTRL-{len(findings) + 1:03d}",
                    "severity": "critical",
                    "component": clean_comp,
                    "summary": "Docker socket or privileged mode detected in control-plane Compose",
                    "status": "open",
                }
            )

    if clean_comp == "runner_agent":
        checks_executed += 1
        runner_compose = _find_compose_file(
            (
                Path("/opt/infrastructure/docker-compose.runner.yml"),
                Path("runner/docker-compose.runner.yml"),
            )
        )
        if runner_compose is None:
            findings.append(
                {
                    "id": f"SELF-RUN-MISSING-{len(findings) + 1:03d}",
                    "severity": "medium",
                    "component": clean_comp,
                    "summary": "Runner compose manifest unmounted — runner check incomplete",
                    "status": "open",
                }
            )
    elif clean_comp == "opa_policies":
        checks_executed += 1
        authz_rego = _find_compose_file(
            (
                Path("/opt/policies/rego/vforge/authz.rego"),
                Path("policies/rego/vforge/authz.rego"),
            )
        )
        if authz_rego is None or "default allow := false" not in authz_rego.read_text(
            encoding="utf-8"
        ):
            findings.append(
                {
                    "id": f"SELF-OPA-{len(findings) + 1:03d}",
                    "severity": "critical",
                    "component": clean_comp,
                    "summary": "OPA authz.rego missing or lacks fail-closed default allow := false",
                    "status": "open",
                }
            )

    crit_high = sum(
        1 for f in findings if str(f.get("severity", "")).lower() in {"critical", "high"}
    )
    summary_msg = (
        f"Executed {checks_executed} honest baseline security self-checks on '{clean_comp}' "
        f"(profile='{profile_name.strip()}'); {crit_high} critical/high findings detected."
    )
    scan = LabSelfScan(
        id=uuid.uuid4(),
        organization_id=organization_id,
        target_component=clean_comp,
        profile_name=profile_name.strip(),
        checks_executed=checks_executed,
        issues_found=len(findings),
        critical_high_count=crit_high,
        findings_json=findings,
        remediation_summary=summary_msg,
        regression_verified=crit_high == 0 and len(findings) == 0,
        status="completed_with_findings" if findings else "completed",
        executed_by=actor_id,
    )
    db.add(scan)
    _record_lab_audit(
        db,
        organization_id=organization_id,
        workspace_id=None,
        action=LabAuditAction.SELF_SCAN_EXECUTED,
        actor_id=actor_id,
        actor_email=actor_email,
        details={
            "target_component": clean_comp,
            "checks_executed": checks_executed,
            "issues_found": len(findings),
            "critical_high_count": crit_high,
        },
    )
    await db.flush()
    return scan


async def get_lab_overview(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
) -> dict[str, Any]:
    """Return full tenant-isolated Phase 13 lab overview."""
    challenges = await list_challenges(db)
    workspaces = (
        (
            await db.execute(
                select(LabWorkspace)
                .where(LabWorkspace.organization_id == organization_id)
                .order_by(LabWorkspace.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    consented_ws_ids = {ws.id for ws in workspaces if ws.consent_to_persist_progress}
    progress = (
        (
            await db.execute(
                select(LabChallengeProgress)
                .where(
                    LabChallengeProgress.organization_id == organization_id,
                    LabChallengeProgress.workspace_id.in_(consented_ws_ids),
                )
                .order_by(LabChallengeProgress.updated_at.desc())
            )
        )
        .scalars()
        .all()
        if consented_ws_ids
        else []
    )
    validations = (
        (
            await db.execute(
                select(LabValidationRun)
                .where(LabValidationRun.organization_id == organization_id)
                .order_by(LabValidationRun.created_at.desc())
                .limit(25)
            )
        )
        .scalars()
        .all()
    )
    self_scans = (
        (
            await db.execute(
                select(LabSelfScan)
                .where(LabSelfScan.organization_id == organization_id)
                .order_by(LabSelfScan.created_at.desc())
                .limit(15)
            )
        )
        .scalars()
        .all()
    )
    audits = (
        (
            await db.execute(
                select(LabAuditEvent)
                .where(LabAuditEvent.organization_id == organization_id)
                .order_by(LabAuditEvent.occurred_at.desc())
                .limit(30)
            )
        )
        .scalars()
        .all()
    )
    return {
        "challenges": challenges,
        "workspaces": list(workspaces),
        "progress": list(progress),
        "validation_runs": list(validations),
        "self_scans": list(self_scans),
        "audit_events": list(audits),
        "compose_isolation": verify_lab_compose_isolation(),
    }
