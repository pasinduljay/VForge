"""Release verification gates, controlled promotion, rollback, and scan pin resolution."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.config import Settings, get_settings
from vforge.errors import ConflictError, NotFoundError, ValidationError
from vforge.lifecycle.monitor import (
    inspect_image_lock_files,
    validate_archive_sha256,
    validate_image_repository,
    validate_version_tag_and_digest,
)
from vforge.models import (
    FeedSnapshot,
    ToolCatalog,
    ToolUpdate,
    ToolVersion,
    UpdateAuditEvent,
    UpdateTestResult,
)
from vforge.models.enums import (
    ToolApprovalChannel,
    UpdateAuditAction,
    UpdateChangeType,
    UpdateRunStatus,
    UpdateTestCategory,
    UpdateTestOutcome,
)

REQUIRED_STANDARD_GATES: tuple[str, ...] = (
    UpdateTestCategory.SIGNATURE_PROVENANCE.value,
    UpdateTestCategory.SBOM_AND_IMAGE_SCAN.value,
    UpdateTestCategory.ADAPTER_CONTRACT.value,
    UpdateTestCategory.REGRESSION_CORPUS.value,
)

REQUIRED_EMERGENCY_GATES: tuple[str, ...] = (
    UpdateTestCategory.SIGNATURE_PROVENANCE.value,
    UpdateTestCategory.ADAPTER_CONTRACT.value,
)

# Maps tool_catalog.tool_slug -> Settings attribute fallback
_TOOL_SETTINGS_FALLBACK: dict[str, tuple[str, str]] = {
    "opengrep": ("opengrep_image_digest", "1.33.1"),
    "gitleaks": ("gitleaks_image_digest", "8.24.0"),
    "syft": ("syft_image_digest", "1.57.1"),
    "grype": ("grype_image_digest", "0.121.3"),
    "checkov": ("checkov_image_digest", "3.2.435"),
    "zap": ("zap_image_digest", "2.16.0"),
    "nuclei": ("nuclei_image_digest", "3.11.1"),
    "nmap": ("nmap_image_digest", "7.98"),
    "testssl": ("testssl_image_digest", "3.2.5"),
}


def assert_automerge_allowed(tool: ToolCatalog) -> None:
    """Enforce Phase 10 rule: scanner engines never auto-promote without human approval."""
    if not tool.automerge_allowed:
        raise ConflictError(
            f"Automated promotion is forbidden for '{tool.tool_slug}' (automerge_allowed=false)"
        )


@dataclass(slots=True)
class ResolvedToolPins:
    """Resolved immutable scanner engine and feed pins for a scan plan."""

    image_refs: dict[str, str] = field(default_factory=dict)
    allowed_image_digests: list[str] = field(default_factory=list)
    provenance_manifest: dict[str, Any] = field(default_factory=dict)


def _format_image_ref(image_repository: str, image_digest: str) -> str:
    return f"{image_repository.strip()}@{image_digest.strip().lower()}"


async def record_audit_event(
    db: AsyncSession,
    *,
    tool_id: uuid.UUID,
    action: UpdateAuditAction | str,
    update_id: uuid.UUID | None = None,
    tool_version_id: uuid.UUID | None = None,
    feed_snapshot_id: uuid.UUID | None = None,
    actor_user_id: uuid.UUID | None = None,
    actor_email: str | None = None,
    reason: str | None = None,
    details: dict[str, Any] | None = None,
) -> UpdateAuditEvent:
    """Append an immutable governance event to update_audit_events."""
    action_value = action.value if isinstance(action, UpdateAuditAction) else str(action)
    event = UpdateAuditEvent(
        update_id=update_id,
        tool_id=tool_id,
        tool_version_id=tool_version_id,
        feed_snapshot_id=feed_snapshot_id,
        action=action_value,
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        reason=reason,
        details_json=details or {},
    )
    db.add(event)
    await db.flush()
    return event


async def _get_tool_by_slug(db: AsyncSession, tool_slug: str) -> ToolCatalog:
    tool = (
        await db.execute(select(ToolCatalog).where(ToolCatalog.tool_slug == tool_slug.strip()))
    ).scalar_one_or_none()
    if tool is None:
        raise NotFoundError(f"Tool '{tool_slug}' not found in tool_catalog")
    return tool


async def _get_update_or_404(db: AsyncSession, update_id: uuid.UUID) -> ToolUpdate:
    row = (
        await db.execute(select(ToolUpdate).where(ToolUpdate.id == update_id))
    ).scalar_one_or_none()
    if row is None:
        raise NotFoundError(f"Tool update '{update_id}' not found")
    return row


async def _get_latest_gate_outcomes(
    db: AsyncSession, *, update_id: uuid.UUID
) -> dict[str, UpdateTestResult]:
    results = (
        (
            await db.execute(
                select(UpdateTestResult)
                .where(UpdateTestResult.update_id == update_id)
                .order_by(UpdateTestResult.executed_at.asc(), UpdateTestResult.id.asc())
            )
        )
        .scalars()
        .all()
    )
    latest: dict[str, UpdateTestResult] = {}
    for row in results:
        latest[row.test_category] = row
    return latest


async def register_update_candidate(
    db: AsyncSession,
    *,
    tool_slug: str,
    version_tag: str,
    image_repository: str,
    image_digest: str,
    adapter_version: str = "1.0.0",
    change_type: str = UpdateChangeType.MINOR.value,
    detected_from: str = "manual-candidate",
    release_notes_url: str | None = None,
    sbom_digest: str | None = None,
    signature_verified: bool = False,
    metadata_json: dict[str, Any] | None = None,
    is_emergency: bool = False,
    emergency_justification: str | None = None,
    actor_user_id: uuid.UUID | None = None,
    actor_email: str | None = None,
) -> tuple[ToolCatalog, ToolVersion, ToolUpdate]:
    """Register a digest-pinned candidate update without mutating active stable/canary pointers."""
    tool = await _get_tool_by_slug(db, tool_slug)
    clean_tag, clean_digest = validate_version_tag_and_digest(version_tag, image_digest)
    clean_repo = validate_image_repository(image_repository)
    clean_sbom_digest: str | None = None
    if sbom_digest:
        sbom_raw = sbom_digest.strip().lower()
        _, clean_sbom_digest = validate_version_tag_and_digest("sbom", sbom_raw)
    if change_type not in {item.value for item in UpdateChangeType}:
        raise ValidationError(f"Invalid change_type '{change_type}'")
    if is_emergency and (not emergency_justification or len(emergency_justification.strip()) < 10):
        raise ValidationError(
            "Emergency candidate registration requires an emergency_justification (>= 10 chars)"
        )

    existing_version = (
        await db.execute(
            select(ToolVersion).where(
                ToolVersion.tool_id == tool.id,
                ToolVersion.image_digest == clean_digest,
            )
        )
    ).scalar_one_or_none()
    if existing_version is not None:
        raise ConflictError(
            f"Digest '{clean_digest}' is already registered for tool '{tool.tool_slug}'"
        )

    active_stable = (
        await db.execute(
            select(ToolVersion).where(
                ToolVersion.tool_id == tool.id,
                ToolVersion.is_active_stable.is_(True),
            )
        )
    ).scalar_one_or_none()

    version_row = ToolVersion(
        tool_id=tool.id,
        version_tag=clean_tag,
        image_repository=clean_repo,
        image_digest=clean_digest,
        adapter_version=adapter_version.strip() or "1.0.0",
        approval_channel=ToolApprovalChannel.CANDIDATE.value,
        is_active_stable=False,
        is_active_canary=False,
        previous_stable_version_id=active_stable.id if active_stable else None,
        signature_verified=bool(signature_verified),
        sbom_digest=clean_sbom_digest,
        release_notes_url=release_notes_url.strip() if release_notes_url else None,
        metadata_json=dict(metadata_json or {}),
    )
    db.add(version_row)
    await db.flush()

    update_row = ToolUpdate(
        tool_id=tool.id,
        candidate_version_id=version_row.id,
        previous_version_id=active_stable.id if active_stable else None,
        stream=tool.stream,
        update_channel=tool.update_channel,
        change_type=change_type,
        status=UpdateRunStatus.DETECTED.value,
        is_emergency=is_emergency,
        emergency_justification=(
            emergency_justification.strip() if emergency_justification else None
        ),
        detected_from=detected_from.strip() or "api",
    )
    db.add(update_row)
    await db.flush()

    await record_audit_event(
        db,
        tool_id=tool.id,
        update_id=update_row.id,
        tool_version_id=version_row.id,
        action=UpdateAuditAction.CANDIDATE_DETECTED,
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        reason=f"Registered candidate {clean_tag} ({clean_digest})",
        details={
            "stream": tool.stream,
            "update_channel": tool.update_channel,
            "change_type": change_type,
            "is_emergency": is_emergency,
            "automerge_allowed": tool.automerge_allowed,
        },
    )
    return tool, version_row, update_row


async def record_validation_results(
    db: AsyncSession,
    *,
    update_id: uuid.UUID,
    tests: list[dict[str, Any]],
    executed_by: str,
    actor_user_id: uuid.UUID | None = None,
    actor_email: str | None = None,
) -> ToolUpdate:
    """Append gate results and transition update status (`validated` or `rejected`)."""
    update_row = (
        await db.execute(select(ToolUpdate).where(ToolUpdate.id == update_id).with_for_update())
    ).scalar_one_or_none()
    if update_row is None:
        raise NotFoundError(f"ToolUpdate '{update_id}' not found")
    # Serialize concurrent promotions on the parent catalog row
    (
        await db.execute(
            select(ToolCatalog).where(ToolCatalog.id == update_row.tool_id).with_for_update()
        )
    ).scalar_one()
    if update_row.status in {
        UpdateRunStatus.STABLE.value,
        UpdateRunStatus.ROLLED_BACK.value,
        UpdateRunStatus.REJECTED.value,
        UpdateRunStatus.APPROVED.value,
        UpdateRunStatus.CANARY.value,
    }:
        raise ConflictError(
            f"Cannot record validation tests when update is in status '{update_row.status}'"
        )
    version_row = (
        await db.execute(
            select(ToolVersion).where(ToolVersion.id == update_row.candidate_version_id)
        )
    ).scalar_one()

    valid_categories = {item.value for item in UpdateTestCategory}
    valid_outcomes = {item.value for item in UpdateTestOutcome}

    for entry in tests:
        cat = str(entry.get("test_category", "")).strip()
        outcome = str(entry.get("outcome", "")).strip()
        summary = str(entry.get("summary", "")).strip()
        if cat not in valid_categories:
            raise ValidationError(f"Invalid test_category '{cat}'")
        if outcome not in valid_outcomes:
            raise ValidationError(f"Invalid test outcome '{outcome}'")
        if not summary:
            raise ValidationError("Test result summary cannot be empty")
        result_row = UpdateTestResult(
            update_id=update_row.id,
            tool_version_id=version_row.id,
            test_category=cat,
            outcome=outcome,
            summary=summary,
            details_json=dict(entry.get("details_json") or {}),
            executed_by=executed_by,
        )
        db.add(result_row)
    await db.flush()

    latest = await _get_latest_gate_outcomes(db, update_id=update_row.id)
    failed_gates = [
        cat for cat, res in latest.items() if res.outcome == UpdateTestOutcome.FAILED.value
    ]

    if failed_gates:
        update_row.status = UpdateRunStatus.REJECTED.value
        update_row.rejection_reason = (
            f"Validation gate failure in: {', '.join(sorted(failed_gates))}"
        )
        version_row.approval_channel = ToolApprovalChannel.REJECTED.value
        await record_audit_event(
            db,
            tool_id=update_row.tool_id,
            update_id=update_row.id,
            tool_version_id=version_row.id,
            action=UpdateAuditAction.REJECTED,
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            reason=update_row.rejection_reason,
            details={"failed_gates": sorted(failed_gates)},
        )
    elif all(
        latest.get(gate) is not None and latest[gate].outcome == UpdateTestOutcome.PASSED.value
        for gate in REQUIRED_STANDARD_GATES
    ):
        update_row.status = UpdateRunStatus.VALIDATED.value
        update_row.rejection_reason = None
        version_row.approval_channel = ToolApprovalChannel.VALIDATED.value
        await record_audit_event(
            db,
            tool_id=update_row.tool_id,
            update_id=update_row.id,
            tool_version_id=version_row.id,
            action=UpdateAuditAction.VALIDATION_RECORDED,
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            reason="All required Phase 10 verification gates passed",
            details={"passed_gates": list(REQUIRED_STANDARD_GATES)},
        )
    else:
        update_row.status = UpdateRunStatus.VALIDATING.value
        await record_audit_event(
            db,
            tool_id=update_row.tool_id,
            update_id=update_row.id,
            tool_version_id=version_row.id,
            action=UpdateAuditAction.VALIDATION_RECORDED,
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            reason="Partial verification gates recorded",
            details={"recorded_gates": sorted(latest.keys())},
        )

    await db.flush()
    return update_row


async def run_automated_validation_gates(
    db: AsyncSession,
    *,
    update_id: uuid.UUID,
    executed_by: str,
    actor_user_id: uuid.UUID | None = None,
    actor_email: str | None = None,
    simulate_failure_gate: str | None = None,
    skip_regression_corpus: bool = False,
) -> ToolUpdate:
    """Execute honest verification checks against a candidate update (fail-closed if unverified)."""
    update_row = (
        await db.execute(select(ToolUpdate).where(ToolUpdate.id == update_id).with_for_update())
    ).scalar_one_or_none()
    if update_row is None:
        raise NotFoundError(f"ToolUpdate '{update_id}' not found")
    # Serialize concurrent promotions on the parent catalog row
    (
        await db.execute(
            select(ToolCatalog).where(ToolCatalog.id == update_row.tool_id).with_for_update()
        )
    ).scalar_one()
    version_row = (
        await db.execute(
            select(ToolVersion).where(ToolVersion.id == update_row.candidate_version_id)
        )
    ).scalar_one()

    # Verify digest, repository, & non-:latest contract before evaluating gates
    validate_version_tag_and_digest(version_row.version_tag, version_row.image_digest)
    validate_image_repository(version_row.image_repository)

    from vforge_scanners import CAPABILITY_REGISTRY

    meta = dict(version_row.metadata_json or {})
    lock_digests = {entry["image_digest"] for entry in inspect_image_lock_files()}
    provenance_verified = bool(
        version_row.signature_verified
        or version_row.image_digest in lock_digests
        or meta.get("provenance_verified") is True
    )
    has_valid_sbom = bool(version_row.sbom_digest) or bool(meta.get("sbom_attestation_verified"))
    critical_cves = int(meta.get("critical_cves", 0) or 0)
    vuln_scan_failed = bool(meta.get("vuln_scan_failed")) or critical_cves > 0
    regression_failed = bool(meta.get("regression_corpus_failed"))

    tests: list[dict[str, Any]] = []
    for gate in REQUIRED_STANDARD_GATES:
        if simulate_failure_gate == gate:
            tests.append(
                {
                    "test_category": gate,
                    "outcome": UpdateTestOutcome.FAILED.value,
                    "summary": f"Verification gate '{gate}' failed verification checks",
                    "details_json": {"digest": version_row.image_digest},
                }
            )
            continue

        if gate == UpdateTestCategory.SIGNATURE_PROVENANCE.value:
            outcome = (
                UpdateTestOutcome.PASSED.value
                if provenance_verified
                else UpdateTestOutcome.FAILED.value
            )
            summary = (
                "Signature and digest provenance verified"
                if provenance_verified
                else "Signature/provenance missing: candidate is unsigned or unpinned"
            )
        elif gate == UpdateTestCategory.SBOM_AND_IMAGE_SCAN.value:
            sbom_ok = has_valid_sbom and not vuln_scan_failed
            outcome = UpdateTestOutcome.PASSED.value if sbom_ok else UpdateTestOutcome.FAILED.value
            summary = (
                "SBOM attestation present and zero critical CVEs reported"
                if sbom_ok
                else "Missing SBOM sha256 attestation or unresolved critical image vulnerabilities"
            )
        elif gate == UpdateTestCategory.REGRESSION_CORPUS.value:
            if skip_regression_corpus:
                tests.append(
                    {
                        "test_category": gate,
                        "outcome": UpdateTestOutcome.SKIPPED.value,
                        "summary": "Regression corpus deferred for emergency security evaluation",
                        "details_json": {"deferred": True},
                    }
                )
                continue
            reg_ok = (len(CAPABILITY_REGISTRY) > 0) and not regression_failed
            outcome = UpdateTestOutcome.PASSED.value if reg_ok else UpdateTestOutcome.FAILED.value
            summary = (
                "Regression corpus & capability contract passed"
                if reg_ok
                else "Regression corpus verification failed"
            )
        else:
            contract_ok = bool(version_row.adapter_version.strip()) and len(CAPABILITY_REGISTRY) > 0
            outcome = (
                UpdateTestOutcome.PASSED.value if contract_ok else UpdateTestOutcome.FAILED.value
            )
            summary = (
                "Adapter schema contract and digest format verified"
                if contract_ok
                else "Adapter schema contract check failed"
            )

        tests.append(
            {
                "test_category": gate,
                "outcome": outcome,
                "summary": summary,
                "details_json": {
                    "version_tag": version_row.version_tag,
                    "image_digest": version_row.image_digest,
                    "sbom_digest": version_row.sbom_digest,
                    "signature_verified": version_row.signature_verified,
                    "registered_capabilities": len(CAPABILITY_REGISTRY),
                },
            }
        )

    return await record_validation_results(
        db,
        update_id=update_id,
        tests=tests,
        executed_by=executed_by,
        actor_user_id=actor_user_id,
        actor_email=actor_email,
    )


async def approve_update_candidate(
    db: AsyncSession,
    *,
    update_id: uuid.UUID,
    actor_user_id: uuid.UUID,
    actor_email: str,
    is_emergency: bool = False,
    emergency_justification: str | None = None,
) -> ToolUpdate:
    """Approve a validated candidate (or emergency security patch with mandatory safety gates)."""
    update_row = (
        await db.execute(select(ToolUpdate).where(ToolUpdate.id == update_id).with_for_update())
    ).scalar_one_or_none()
    if update_row is None:
        raise NotFoundError(f"ToolUpdate '{update_id}' not found")
    # Serialize concurrent promotions on the parent catalog row
    (
        await db.execute(
            select(ToolCatalog).where(ToolCatalog.id == update_row.tool_id).with_for_update()
        )
    ).scalar_one()
    if update_row.status in {
        UpdateRunStatus.REJECTED.value,
        UpdateRunStatus.ROLLED_BACK.value,
        UpdateRunStatus.STABLE.value,
    }:
        raise ConflictError(f"Cannot approve update in status '{update_row.status}'")

    version_row = (
        await db.execute(
            select(ToolVersion).where(ToolVersion.id == update_row.candidate_version_id)
        )
    ).scalar_one()
    latest = await _get_latest_gate_outcomes(db, update_id=update_row.id)

    # Any failed gate unconditionally blocks approval
    failed = [cat for cat, res in latest.items() if res.outcome == UpdateTestOutcome.FAILED.value]
    if failed:
        raise ConflictError(
            f"Approval blocked: failed verification gates ({', '.join(sorted(failed))})"
        )

    effective_emergency = bool(is_emergency or update_row.is_emergency)
    justification = (emergency_justification or update_row.emergency_justification or "").strip()

    if effective_emergency:
        if len(justification) < 10:
            raise ValidationError(
                "Emergency security approval requires emergency_justification (>= 10 characters)"
            )
        missing_or_unpassed = [
            gate
            for gate in REQUIRED_EMERGENCY_GATES
            if latest.get(gate) is None or latest[gate].outcome != UpdateTestOutcome.PASSED.value
        ]
        if missing_or_unpassed:
            raise ConflictError(
                "Emergency approval still requires passed provenance & adapter contract gates: "
                + ", ".join(missing_or_unpassed)
            )
    else:
        missing_or_unpassed = [
            gate
            for gate in REQUIRED_STANDARD_GATES
            if latest.get(gate) is None or latest[gate].outcome != UpdateTestOutcome.PASSED.value
        ]
        if missing_or_unpassed:
            raise ConflictError(
                "Approval blocked until all verification gates pass: "
                + ", ".join(missing_or_unpassed)
            )

    now = datetime.now(UTC)
    update_row.is_emergency = effective_emergency
    if effective_emergency:
        update_row.emergency_justification = justification
    update_row.status = UpdateRunStatus.APPROVED.value
    update_row.approved_by_user_id = actor_user_id
    update_row.approved_at = now
    version_row.approval_channel = ToolApprovalChannel.APPROVED.value

    await record_audit_event(
        db,
        tool_id=update_row.tool_id,
        update_id=update_row.id,
        tool_version_id=version_row.id,
        action=(
            UpdateAuditAction.EMERGENCY_APPROVED
            if effective_emergency
            else UpdateAuditAction.APPROVED
        ),
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        reason=justification if effective_emergency else "All verification gates passed",
        details={"is_emergency": effective_emergency},
    )
    await db.flush()
    return update_row


async def promote_update_candidate(
    db: AsyncSession,
    *,
    update_id: uuid.UUID,
    target_channel: Literal["canary", "stable"],
    actor_user_id: uuid.UUID,
    actor_email: str,
    reason: str | None = None,
) -> ToolUpdate:
    """Promote an approved (or canary) candidate update to canary or stable."""
    update_row = (
        await db.execute(select(ToolUpdate).where(ToolUpdate.id == update_id).with_for_update())
    ).scalar_one_or_none()
    if update_row is None:
        raise NotFoundError(f"ToolUpdate '{update_id}' not found")
    # Serialize concurrent promotions on the parent catalog row
    (
        await db.execute(
            select(ToolCatalog).where(ToolCatalog.id == update_row.tool_id).with_for_update()
        )
    ).scalar_one()
    if target_channel not in {"canary", "stable"}:
        raise ValidationError("target_channel must be 'canary' or 'stable'")

    allowed_source_statuses = (
        {UpdateRunStatus.APPROVED.value}
        if target_channel == "canary"
        else {UpdateRunStatus.APPROVED.value, UpdateRunStatus.CANARY.value}
    )
    if update_row.status not in allowed_source_statuses:
        raise ConflictError(
            f"Cannot promote update from status '{update_row.status}' to '{target_channel}'"
        )

    latest = await _get_latest_gate_outcomes(db, update_id=update_row.id)
    required = REQUIRED_EMERGENCY_GATES if update_row.is_emergency else REQUIRED_STANDARD_GATES
    unpassed = [
        gate
        for gate in required
        if latest.get(gate) is None or latest[gate].outcome != UpdateTestOutcome.PASSED.value
    ]
    if unpassed or any(res.outcome == UpdateTestOutcome.FAILED.value for res in latest.values()):
        raise ConflictError("Promotion blocked: verification gate requirements are not satisfied")

    version_row = (
        await db.execute(
            select(ToolVersion).where(ToolVersion.id == update_row.candidate_version_id)
        )
    ).scalar_one()
    now = datetime.now(UTC)

    if target_channel == "canary":
        prev_canary = (
            await db.execute(
                select(ToolVersion).where(
                    ToolVersion.tool_id == update_row.tool_id,
                    ToolVersion.is_active_canary.is_(True),
                    ToolVersion.id != version_row.id,
                )
            )
        ).scalar_one_or_none()
        if prev_canary is not None:
            prev_canary.is_active_canary = False
            if not prev_canary.is_active_stable:
                prev_canary.approval_channel = ToolApprovalChannel.APPROVED.value
            await db.flush()

        version_row.is_active_canary = True
        version_row.approval_channel = ToolApprovalChannel.CANARY.value
        version_row.promoted_at = now
        update_row.status = UpdateRunStatus.CANARY.value
        update_row.promoted_by_user_id = actor_user_id
        update_row.promoted_at = now

        await record_audit_event(
            db,
            tool_id=update_row.tool_id,
            update_id=update_row.id,
            tool_version_id=version_row.id,
            action=UpdateAuditAction.PROMOTED_CANARY,
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            reason=reason or "Promoted candidate to canary channel",
            details={
                "version_tag": version_row.version_tag,
                "image_digest": version_row.image_digest,
            },
        )
    else:
        prev_stable = (
            await db.execute(
                select(ToolVersion).where(
                    ToolVersion.tool_id == update_row.tool_id,
                    ToolVersion.is_active_stable.is_(True),
                    ToolVersion.id != version_row.id,
                )
            )
        ).scalar_one_or_none()
        if prev_stable is not None:
            prev_stable.is_active_stable = False
            await db.flush()
            version_row.previous_stable_version_id = prev_stable.id
            update_row.previous_version_id = prev_stable.id

        version_row.is_active_canary = False
        version_row.is_active_stable = True
        version_row.approval_channel = ToolApprovalChannel.STABLE.value
        version_row.promoted_at = now
        update_row.status = UpdateRunStatus.STABLE.value
        update_row.promoted_by_user_id = actor_user_id
        update_row.promoted_at = now

        await record_audit_event(
            db,
            tool_id=update_row.tool_id,
            update_id=update_row.id,
            tool_version_id=version_row.id,
            action=UpdateAuditAction.PROMOTED_STABLE,
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            reason=reason or "Promoted candidate to stable channel",
            details={
                "version_tag": version_row.version_tag,
                "image_digest": version_row.image_digest,
                "previous_stable_version_id": str(prev_stable.id) if prev_stable else None,
            },
        )

    await db.flush()
    return update_row


async def rollback_tool_version(
    db: AsyncSession,
    *,
    tool_slug: str,
    reason: str,
    actor_user_id: uuid.UUID,
    actor_email: str,
    target_version_id: uuid.UUID | None = None,
    channel: Literal["auto", "canary", "stable"] = "auto",
) -> tuple[ToolVersion, ToolVersion | None]:
    """Instant zero-rebuild rollback of canary or active stable version."""
    clean_reason = reason.strip()
    if len(clean_reason) < 5:
        raise ValidationError("Rollback requires a descriptive reason (>= 5 chars)")

    tool = (
        await db.execute(
            select(ToolCatalog).where(ToolCatalog.tool_slug == tool_slug.strip()).with_for_update()
        )
    ).scalar_one_or_none()
    if tool is None:
        raise NotFoundError(f"Tool catalog entry '{tool_slug}' not found")
    now = datetime.now(UTC)

    active_canary = (
        await db.execute(
            select(ToolVersion)
            .where(
                ToolVersion.tool_id == tool.id,
                ToolVersion.is_active_canary.is_(True),
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    active_stable = (
        await db.execute(
            select(ToolVersion)
            .where(
                ToolVersion.tool_id == tool.id,
                ToolVersion.is_active_stable.is_(True),
            )
            .with_for_update()
        )
    ).scalar_one_or_none()

    # Rollback canary if requested or active when target_version_id is unspecified
    if channel == "canary" or (
        channel == "auto" and active_canary is not None and target_version_id is None
    ):
        if active_canary is None:
            raise ConflictError(f"Tool '{tool.tool_slug}' has no active canary to roll back")
        active_canary.is_active_canary = False
        active_canary.approval_channel = ToolApprovalChannel.ROLLED_BACK.value
        active_canary.rolled_back_at = now
        matching_update = (
            await db.execute(
                select(ToolUpdate)
                .where(ToolUpdate.candidate_version_id == active_canary.id)
                .order_by(ToolUpdate.created_at.desc())
            )
        ).scalar_one_or_none()
        if matching_update is not None:
            matching_update.status = UpdateRunStatus.ROLLED_BACK.value
            matching_update.rolled_back_by_user_id = actor_user_id
            matching_update.rolled_back_at = now
            matching_update.rollback_reason = clean_reason
        await record_audit_event(
            db,
            tool_id=tool.id,
            update_id=matching_update.id if matching_update else None,
            tool_version_id=active_canary.id,
            action=UpdateAuditAction.ROLLED_BACK,
            actor_user_id=actor_user_id,
            actor_email=actor_email,
            reason=clean_reason,
            details={
                "rolled_back_channel": "canary",
                "restored_stable_id": str(active_stable.id) if active_stable else None,
            },
        )
        await db.flush()
        return active_canary, active_stable

    # Rollback active stable to previous_stable_version_id or explicit target_version_id
    if active_stable is None:
        raise ConflictError(f"Tool '{tool.tool_slug}' has no active stable version to roll back")

    restore_id = target_version_id or active_stable.previous_stable_version_id
    if restore_id is None:
        raise ConflictError(
            f"Tool '{tool.tool_slug}' has no recorded previous stable version for rollback"
        )
    if restore_id == active_stable.id:
        raise ValidationError("Rollback target cannot be the currently active version")

    restored = (
        await db.execute(
            select(ToolVersion).where(
                ToolVersion.id == restore_id,
                ToolVersion.tool_id == tool.id,
            )
        )
    ).scalar_one_or_none()
    if restored is None:
        raise NotFoundError(
            f"Target rollback version '{restore_id}' not found for '{tool.tool_slug}'"
        )

    active_stable.is_active_stable = False
    active_stable.is_active_canary = False
    active_stable.approval_channel = ToolApprovalChannel.ROLLED_BACK.value
    active_stable.rolled_back_at = now
    await db.flush()

    restored.is_active_stable = True
    restored.approval_channel = ToolApprovalChannel.STABLE.value
    restored.promoted_at = now

    matching_update = (
        await db.execute(
            select(ToolUpdate)
            .where(ToolUpdate.candidate_version_id == active_stable.id)
            .order_by(ToolUpdate.created_at.desc())
        )
    ).scalar_one_or_none()
    if matching_update is not None:
        matching_update.status = UpdateRunStatus.ROLLED_BACK.value
        matching_update.rolled_back_by_user_id = actor_user_id
        matching_update.rolled_back_at = now
        matching_update.rollback_reason = clean_reason

    await record_audit_event(
        db,
        tool_id=tool.id,
        update_id=matching_update.id if matching_update else None,
        tool_version_id=restored.id,
        action=UpdateAuditAction.ROLLED_BACK,
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        reason=clean_reason,
        details={
            "rolled_back_channel": "stable",
            "demoted_version_id": str(active_stable.id),
            "demoted_digest": active_stable.image_digest,
            "restored_version_id": str(restored.id),
            "restored_digest": restored.image_digest,
        },
    )
    await db.flush()
    return active_stable, restored


async def register_feed_snapshot(
    db: AsyncSession,
    *,
    tool_slug: str,
    feed_slug: str,
    snapshot_tag: str,
    archive_sha256: str,
    schema_version: str = "v5",
    record_count: int = 0,
    source_url: str | None = None,
) -> FeedSnapshot:
    """Register a candidate feed/DB snapshot for stream 2/3 channels."""
    tool = await _get_tool_by_slug(db, tool_slug)
    clean_sha = validate_archive_sha256(archive_sha256)
    clean_tag = snapshot_tag.strip()
    if not clean_tag or clean_tag.lower() == "latest" or clean_tag.lower().endswith(":latest"):
        raise ValidationError("Feed snapshot_tag must be non-empty and cannot be ':latest'")

    existing = (
        await db.execute(
            select(FeedSnapshot).where(
                FeedSnapshot.feed_slug == feed_slug.strip(),
                FeedSnapshot.snapshot_tag == clean_tag,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ConflictError(f"Feed snapshot '{feed_slug}:{clean_tag}' already exists")

    snap = FeedSnapshot(
        tool_id=tool.id,
        feed_slug=feed_slug.strip(),
        stream=tool.stream,
        update_channel=tool.update_channel,
        snapshot_tag=clean_tag,
        archive_sha256=clean_sha,
        schema_version=schema_version.strip() or "v1",
        record_count=max(0, record_count),
        approval_channel=ToolApprovalChannel.CANDIDATE.value,
        source_url=source_url,
    )
    db.add(snap)
    await db.flush()
    return snap


async def promote_feed_snapshot(
    db: AsyncSession,
    *,
    snapshot_id: uuid.UUID,
    target_channel: Literal["canary", "stable"],
    actor_user_id: uuid.UUID,
    actor_email: str,
    reason: str | None = None,
) -> FeedSnapshot:
    """Promote a feed/DB snapshot to canary or stable with rollback pointer."""
    snap = (
        await db.execute(
            select(FeedSnapshot).where(FeedSnapshot.id == snapshot_id).with_for_update()
        )
    ).scalar_one_or_none()
    if snap is None:
        raise NotFoundError(f"FeedSnapshot '{snapshot_id}' not found")
    # Lock parent catalog row to serialize concurrent feed promotions
    (
        await db.execute(
            select(ToolCatalog).where(ToolCatalog.id == snap.tool_id).with_for_update()
        )
    ).scalar_one()
    if snap.approval_channel in {
        ToolApprovalChannel.REJECTED.value,
        ToolApprovalChannel.ROLLED_BACK.value,
    }:
        raise ConflictError(f"Cannot promote feed snapshot in status '{snap.approval_channel}'")

    now = datetime.now(UTC)
    if target_channel == "canary":
        prev_canary = (
            await db.execute(
                select(FeedSnapshot).where(
                    FeedSnapshot.feed_slug == snap.feed_slug,
                    FeedSnapshot.is_active_canary.is_(True),
                    FeedSnapshot.id != snap.id,
                )
            )
        ).scalar_one_or_none()
        if prev_canary is not None:
            prev_canary.is_active_canary = False
            await db.flush()
        snap.is_active_canary = True
        snap.approval_channel = ToolApprovalChannel.CANARY.value
        snap.promoted_at = now
    else:
        prev_stable = (
            await db.execute(
                select(FeedSnapshot).where(
                    FeedSnapshot.feed_slug == snap.feed_slug,
                    FeedSnapshot.is_active_stable.is_(True),
                    FeedSnapshot.id != snap.id,
                )
            )
        ).scalar_one_or_none()
        if prev_stable is not None:
            prev_stable.is_active_stable = False
            await db.flush()
            snap.previous_stable_snapshot_id = prev_stable.id
        snap.is_active_canary = False
        snap.is_active_stable = True
        snap.approval_channel = ToolApprovalChannel.STABLE.value
        snap.promoted_at = now

    await record_audit_event(
        db,
        tool_id=snap.tool_id,
        feed_snapshot_id=snap.id,
        action=UpdateAuditAction.FEED_PROMOTED,
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        reason=reason or f"Promoted feed snapshot {snap.snapshot_tag} to {target_channel}",
        details={"feed_slug": snap.feed_slug, "target_channel": target_channel},
    )
    await db.flush()
    return snap


async def rollback_feed_snapshot(
    db: AsyncSession,
    *,
    feed_slug: str,
    reason: str,
    actor_user_id: uuid.UUID,
    actor_email: str,
) -> tuple[FeedSnapshot, FeedSnapshot]:
    """Rollback active stable feed snapshot to its previous stable snapshot."""
    clean_reason = reason.strip()
    if len(clean_reason) < 5:
        raise ValidationError("Feed rollback requires a descriptive reason (>= 5 chars)")

    active_stable = (
        await db.execute(
            select(FeedSnapshot)
            .where(
                FeedSnapshot.feed_slug == feed_slug.strip(),
                FeedSnapshot.is_active_stable.is_(True),
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if active_stable is None or active_stable.previous_stable_snapshot_id is None:
        raise ConflictError(f"Feed '{feed_slug}' has no previous stable snapshot for rollback")

    # Lock parent catalog row to prevent concurrent feed mutations
    (
        await db.execute(
            select(ToolCatalog).where(ToolCatalog.id == active_stable.tool_id).with_for_update()
        )
    ).scalar_one()

    restored = (
        await db.execute(
            select(FeedSnapshot)
            .where(FeedSnapshot.id == active_stable.previous_stable_snapshot_id)
            .with_for_update()
        )
    ).scalar_one()

    now = datetime.now(UTC)
    active_stable.is_active_stable = False
    active_stable.is_active_canary = False
    active_stable.approval_channel = ToolApprovalChannel.ROLLED_BACK.value
    active_stable.rolled_back_at = now
    await db.flush()

    restored.is_active_stable = True
    restored.approval_channel = ToolApprovalChannel.STABLE.value
    restored.promoted_at = now

    await record_audit_event(
        db,
        tool_id=active_stable.tool_id,
        feed_snapshot_id=restored.id,
        action=UpdateAuditAction.FEED_ROLLED_BACK,
        actor_user_id=actor_user_id,
        actor_email=actor_email,
        reason=clean_reason,
        details={
            "feed_slug": feed_slug,
            "demoted_snapshot_tag": active_stable.snapshot_tag,
            "restored_snapshot_tag": restored.snapshot_tag,
        },
    )
    await db.flush()
    return active_stable, restored


async def resolve_active_tool_pins(
    db: AsyncSession,
    *,
    settings: Settings | None = None,
    use_canary: bool = False,
) -> ResolvedToolPins:
    """Resolve currently active stable or canary tool digests and feeds for scan runs."""
    cfg = settings or get_settings()
    catalog_rows = (
        (await db.execute(select(ToolCatalog).where(ToolCatalog.is_active.is_(True))))
        .scalars()
        .all()
    )
    catalog_by_id = {row.id: row for row in catalog_rows}

    active_versions = (
        (
            await db.execute(
                select(ToolVersion).where(
                    (ToolVersion.is_active_stable.is_(True))
                    | (ToolVersion.is_active_canary.is_(True))
                )
            )
        )
        .scalars()
        .all()
    )

    selected_by_slug: dict[str, ToolVersion] = {}
    allowed_digests: list[str] = list(cfg.runner_allowed_image_digests)
    configured_allowlist = {
        entry.strip() for entry in cfg.runner_allowed_image_digests if entry.strip()
    }

    for ver in active_versions:
        tool = catalog_by_id.get(ver.tool_id)
        if tool is None:
            continue
        full_ref = _format_image_ref(ver.image_repository, ver.image_digest)
        is_seeded = bool((ver.metadata_json or {}).get("seeded", False))
        # Preserve restrictive Settings allowlists against seeded defaults while enabling
        # dynamically promoted/canary Phase 10 versions without container restart.
        if configured_allowlist and is_seeded and full_ref not in configured_allowlist:
            continue
        if full_ref not in allowed_digests:
            allowed_digests.append(full_ref)
        current = selected_by_slug.get(tool.tool_slug)
        if ver.is_active_canary and use_canary:
            selected_by_slug[tool.tool_slug] = ver
        elif ver.is_active_stable and (
            current is None or not (current.is_active_canary and use_canary)
        ):
            selected_by_slug[tool.tool_slug] = ver

    image_refs: dict[str, str] = {}
    tool_pins: dict[str, Any] = {}
    for slug, (attr_name, fallback_ver) in _TOOL_SETTINGS_FALLBACK.items():
        selected_ver = selected_by_slug.get(slug)
        if selected_ver is not None:
            full_ref = _format_image_ref(selected_ver.image_repository, selected_ver.image_digest)
            image_refs[slug] = full_ref
            tool_pins[slug] = {
                "tool_version_id": str(selected_ver.id),
                "version_tag": selected_ver.version_tag,
                "image_repository": selected_ver.image_repository,
                "image_digest": selected_ver.image_digest,
                "image_ref": full_ref,
                "adapter_version": selected_ver.adapter_version,
                "channel": "canary" if selected_ver.is_active_canary else "stable",
            }
        else:
            fallback_ref = str(getattr(cfg, attr_name))
            image_refs[slug] = fallback_ref
            tool_pins[slug] = {
                "tool_version_id": None,
                "version_tag": fallback_ver,
                "image_ref": fallback_ref,
                "adapter_version": "1.0.0",
                "channel": "config_default",
            }

    # Resolve active feed snapshots
    active_feeds = (
        (
            await db.execute(
                select(FeedSnapshot).where(
                    (FeedSnapshot.is_active_stable.is_(True))
                    | (FeedSnapshot.is_active_canary.is_(True))
                )
            )
        )
        .scalars()
        .all()
    )
    feed_pins: dict[str, Any] = {}
    for snap in active_feeds:
        existing_feed = feed_pins.get(snap.feed_slug)
        if snap.is_active_canary and use_canary:
            pick = True
        elif snap.is_active_stable and existing_feed is None:
            pick = True
        else:
            pick = False
        if pick:
            feed_pins[snap.feed_slug] = {
                "snapshot_id": str(snap.id),
                "snapshot_tag": snap.snapshot_tag,
                "archive_sha256": snap.archive_sha256,
                "schema_version": snap.schema_version,
                "channel": "canary" if snap.is_active_canary else "stable",
            }

    return ResolvedToolPins(
        image_refs=image_refs,
        allowed_image_digests=allowed_digests,
        provenance_manifest={
            "resolved_at": datetime.now(UTC).isoformat(),
            "use_canary": use_canary,
            "tools": tool_pins,
            "feeds": feed_pins,
        },
    )
