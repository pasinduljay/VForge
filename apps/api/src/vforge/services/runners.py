"""Phase 4 runner pools, mTLS auth, artifact encryption, and execution lifecycle."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import logging
import os
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from vforge_scanners import redact_text_secrets, scrub_finding_dict
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.auth.rbac import Permission, assert_permission
from vforge.config import Settings, get_settings
from vforge.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from vforge.models.domain import Authorization, AuthProfile
from vforge.models.enums import (
    AuditOutcome,
    AuthorizationStatus,
    Role,
    RunnerEventSeverity,
    RunnerJobStatus,
    RunnerStatus,
    ScanRunStatus,
    ScanStageStatus,
    TargetLeaseStatus,
    ToolExecutionStatus,
)
from vforge.models.orchestration import (
    RunnerJob,
    ScanRun,
    ScanStage,
    ScanTargetLease,
    TargetHealthProbe,
)
from vforge.models.runner import (
    Artifact,
    Runner,
    RunnerEvent,
    RunnerHeartbeat,
    RunnerPool,
    ToolExecution,
)
from vforge.models.scanner import SbomDocument, SourceSnapshot
from vforge.orchestration.service import (
    advance_run_after_stage_complete,
    fail_stage_and_run,
    finalize_run_cancellation,
)
from vforge.orchestration.state_machine import (
    RUN_TERMINAL_STATUSES,
    validate_job_transition,
    validate_run_transition,
    validate_stage_transition,
)
from vforge.schemas import (
    RunnerArtifactUploadRequest,
    RunnerEventCreate,
    RunnerHeartbeatOut,
    RunnerHeartbeatRequest,
    RunnerJobClaimOut,
    RunnerJobClaimRequest,
    RunnerJobCompleteOut,
    RunnerJobCompleteRequest,
    RunnerPoolCreate,
    RunnerRegisterRequest,
    TargetHealthProbeCreate,
)
from vforge.security.envelope import (
    build_artifact_aad,
    decrypt_artifact_with_keyring,
    encrypt_artifact_bytes,
    resolve_kek,
    resolve_keyring,
)
from vforge.security.mtls import RunnerCertClaims, extract_cert_sha256_and_subject
from vforge.security.signing import SnapshotSigner
from vforge.security.validators import redact_metadata
from vforge.services.audit import record_audit_event
from vforge.services.findings import (
    normalize_and_persist_execution_findings,
    persist_syft_sbom_documents,
)
from vforge.services.source_snapshots import read_decrypted_source_snapshot_bytes

logger = logging.getLogger("vforge.services.runners")
_SECURITY_EVENT_TYPES = frozenset(
    {"cleanup_failed", "egress_blocked", "manifest_rejected", "runner_revoked"}
)


def _artifact_file_path(artifact_root: str, storage_key: str) -> Path:
    root = Path(artifact_root).resolve()
    candidate = (root / storage_key).resolve()
    if not candidate.is_relative_to(root):
        raise ValidationError("Invalid artifact storage path")
    return candidate


async def create_runner_pool(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    payload: RunnerPoolCreate,
    correlation_id: str | None,
) -> RunnerPool:
    assert_permission(actor_role, Permission.RUNNER_MANAGE)
    existing = (
        await db.execute(
            select(RunnerPool).where(
                RunnerPool.organization_id == org_id,
                RunnerPool.slug == payload.slug,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        raise ConflictError(f"Runner pool slug '{payload.slug}' already exists in organization")

    pool = RunnerPool(
        id=uuid.uuid4(),
        organization_id=org_id,
        name=payload.name.strip(),
        slug=payload.slug.strip(),
        pool_type=payload.pool_type.value,
        max_concurrent_jobs=payload.max_concurrent_jobs,
        active=True,
    )
    db.add(pool)
    await db.flush()
    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        action="runner_pool.created",
        resource_type="runner_pool",
        resource_id=pool.id,
        outcome=AuditOutcome.SUCCESS,
        metadata={"slug": pool.slug, "pool_type": pool.pool_type},
    )
    return pool


async def list_runner_pools(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_role: Role,
) -> list[RunnerPool]:
    assert_permission(actor_role, Permission.RUNNER_READ)
    rows = (
        (
            await db.execute(
                select(RunnerPool)
                .where(RunnerPool.organization_id == org_id)
                .order_by(RunnerPool.created_at.asc())
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


async def register_runner(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    payload: RunnerRegisterRequest,
    correlation_id: str | None,
) -> Runner:
    assert_permission(actor_role, Permission.RUNNER_MANAGE)
    pool = (
        await db.execute(
            select(RunnerPool).where(
                RunnerPool.id == payload.pool_id,
                RunnerPool.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if pool is None:
        raise NotFoundError("Runner pool not found")
    if not pool.active:
        raise ConflictError("Cannot register runner in inactive pool")

    try:
        cert_sha256, cert_subject, cert_expires_at, spiffe_uri = extract_cert_sha256_and_subject(
            payload.certificate_pem
        )
    except ValueError as exc:
        raise ValidationError(str(exc)) from exc

    # Extract UUIDs cleanly from verified SPIFFE URI
    parts = spiffe_uri.split("/")
    cert_org_id = uuid.UUID(parts[4])
    cert_runner_id = uuid.UUID(parts[6])
    if cert_org_id != org_id:
        raise ForbiddenError("Runner certificate SPIFFE organization ID does not match tenant")

    dup = (
        await db.execute(
            select(Runner).where(
                (Runner.id == cert_runner_id) | (Runner.cert_sha256 == cert_sha256)
            )
        )
    ).scalar_one_or_none()
    if dup is not None:
        raise ConflictError("Runner ID or certificate fingerprint is already registered")

    runner = Runner(
        id=cert_runner_id,
        organization_id=org_id,
        pool_id=pool.id,
        name=payload.name.strip(),
        runner_identity=spiffe_uri,
        cert_sha256=cert_sha256,
        cert_subject=cert_subject,
        cert_expires_at=cert_expires_at,
        status=RunnerStatus.ACTIVE.value,
        version=payload.version.strip(),
        capabilities_json=redact_metadata(payload.capabilities),
    )
    db.add(runner)
    await db.flush()

    db.add(
        RunnerEvent(
            id=uuid.uuid4(),
            organization_id=org_id,
            runner_id=runner.id,
            event_type="runner_registered",
            severity=RunnerEventSeverity.INFO.value,
            details_json={"pool_id": str(pool.id), "cert_sha256": cert_sha256},
        )
    )
    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        action="runner.registered",
        resource_type="runner",
        resource_id=runner.id,
        outcome=AuditOutcome.SUCCESS,
        metadata={"pool_id": str(pool.id), "runner_identity": spiffe_uri},
    )
    return runner


async def list_runners(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_role: Role,
) -> list[Runner]:
    assert_permission(actor_role, Permission.RUNNER_READ)
    rows = (
        (
            await db.execute(
                select(Runner)
                .where(Runner.organization_id == org_id)
                .order_by(Runner.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


async def list_runner_events(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_role: Role,
    limit: int = 100,
) -> list[RunnerEvent]:
    assert_permission(actor_role, Permission.RUNNER_READ)
    rows = (
        (
            await db.execute(
                select(RunnerEvent)
                .where(RunnerEvent.organization_id == org_id)
                .order_by(RunnerEvent.created_at.desc())
                .limit(max(1, min(limit, 500)))
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


async def revoke_runner(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    runner_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    reason: str,
    correlation_id: str | None,
) -> Runner:
    assert_permission(actor_role, Permission.RUNNER_MANAGE)
    now = datetime.now(UTC)
    runner = (
        await db.execute(
            select(Runner)
            .where(Runner.id == runner_id, Runner.organization_id == org_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if runner is None:
        raise NotFoundError("Runner not found")

    if runner.status != RunnerStatus.REVOKED.value:
        runner.status = RunnerStatus.REVOKED.value
        runner.revoked_by = actor_id
        runner.revoked_at = now
        runner.revocation_reason = reason.strip()

        await db.execute(
            update(RunnerJob)
            .where(
                RunnerJob.organization_id == org_id,
                RunnerJob.claimed_by_runner_id == runner.id,
                RunnerJob.status == RunnerJobStatus.RUNNING.value,
            )
            .values(cancel_requested_at=now)
        )
        db.add(
            RunnerEvent(
                id=uuid.uuid4(),
                organization_id=org_id,
                runner_id=runner.id,
                event_type="runner_revoked",
                severity=RunnerEventSeverity.SECURITY.value,
                details_json={"reason": runner.revocation_reason},
            )
        )
        await record_audit_event(
            db,
            organization_id=org_id,
            actor_id=actor_id,
            correlation_id=correlation_id,
            action="runner.revoked",
            resource_type="runner",
            resource_id=runner.id,
            outcome=AuditOutcome.SUCCESS,
            metadata={"reason": runner.revocation_reason},
        )
    return runner


async def authenticate_mtls_runner(
    db: AsyncSession,
    *,
    claims: RunnerCertClaims,
) -> Runner:
    """Authenticate an active runner against CA-extracted SPIFFE SAN & pinned cert SHA-256."""
    now = datetime.now(UTC)
    runner = (
        await db.execute(
            select(Runner).where(
                Runner.id == claims.runner_id,
                Runner.organization_id == claims.organization_id,
            )
        )
    ).scalar_one_or_none()
    if runner is None:
        raise ForbiddenError("Unknown runner certificate identity")

    if not hmac.compare_digest(runner.cert_sha256, claims.cert_sha256):
        raise ForbiddenError("Runner certificate fingerprint mismatch")

    if runner.runner_identity != claims.runner_identity:
        raise ForbiddenError("Runner SPIFFE identity mismatch")

    if runner.status != RunnerStatus.ACTIVE.value:
        raise ForbiddenError(f"Runner is not active (status={runner.status})")

    if runner.cert_expires_at <= now:
        raise ForbiddenError("Runner certificate registration has expired")

    pool = (
        await db.execute(
            select(RunnerPool).where(
                RunnerPool.id == runner.pool_id,
                RunnerPool.organization_id == runner.organization_id,
            )
        )
    ).scalar_one_or_none()
    if pool is None or not pool.active:
        raise ForbiddenError("Runner pool is inactive")

    return runner


async def claim_next_runner_job(
    db: AsyncSession,
    *,
    runner: Runner,
    payload: RunnerJobClaimRequest,
    settings: Settings | None = None,
) -> RunnerJobClaimOut:
    """Atomically claim one due signed RunnerJob matching this runner's tenant and pool."""
    cfg = settings or get_settings()
    now = datetime.now(UTC)
    runner.last_heartbeat_at = now
    if payload.runner_version:
        runner.version = payload.runner_version.strip()

    target_pool_id = payload.pool_id or runner.pool_id
    if target_pool_id != runner.pool_id:
        raise ForbiddenError("Runner cannot claim jobs from a different pool")

    pool = (
        await db.execute(
            select(RunnerPool)
            .where(
                RunnerPool.id == runner.pool_id,
                RunnerPool.organization_id == runner.organization_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if pool is None or not pool.active:
        return RunnerJobClaimOut(claimed=False)

    running_in_pool = int(
        (
            await db.execute(
                select(func.count(RunnerJob.id)).where(
                    RunnerJob.organization_id == runner.organization_id,
                    RunnerJob.target_pool_id == runner.pool_id,
                    RunnerJob.status == RunnerJobStatus.RUNNING.value,
                )
            )
        ).scalar_one()
    )
    if running_in_pool >= pool.max_concurrent_jobs:
        return RunnerJobClaimOut(claimed=False)

    job = (
        (
            await db.execute(
                select(RunnerJob)
                .where(
                    RunnerJob.organization_id == runner.organization_id,
                    RunnerJob.target_pool_id == runner.pool_id,
                    RunnerJob.execution_mode == "runner",
                    RunnerJob.status == RunnerJobStatus.LEASED.value,
                    RunnerJob.claimed_by_runner_id.is_(None),
                    RunnerJob.cancel_requested_at.is_(None),
                    RunnerJob.manifest_expires_at > now,
                )
                .order_by(RunnerJob.created_at.asc())
                .limit(1)
                .with_for_update(skip_locked=True)
            )
        )
        .scalars()
        .first()
    )
    if job is None:
        return RunnerJobClaimOut(claimed=False)

    run = (
        await db.execute(
            select(ScanRun)
            .where(
                ScanRun.id == job.scan_run_id,
                ScanRun.organization_id == runner.organization_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    stage = (
        await db.execute(
            select(ScanStage)
            .where(
                ScanStage.id == job.scan_stage_id,
                ScanStage.organization_id == runner.organization_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if (
        run is None
        or stage is None
        or run.status in RUN_TERMINAL_STATUSES
        or run.status == ScanRunStatus.CANCELLING.value
    ):
        return RunnerJobClaimOut(claimed=False)

    auth = (
        await db.execute(
            select(Authorization).where(
                Authorization.id == run.authorization_id,
                Authorization.organization_id == runner.organization_id,
            )
        )
    ).scalar_one_or_none()
    if auth is None or auth.status != AuthorizationStatus.APPROVED.value or auth.expires_at <= now:
        job.status = validate_job_transition(job.status, RunnerJobStatus.FAILED.value)
        job.last_error_code = "authorization_invalid"
        job.last_error_message = "Authorization expired or revoked before runner claim"
        job.completed_at = now
        await fail_stage_and_run(
            db,
            org_id=runner.organization_id,
            run=run,
            stage=stage,
            now=now,
            error_summary="Authorization became invalid prior to runner claim",
        )
        return RunnerJobClaimOut(claimed=False)

    lease_window = min(max(job.timeout_seconds, 60), 900)
    job.claimed_by_runner_id = runner.id
    job.claimed_at = now
    job.lease_owner = f"runner:{runner.id}"
    job.heartbeat_at = now
    job.lease_expires_at = now + timedelta(seconds=lease_window)
    job.started_at = job.started_at or now
    job.status = validate_job_transition(job.status, RunnerJobStatus.RUNNING.value)

    await db.execute(
        update(ScanTargetLease)
        .where(
            ScanTargetLease.organization_id == runner.organization_id,
            ScanTargetLease.runner_job_id == job.id,
            ScanTargetLease.status == TargetLeaseStatus.ACTIVE.value,
        )
        .values(
            lease_owner=f"runner:{runner.id}",
            heartbeat_at=now,
            expires_at=job.lease_expires_at,
        )
    )

    if stage.status in {ScanStageStatus.PENDING.value, ScanStageStatus.QUEUED.value}:
        stage.status = validate_stage_transition(stage.status, ScanStageStatus.RUNNING.value)
        stage.started_at = stage.started_at or now
    if run.status in {ScanRunStatus.QUEUED.value, ScanRunStatus.PROVISIONING.value}:
        run.status = validate_run_transition(run.status, ScanRunStatus.RUNNING.value)
        run.started_at = run.started_at or now

    execution_id = uuid.uuid4()
    execution = ToolExecution(
        id=execution_id,
        organization_id=runner.organization_id,
        runner_job_id=job.id,
        runner_id=runner.id,
        tool_id=job.tool_id,
        tool_version=job.tool_version,
        image_digest=job.image_digest,
        adapter_version=job.adapter_version,
        config_hash=job.manifest_sha256,
        status=ToolExecutionStatus.RUNNING.value,
        started_at=now,
    )
    db.add(execution)
    db.add(
        RunnerEvent(
            id=uuid.uuid4(),
            organization_id=runner.organization_id,
            runner_id=runner.id,
            runner_job_id=job.id,
            event_type="job_claimed",
            severity=RunnerEventSeverity.INFO.value,
            details_json={
                "execution_id": str(execution_id),
                "attempt_number": job.attempt_count,
                "active_containers": payload.active_containers,
            },
        )
    )

    signed_manifest = dict((job.job_configuration or {}).get("signed_manifest") or {})
    signer = SnapshotSigner.from_settings(cfg)
    keyring_json = signer.export_public_keyring_json()

    from vforge.lifecycle.pipeline import resolve_active_tool_pins

    resolved_pins = await resolve_active_tool_pins(db, settings=cfg, use_canary=False)
    allowlist_payload = {"allowed_image_digests": resolved_pins.allowed_image_digests}
    allowlist_bundle = signer.sign_payload(allowlist_payload)
    return RunnerJobClaimOut(
        claimed=True,
        job_id=job.id,
        scan_run_id=run.id,
        execution_id=execution_id,
        attempt_number=job.attempt_count,
        manifest=signed_manifest,
        manifest_sha256=job.manifest_sha256,
        manifest_signature=job.manifest_signature,
        manifest_signing_key_id=job.manifest_signing_key_id,
        public_keyring_json=keyring_json,
        signed_allowlist_payload=allowlist_payload,
        allowlist_sha256=allowlist_bundle.payload_sha256,
        allowlist_signature=allowlist_bundle.signature,
        allowlist_signing_key_id=allowlist_bundle.signing_key_id,
    )


async def record_runner_heartbeat(
    db: AsyncSession,
    *,
    runner: Runner,
    job_id: uuid.UUID,
    payload: RunnerHeartbeatRequest,
) -> RunnerHeartbeatOut:
    """Extend active job & target lease TTLs and signal pending cancellation."""
    now = datetime.now(UTC)
    runner.last_heartbeat_at = now
    job = (
        await db.execute(
            select(RunnerJob)
            .where(
                RunnerJob.id == job_id,
                RunnerJob.organization_id == runner.organization_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if job is None:
        raise NotFoundError("Runner job not found")
    if job.claimed_by_runner_id != runner.id or job.attempt_count != payload.attempt_number:
        raise ForbiddenError("Runner does not own active lease for this job attempt")

    run = (
        await db.execute(
            select(ScanRun).where(
                ScanRun.id == job.scan_run_id,
                ScanRun.organization_id == runner.organization_id,
            )
        )
    ).scalar_one_or_none()

    cancel_requested = (
        job.cancel_requested_at is not None
        or (run is not None and run.status == ScanRunStatus.CANCELLING.value)
        or runner.status != RunnerStatus.ACTIVE.value
    )
    if job.status == RunnerJobStatus.RUNNING.value and not cancel_requested:
        lease_window = min(max(job.timeout_seconds, 60), 900)
        new_expiry = now + timedelta(seconds=lease_window)
        job.heartbeat_at = now
        job.lease_expires_at = new_expiry
        await db.execute(
            update(ScanTargetLease)
            .where(
                ScanTargetLease.organization_id == runner.organization_id,
                ScanTargetLease.runner_job_id == job.id,
                ScanTargetLease.status == TargetLeaseStatus.ACTIVE.value,
            )
            .values(heartbeat_at=now, expires_at=new_expiry)
        )

    db.add(
        RunnerHeartbeat(
            id=uuid.uuid4(),
            organization_id=runner.organization_id,
            runner_id=runner.id,
            runner_job_id=job.id,
            status=payload.status,
            cpu_percent=payload.cpu_percent,
            memory_mb=payload.memory_mb,
            active_containers=payload.active_containers,
            metrics_json=redact_metadata(payload.metrics),
            recorded_at=now,
        )
    )
    return RunnerHeartbeatOut(
        acknowledged=True,
        cancel_requested=cancel_requested,
        runner_status=RunnerStatus(runner.status),
        lease_expires_at=job.lease_expires_at,
    )


async def record_runner_event(
    db: AsyncSession,
    *,
    runner: Runner,
    job_id: uuid.UUID,
    payload: RunnerEventCreate,
) -> RunnerEvent:
    """Persist an append-only runner event; cleanup & egress failures force security severity."""
    job = (
        await db.execute(
            select(RunnerJob).where(
                RunnerJob.id == job_id,
                RunnerJob.organization_id == runner.organization_id,
            )
        )
    ).scalar_one_or_none()
    if job is None:
        raise NotFoundError("Runner job not found")
    if job.claimed_by_runner_id != runner.id:
        raise ForbiddenError("Runner does not own this job")

    severity = (
        RunnerEventSeverity.SECURITY.value
        if payload.event_type in _SECURITY_EVENT_TYPES
        else payload.severity.value
    )
    event = RunnerEvent(
        id=uuid.uuid4(),
        organization_id=runner.organization_id,
        runner_id=runner.id,
        runner_job_id=job.id,
        event_type=payload.event_type.strip(),
        severity=severity,
        details_json=redact_metadata(payload.details),
    )
    db.add(event)
    await db.flush()
    return event


async def upload_runner_artifact(
    db: AsyncSession,
    *,
    runner: Runner,
    job_id: uuid.UUID,
    payload: RunnerArtifactUploadRequest,
    settings: Settings | None = None,
) -> Artifact:
    """Verify plaintext SHA-256, envelope-encrypt with AES-256-GCM, and store artifact."""
    cfg = settings or get_settings()
    scan_run_id_ref = (
        await db.execute(
            select(RunnerJob.scan_run_id).where(
                RunnerJob.id == job_id,
                RunnerJob.organization_id == runner.organization_id,
            )
        )
    ).scalar_one_or_none()
    if scan_run_id_ref is None:
        raise NotFoundError("Runner job not found")

    # Canonical lock order: ScanRun (KEY SHARE before FK check) -> RunnerJob
    await db.execute(
        select(ScanRun.id)
        .where(ScanRun.id == scan_run_id_ref, ScanRun.organization_id == runner.organization_id)
        .with_for_update(key_share=True)
    )
    job = (
        await db.execute(
            select(RunnerJob)
            .where(
                RunnerJob.id == job_id,
                RunnerJob.organization_id == runner.organization_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if job is None:
        raise NotFoundError("Runner job not found")
    if (
        job.claimed_by_runner_id != runner.id
        or job.attempt_count != payload.attempt_number
        or job.status != RunnerJobStatus.RUNNING.value
    ):
        raise ForbiddenError("Runner cannot upload artifacts for inactive or unowned job")

    execution = (
        await db.execute(
            select(ToolExecution).where(
                ToolExecution.id == payload.execution_id,
                ToolExecution.organization_id == runner.organization_id,
                ToolExecution.runner_job_id == job.id,
                ToolExecution.runner_id == runner.id,
            )
        )
    ).scalar_one_or_none()
    if execution is None:
        raise NotFoundError("Tool execution record not found for runner job")

    try:
        plaintext = base64.b64decode(payload.content_b64.encode("ascii"), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValidationError("Invalid base64 artifact payload") from exc

    if len(plaintext) > cfg.runner_max_artifact_bytes:
        raise ValidationError("Artifact exceeds maximum permitted size")

    actual_sha256 = hashlib.sha256(plaintext).hexdigest()
    if not hmac.compare_digest(actual_sha256, payload.sha256.lower()):
        raise ValidationError("Uploaded artifact SHA-256 does not match declared digest")

    kek_id, kek_bytes = resolve_kek(cfg)
    aad = build_artifact_aad(
        organization_id=str(runner.organization_id),
        scan_run_id=str(job.scan_run_id),
        runner_job_id=str(job.id),
        plaintext_sha256=actual_sha256,
    )
    encrypted = encrypt_artifact_bytes(
        plaintext=plaintext,
        kek_id=kek_id,
        kek_bytes=kek_bytes,
        aad=aad,
    )

    artifact_id = uuid.uuid4()
    storage_key = f"{runner.organization_id}/{job.scan_run_id}/{artifact_id}.enc"
    target_path = _artifact_file_path(cfg.artifact_root, storage_key)
    target_path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = target_path.with_suffix(".tmp")
    tmp_path.write_bytes(encrypted.ciphertext)
    os.replace(tmp_path, target_path)

    artifact = Artifact(
        id=artifact_id,
        organization_id=runner.organization_id,
        scan_run_id=job.scan_run_id,
        runner_job_id=job.id,
        execution_id=execution.id,
        artifact_type=payload.artifact_type.value,
        storage_key=storage_key,
        sha256=encrypted.plaintext_sha256,
        ciphertext_sha256=encrypted.ciphertext_sha256,
        encryption_algorithm=encrypted.encryption_algorithm,
        encryption_key_id=encrypted.encryption_key_id,
        wrapped_dek_b64=encrypted.wrapped_dek_b64,
        nonce_b64=encrypted.nonce_b64,
        aad_b64=encrypted.aad_b64,
        content_type=payload.content_type.strip(),
        size_bytes=len(plaintext),
    )
    db.add(artifact)
    await db.flush()
    db.add(
        RunnerEvent(
            id=uuid.uuid4(),
            organization_id=runner.organization_id,
            runner_id=runner.id,
            runner_job_id=job.id,
            event_type="artifact_uploaded",
            severity=RunnerEventSeverity.INFO.value,
            details_json={
                "artifact_id": str(artifact.id),
                "sha256": artifact.sha256,
                "size_bytes": artifact.size_bytes,
            },
        )
    )
    return artifact


async def get_runner_job_source_snapshot(
    db: AsyncSession,
    *,
    runner: Runner,
    job_id: uuid.UUID,
    settings: Settings | None = None,
) -> tuple[SourceSnapshot, bytes]:
    """Stream decrypted source snapshot `.tar.gz` bytes exclusively to the owning active runner."""
    cfg = settings or get_settings()
    job = (
        await db.execute(
            select(RunnerJob).where(
                RunnerJob.id == job_id,
                RunnerJob.organization_id == runner.organization_id,
            )
        )
    ).scalar_one_or_none()
    if job is None:
        raise NotFoundError("Runner job not found")
    if job.claimed_by_runner_id != runner.id or job.status != RunnerJobStatus.RUNNING.value:
        raise ForbiddenError("Runner does not hold active running lease for source snapshot")

    run = (
        await db.execute(
            select(ScanRun).where(
                ScanRun.id == job.scan_run_id,
                ScanRun.organization_id == runner.organization_id,
            )
        )
    ).scalar_one_or_none()
    if run is None or run.source_snapshot_id is None:
        raise NotFoundError("Runner job does not have an attached source snapshot")

    snap = (
        await db.execute(
            select(SourceSnapshot).where(
                SourceSnapshot.id == run.source_snapshot_id,
                SourceSnapshot.organization_id == runner.organization_id,
            )
        )
    ).scalar_one_or_none()
    if snap is None:
        raise NotFoundError("Source snapshot not found")

    archive_bytes = await read_decrypted_source_snapshot_bytes(snap, settings=cfg)
    return snap, archive_bytes


async def get_runner_job_sbom_input(
    db: AsyncSession,
    *,
    runner: Runner,
    job_id: uuid.UUID,
    settings: Settings | None = None,
) -> tuple[SbomDocument, bytes]:
    """Stream decrypted CycloneDX JSON SBOM bytes exclusively to the owning active SCA runner."""
    cfg = settings or get_settings()
    job = (
        await db.execute(
            select(RunnerJob).where(
                RunnerJob.id == job_id,
                RunnerJob.organization_id == runner.organization_id,
            )
        )
    ).scalar_one_or_none()
    if job is None:
        raise NotFoundError("Runner job not found")
    if job.claimed_by_runner_id != runner.id or job.status != RunnerJobStatus.RUNNING.value:
        raise ForbiddenError("Runner does not hold active running lease for SBOM input")
    if job.tool_id != "grype":
        raise ValidationError("SBOM input endpoint is restricted to SCA jobs")

    sbom_doc = (
        await db.execute(
            select(SbomDocument)
            .where(
                SbomDocument.organization_id == runner.organization_id,
                SbomDocument.scan_run_id == job.scan_run_id,
                SbomDocument.sbom_format == "cyclonedx-json",
            )
            .order_by(SbomDocument.created_at.desc())
            .limit(1)
        )
    ).scalar_one_or_none()
    if sbom_doc is None:
        raise NotFoundError("CycloneDX SBOM document not found for this scan run")

    artifact = (
        await db.execute(
            select(Artifact).where(
                Artifact.id == sbom_doc.artifact_id,
                Artifact.organization_id == runner.organization_id,
            )
        )
    ).scalar_one_or_none()
    if artifact is None:
        raise NotFoundError("Encrypted SBOM artifact record not found")

    blob_path = _artifact_file_path(cfg.artifact_root, artifact.storage_key)
    if not blob_path.exists():
        raise NotFoundError("Encrypted SBOM artifact payload missing from storage")

    keyring = resolve_keyring(cfg)
    sbom_bytes = decrypt_artifact_with_keyring(
        ciphertext=blob_path.read_bytes(),
        expected_plaintext_sha256=artifact.sha256,
        expected_ciphertext_sha256=artifact.ciphertext_sha256,
        encryption_key_id=artifact.encryption_key_id or keyring.active_kek_id,
        keyring=keyring.keys,
        wrapped_dek_b64=artifact.wrapped_dek_b64,
        nonce_b64=artifact.nonce_b64,
        aad_b64=artifact.aad_b64,
    )
    return sbom_doc, sbom_bytes


async def complete_runner_job(
    db: AsyncSession,
    *,
    runner: Runner,
    job_id: uuid.UUID,
    payload: RunnerJobCompleteRequest,
    settings: Settings | None = None,
) -> RunnerJobCompleteOut:
    """Finalize tool execution, release leases cleanly, and advance orchestration state."""
    now = datetime.now(UTC)
    runner.last_heartbeat_at = now

    ref = (
        await db.execute(
            select(RunnerJob.scan_run_id, RunnerJob.scan_stage_id).where(
                RunnerJob.id == job_id,
                RunnerJob.organization_id == runner.organization_id,
            )
        )
    ).first()
    if ref is None:
        raise NotFoundError("Runner job not found")
    scan_run_id_ref, stage_id_ref = ref

    # Canonical lock order: ScanRun -> ScanStage -> RunnerJob -> ToolExecution
    run = (
        await db.execute(
            select(ScanRun)
            .where(ScanRun.id == scan_run_id_ref, ScanRun.organization_id == runner.organization_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    stage = (
        await db.execute(
            select(ScanStage)
            .where(
                ScanStage.id == stage_id_ref,
                ScanStage.organization_id == runner.organization_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    job = (
        await db.execute(
            select(RunnerJob)
            .where(RunnerJob.id == job_id, RunnerJob.organization_id == runner.organization_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if run is None or stage is None or job is None:
        raise NotFoundError("Orchestration entities not found")

    if (
        job.claimed_by_runner_id != runner.id
        or job.attempt_count != payload.attempt_number
        or job.status != RunnerJobStatus.RUNNING.value
    ):
        raise ConflictError("Runner does not hold active running lease for this job")

    execution = (
        await db.execute(
            select(ToolExecution)
            .where(
                ToolExecution.id == payload.execution_id,
                ToolExecution.organization_id == runner.organization_id,
                ToolExecution.runner_job_id == job.id,
                ToolExecution.runner_id == runner.id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if execution is None:
        raise NotFoundError("Tool execution record not found")

    await db.execute(
        update(ScanTargetLease)
        .where(
            ScanTargetLease.organization_id == runner.organization_id,
            ScanTargetLease.runner_job_id == job.id,
            ScanTargetLease.status == TargetLeaseStatus.ACTIVE.value,
        )
        .values(
            status=(
                TargetLeaseStatus.REVOKED.value
                if payload.status == "cancelled" or run.status == ScanRunStatus.CANCELLING.value
                else TargetLeaseStatus.RELEASED.value
            ),
            released_at=now,
        )
    )

    execution.exit_code = payload.exit_code
    execution.completed_at = now
    execution.execution_metrics = redact_metadata(payload.metrics)

    if run.status == ScanRunStatus.CANCELLING.value or payload.status == "cancelled":
        execution.status = ToolExecutionStatus.CANCELLED.value
        job.status = validate_job_transition(job.status, RunnerJobStatus.CANCELLED.value)
        job.completed_at = now
        job.lease_owner = None
        job.lease_expires_at = None
        job.execution_count += 1
        await finalize_run_cancellation(db, run=run, org_id=runner.organization_id, now=now)
    elif payload.status == "completed":
        try:
            async with db.begin_nested():
                sbom_docs = await persist_syft_sbom_documents(
                    db,
                    run=run,
                    job=job,
                    execution=execution,
                    settings=settings,
                )
                persisted_findings = await normalize_and_persist_execution_findings(
                    db,
                    run=run,
                    job=job,
                    execution=execution,
                    now=now,
                    settings=settings,
                )
        except (ValueError, ValidationError) as exc:
            err_msg = (redact_text_secrets(str(exc)) or "Missing or invalid tool output")[:500]
            execution.status = ToolExecutionStatus.FAILED.value
            job.status = validate_job_transition(job.status, RunnerJobStatus.FAILED.value)
            job.completed_at = now
            job.lease_owner = None
            job.lease_expires_at = None
            job.execution_count += 1
            job.last_error_code = "missing_or_invalid_tool_output"
            job.last_error_message = err_msg
            await fail_stage_and_run(
                db,
                org_id=runner.organization_id,
                run=run,
                stage=stage,
                now=now,
                error_summary=err_msg,
            )
            db.add(
                RunnerEvent(
                    id=uuid.uuid4(),
                    organization_id=runner.organization_id,
                    runner_id=runner.id,
                    runner_job_id=job.id,
                    event_type=f"job_{job.status}",
                    severity=RunnerEventSeverity.WARNING.value,
                    details_json={
                        "execution_id": str(execution.id),
                        "exit_code": payload.exit_code,
                        "error_code": "missing_or_invalid_tool_output",
                    },
                )
            )
            return RunnerJobCompleteOut(
                job_id=job.id,
                job_status=RunnerJobStatus(job.status),
                execution_status=ToolExecutionStatus(execution.status),
                scan_run_status=ScanRunStatus(run.status),
            )

        execution.status = ToolExecutionStatus.COMPLETED.value
        job.status = validate_job_transition(job.status, RunnerJobStatus.COMPLETED.value)
        job.completed_at = now
        job.lease_owner = None
        job.lease_expires_at = None
        job.execution_count += 1
        await db.flush()
        cdx_count = next(
            (doc.component_count for doc in sbom_docs if doc.sbom_format == "cyclonedx-json"),
            0,
        )
        job.result_summary = redact_metadata(
            {
                "execution_id": str(execution.id),
                "exit_code": payload.exit_code,
                "findings_persisted": persisted_findings,
                "sbom_documents_persisted": len(sbom_docs),
                "sbom_component_count": cdx_count,
                **payload.metrics,
            }
        )
        await db.flush()
        stage_jobs = (
            (
                await db.execute(
                    select(RunnerJob).where(
                        RunnerJob.scan_stage_id == stage.id,
                        RunnerJob.organization_id == runner.organization_id,
                    )
                )
            )
            .scalars()
            .all()
        )
        if all(j.status == RunnerJobStatus.COMPLETED.value for j in stage_jobs):
            stage.status = validate_stage_transition(stage.status, ScanStageStatus.COMPLETED.value)
            stage.completed_at = now
            await db.flush()
            await advance_run_after_stage_complete(
                db,
                org_id=runner.organization_id,
                run=run,
                completed_stage=stage,
                now=now,
            )
    else:
        target_job_status = (
            RunnerJobStatus.TIMED_OUT.value
            if payload.status == "timed_out"
            else RunnerJobStatus.FAILED.value
        )
        execution.status = (
            ToolExecutionStatus.TIMED_OUT.value
            if payload.status == "timed_out"
            else ToolExecutionStatus.FAILED.value
        )
        job.status = validate_job_transition(job.status, target_job_status)
        job.completed_at = now
        job.lease_owner = None
        job.lease_expires_at = None
        job.execution_count += 1
        job.last_error_code = payload.error_code or payload.status
        job.last_error_message = (
            payload.error_message or f"Runner execution ended as {payload.status}"
        )
        await fail_stage_and_run(
            db,
            org_id=runner.organization_id,
            run=run,
            stage=stage,
            now=now,
            error_summary=job.last_error_message,
        )

    db.add(
        RunnerEvent(
            id=uuid.uuid4(),
            organization_id=runner.organization_id,
            runner_id=runner.id,
            runner_job_id=job.id,
            event_type=f"job_{job.status}",
            severity=RunnerEventSeverity.INFO.value,
            details_json={
                "execution_id": str(execution.id),
                "exit_code": payload.exit_code,
            },
        )
    )
    return RunnerJobCompleteOut(
        job_id=job.id,
        job_status=RunnerJobStatus(job.status),
        execution_status=ToolExecutionStatus(execution.status),
        scan_run_status=ScanRunStatus(run.status),
    )


async def list_scan_artifacts(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    scan_run_id: uuid.UUID,
    actor_role: Role,
) -> list[Artifact]:
    assert_permission(actor_role, Permission.SCAN_READ)
    rows = (
        (
            await db.execute(
                select(Artifact)
                .where(
                    Artifact.organization_id == org_id,
                    Artifact.scan_run_id == scan_run_id,
                )
                .order_by(Artifact.created_at.asc())
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


async def download_decrypted_artifact(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    scan_run_id: uuid.UUID,
    artifact_id: uuid.UUID,
    actor_role: Role,
    settings: Settings | None = None,
) -> tuple[Artifact, bytes]:
    assert_permission(actor_role, Permission.SCAN_READ)
    cfg = settings or get_settings()
    artifact = (
        await db.execute(
            select(Artifact).where(
                Artifact.id == artifact_id,
                Artifact.organization_id == org_id,
                Artifact.scan_run_id == scan_run_id,
            )
        )
    ).scalar_one_or_none()
    if artifact is None:
        raise NotFoundError("Artifact not found")

    target_path = _artifact_file_path(cfg.artifact_root, artifact.storage_key)
    if not target_path.exists():
        raise NotFoundError("Encrypted artifact blob missing from storage")

    keyring = resolve_keyring(cfg)
    ciphertext = target_path.read_bytes()
    plaintext = decrypt_artifact_with_keyring(
        ciphertext=ciphertext,
        expected_plaintext_sha256=artifact.sha256,
        expected_ciphertext_sha256=artifact.ciphertext_sha256,
        encryption_key_id=artifact.encryption_key_id or keyring.active_kek_id,
        keyring=keyring.keys,
        wrapped_dek_b64=artifact.wrapped_dek_b64,
        nonce_b64=artifact.nonce_b64,
        aad_b64=artifact.aad_b64,
    )
    return artifact, plaintext


async def get_runner_job_target_auth(
    db: AsyncSession,
    *,
    runner: Runner,
    job_id: uuid.UUID,
    settings: Settings | None = None,
) -> dict[str, Any]:
    """Resolve target authentication credentials via SecretProvider for an active claimed job."""
    cfg = settings or get_settings()
    job = (
        await db.execute(
            select(RunnerJob).where(
                RunnerJob.id == job_id,
                RunnerJob.organization_id == runner.organization_id,
            )
        )
    ).scalar_one_or_none()
    if job is None:
        raise NotFoundError("Runner job not found")
    if job.claimed_by_runner_id != runner.id or job.status != RunnerJobStatus.RUNNING.value:
        raise ForbiddenError("Runner does not hold active running lease for target authentication")

    run = (
        await db.execute(
            select(ScanRun).where(
                ScanRun.id == job.scan_run_id,
                ScanRun.organization_id == runner.organization_id,
            )
        )
    ).scalar_one_or_none()
    if run is None or run.auth_profile_id is None:
        raise NotFoundError("Runner job does not have an attached auth profile")

    auth_profile = (
        await db.execute(
            select(AuthProfile).where(
                AuthProfile.id == run.auth_profile_id,
                AuthProfile.organization_id == runner.organization_id,
            )
        )
    ).scalar_one_or_none()
    if auth_profile is None:
        raise NotFoundError("Auth profile not found")
    if auth_profile.status != "active":
        raise ForbiddenError(f"Auth profile is not active (status={auth_profile.status})")

    secret_prov = cfg.get_secret_provider()
    parts = urlsplit(auth_profile.secret_manager_ref)
    key_name = (parts.netloc + parts.path).strip("/")
    secret_val = secret_prov.get_secret(key_name, required=False) or ""

    db.add(
        RunnerEvent(
            id=uuid.uuid4(),
            organization_id=runner.organization_id,
            runner_id=runner.id,
            runner_job_id=job.id,
            event_type="target_auth_resolved",
            severity=RunnerEventSeverity.SECURITY.value,
            details_json={
                "auth_profile_id": str(auth_profile.id),
                "auth_type": auth_profile.auth_type,
                "name": auth_profile.name,
            },
        )
    )
    return {
        "auth_profile_id": auth_profile.id,
        "auth_type": auth_profile.auth_type,
        "name": auth_profile.name,
        "credentials": {
            "secret_value": secret_val,
        },
    }


async def get_runner_job_openapi_spec(
    db: AsyncSession,
    *,
    runner: Runner,
    job_id: uuid.UUID,
) -> bytes:
    """Return attached OpenAPI spec JSON/YAML bytes exclusively for the active claimed job."""
    job = (
        await db.execute(
            select(RunnerJob).where(
                RunnerJob.id == job_id,
                RunnerJob.organization_id == runner.organization_id,
            )
        )
    ).scalar_one_or_none()
    if job is None:
        raise NotFoundError("Runner job not found")
    if job.claimed_by_runner_id != runner.id or job.status != RunnerJobStatus.RUNNING.value:
        raise ForbiddenError("Runner does not hold active running lease for OpenAPI spec")

    job_cfg = job.job_configuration or {}
    spec_text = str(job_cfg.get("openapi_spec") or "").strip()
    if not spec_text:
        raise NotFoundError("Runner job does not have an attached OpenAPI specification")
    return spec_text.encode("utf-8")


async def record_target_health_probe(
    db: AsyncSession,
    *,
    runner: Runner,
    job_id: uuid.UUID,
    payload: TargetHealthProbeCreate,
) -> TargetHealthProbe:
    """Persist an immutable target health probe observation recorded during DAST."""
    job = (
        await db.execute(
            select(RunnerJob).where(
                RunnerJob.id == job_id,
                RunnerJob.organization_id == runner.organization_id,
            )
        )
    ).scalar_one_or_none()
    if job is None:
        raise NotFoundError("Runner job not found")
    if job.claimed_by_runner_id != runner.id or job.status not in {
        RunnerJobStatus.RUNNING.value,
        RunnerJobStatus.FAILED.value,
    }:
        raise ForbiddenError("Runner does not hold running lease to record health probe")

    run = (
        await db.execute(
            select(ScanRun).where(
                ScanRun.id == job.scan_run_id,
                ScanRun.organization_id == runner.organization_id,
            )
        )
    ).scalar_one()
    raw_asset_id = (run.target_snapshot or {}).get("asset_id")
    if not raw_asset_id:
        raise ValidationError("ScanRun missing asset_id in target_snapshot")
    asset_uuid = uuid.UUID(str(raw_asset_id))

    probe = TargetHealthProbe(
        id=uuid.uuid4(),
        organization_id=runner.organization_id,
        scan_run_id=job.scan_run_id,
        runner_job_id=job.id,
        asset_id=asset_uuid,
        probe_type=payload.probe_type,
        target_url=redact_text_secrets(payload.target_url) or payload.target_url,
        status_code=payload.status_code,
        latency_ms=payload.latency_ms,
        healthy=payload.healthy,
        error_message=redact_text_secrets(payload.error_message) if payload.error_message else None,
        probe_metadata=scrub_finding_dict(payload.probe_metadata),
    )
    db.add(probe)
    await db.flush()
    return probe
