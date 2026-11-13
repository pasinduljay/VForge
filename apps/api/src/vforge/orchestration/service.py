"""Phase 3 scan orchestration service: planning, outbox dispatch, leases, and reconciliation."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from vforge_scanners import SourceDiscoveryReport, evaluate_coverage
from vforge_scope import (
    DnsResolver,
    IntensityLevel,
    SystemDnsResolver,
    TargetType,
    normalize_capabilities,
)
from sqlalchemy import func, select, text, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.orm import selectinload

from vforge.auth.rbac import Permission, assert_permission
from vforge.config import Settings, get_settings
from vforge.db import set_db_context
from vforge.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from vforge.lifecycle.pipeline import resolve_active_tool_pins
from vforge.models.domain import (
    Asset,
    Authorization,
    AuthProfile,
    Environment,
    Project,
    ScanProfile,
    ScopeSnapshot,
)
from vforge.models.enums import (
    AuditOutcome,
    AuthProfileStatus,
    CoverageStatus,
    OutboxEventStatus,
    Role,
    RunnerJobStatus,
    ScanRunStatus,
    ScanStageStatus,
    TargetLeaseStatus,
)
from vforge.models.orchestration import (
    OutboxEvent,
    RunnerJob,
    ScanRun,
    ScanStage,
    ScanTargetLease,
    TargetHealthProbe,
)
from vforge.models.runner import RunnerPool
from vforge.models.scanner import SourceSnapshot
from vforge.orchestration.broker import DISPATCH_ROUTING_KEY, OrchestrationBroker
from vforge.orchestration.manifest import (
    sign_execution_manifest,
    validate_pinned_image_digest,
)
from vforge.orchestration.planner import build_declarative_scan_plan
from vforge.orchestration.state_machine import (
    JOB_TERMINAL_STATUSES,
    RUN_TERMINAL_STATUSES,
    validate_job_transition,
    validate_run_transition,
    validate_stage_transition,
)
from vforge.schemas import ScanRunCreate, ScopeEvaluateRequest
from vforge.security.opa_client import OpaScopeClient
from vforge.security.signing import SnapshotSigner
from vforge.services.audit import record_audit_event
from vforge.services.findings import resolve_scan_run_coverage_status
from vforge.services.scope import evaluate_scope, verify_snapshot
from vforge.studio.service import resolve_and_verify_rule_packs_for_scan

logger = logging.getLogger("vforge.orchestration.service")

_PRODUCTION_ENVS = frozenset({"production", "prod", "staging"})

_ACTIVE_RUN_STATUSES = frozenset(
    {
        ScanRunStatus.QUEUED.value,
        ScanRunStatus.PROVISIONING.value,
        ScanRunStatus.RUNNING.value,
        ScanRunStatus.COLLECTING.value,
        ScanRunStatus.NORMALIZING.value,
        ScanRunStatus.CORRELATING.value,
        ScanRunStatus.REPORTING.value,
    }
)


@dataclass(frozen=True)
class ScanCreationResult:
    scan_run: ScanRun
    idempotent_replay: bool


_ASSET_TYPE_TO_TARGET_TYPE: dict[str, TargetType] = {
    "web_application": TargetType.EXACT_URL,
    "rest_api": TargetType.REST_API,
    "source_repository": TargetType.SOURCE_REPOSITORY,
    "container_image": TargetType.CONTAINER_IMAGE,
    "cidr_range": TargetType.CIDR_RANGE,
    "network_service": TargetType.NETWORK_SERVICE,
    "infrastructure_definition": TargetType.INFRASTRUCTURE_DEFINITION,
}


def _resolve_target_type(raw_target_type: str, canonical_locator: str) -> TargetType:
    """Resolve stored asset_type / target_type strings into a `TargetType` enum."""
    cleaned = raw_target_type.strip().lower()
    if cleaned == "ip_address":
        return TargetType.IPV6 if ":" in canonical_locator else TargetType.IPV4
    if cleaned in _ASSET_TYPE_TO_TARGET_TYPE:
        return _ASSET_TYPE_TO_TARGET_TYPE[cleaned]
    try:
        return TargetType(cleaned)
    except ValueError as exc:
        raise ValidationError(f"Unsupported snapshot target_type: {raw_target_type}") from exc


def _canonical_fingerprint(data: dict[str, Any]) -> str:
    encoded = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _as_uuid(val: Any) -> uuid.UUID:
    return val if isinstance(val, uuid.UUID) else uuid.UUID(str(val))


async def _load_run_with_relations(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    scan_run_id: uuid.UUID,
) -> ScanRun | None:
    stmt = (
        select(ScanRun)
        .where(ScanRun.id == scan_run_id, ScanRun.organization_id == org_id)
        .options(
            selectinload(ScanRun.stages),
            selectinload(ScanRun.jobs),
            selectinload(ScanRun.leases),
            selectinload(ScanRun.health_probes),
        )
    )
    return (await db.execute(stmt)).scalar_one_or_none()


async def create_scan_run(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    request: ScanRunCreate,
    idempotency_key: str,
    correlation_id: str | None,
    settings: Settings | None = None,
    dns_resolver: DnsResolver | None = None,
    opa_client: OpaScopeClient | None = None,
    signer: SnapshotSigner | None = None,
) -> ScanCreationResult:
    """Validate authorization/scope fail-closed and atomically enqueue a declarative scan run."""
    assert_permission(actor_role, Permission.SCAN_START)
    cleaned_key = idempotency_key.strip()
    if not cleaned_key or len(cleaned_key) > 200:
        raise ValidationError("Idempotency-Key header must be 1..200 characters")

    cfg = settings or get_settings()
    if cfg.vforge_env.strip().lower() in _PRODUCTION_ENVS and (
        request.simulation_mode != "success" or request.simulation_delay_ms > 0
    ):
        raise ValidationError(
            "Simulation parameters are disabled in staging and production environments"
        )

    fingerprint = _canonical_fingerprint(
        {
            "organization_id": str(org_id),
            "project_id": str(request.project_id),
            "environment_id": str(request.environment_id),
            "scan_profile_id": str(request.scan_profile_id),
            "authorization_id": str(request.authorization_id),
            "scope_snapshot_id": str(request.scope_snapshot_id),
            "source_snapshot_id": str(request.source_snapshot_id)
            if request.source_snapshot_id
            else None,
            "auth_profile_id": str(request.auth_profile_id) if request.auth_profile_id else None,
            "requested_intensity": (
                request.requested_intensity.value if request.requested_intensity else None
            ),
            "execution_mode": request.execution_mode,
            "target_pool_id": str(request.target_pool_id) if request.target_pool_id else None,
            "runner_image_digest": request.runner_image_digest,
            "simulation_mode": request.simulation_mode,
            "simulation_delay_ms": request.simulation_delay_ms,
            "timeout_seconds_override": request.timeout_seconds_override,
            "max_attempts": request.max_attempts,
        }
    )

    # Serialize concurrent POST /scans requests sharing the same (org_id, idempotency_key)
    lock_digest = hashlib.sha256(f"scan_idemp:{org_id}:{cleaned_key}".encode()).digest()
    lock_key_int = int.from_bytes(lock_digest[:8], "big", signed=True)
    await db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": lock_key_int})

    existing = (
        await db.execute(
            select(ScanRun).where(
                ScanRun.organization_id == org_id,
                ScanRun.idempotency_key == cleaned_key,
            )
        )
    ).scalar_one_or_none()
    if existing is not None:
        if existing.request_fingerprint != fingerprint:
            raise ConflictError(
                "Idempotency-Key was already used with a different scan request payload"
            )
        loaded = await _load_run_with_relations(db, org_id=org_id, scan_run_id=existing.id)
        if loaded is None:
            raise NotFoundError("Scan run not found")
        return ScanCreationResult(scan_run=loaded, idempotent_replay=True)

    project = (
        await db.execute(
            select(Project).where(
                Project.id == request.project_id,
                Project.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if project is None:
        raise NotFoundError("Project not found")

    env = (
        await db.execute(
            select(Environment).where(
                Environment.id == request.environment_id,
                Environment.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if env is None or env.project_id != project.id:
        raise NotFoundError("Environment not found in specified project")

    profile = (
        await db.execute(
            select(ScanProfile).where(
                ScanProfile.id == request.scan_profile_id,
                ScanProfile.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if profile is None:
        raise NotFoundError("Scan profile not found")

    auth = (
        await db.execute(
            select(Authorization).where(
                Authorization.id == request.authorization_id,
                Authorization.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if auth is None:
        raise NotFoundError("Authorization not found")

    snapshot = (
        await db.execute(
            select(ScopeSnapshot).where(
                ScopeSnapshot.id == request.scope_snapshot_id,
                ScopeSnapshot.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if snapshot is None:
        raise NotFoundError("Scope snapshot not found")
    if snapshot.authorization_id != auth.id or snapshot.project_id != project.id:
        raise ValidationError("Scope snapshot does not belong to specified authorization/project")

    asset = (
        await db.execute(
            select(Asset).where(Asset.id == auth.asset_id, Asset.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if asset is None or asset.environment_id != env.id:
        raise ValidationError("Authorized asset does not belong to specified environment")

    source_snapshot: SourceSnapshot | None = None
    if request.source_snapshot_id is not None:
        source_snapshot = (
            await db.execute(
                select(SourceSnapshot).where(
                    SourceSnapshot.id == request.source_snapshot_id,
                    SourceSnapshot.organization_id == org_id,
                    SourceSnapshot.project_id == project.id,
                )
            )
        ).scalar_one_or_none()
        if source_snapshot is None:
            raise NotFoundError("Source snapshot not found in project")
        if source_snapshot.asset_id != asset.id:
            raise ValidationError("Source snapshot does not belong to target asset")

    resolved_pool: RunnerPool | None = None
    if request.execution_mode == "runner":
        if request.target_pool_id is not None:
            resolved_pool = (
                await db.execute(
                    select(RunnerPool).where(
                        RunnerPool.id == request.target_pool_id,
                        RunnerPool.organization_id == org_id,
                    )
                )
            ).scalar_one_or_none()
            if resolved_pool is None:
                raise NotFoundError("Target runner pool not found")
            if not resolved_pool.active:
                raise ConflictError("Target runner pool is inactive")
        else:
            resolved_pool = (
                await db.execute(
                    select(RunnerPool)
                    .where(RunnerPool.organization_id == org_id, RunnerPool.active.is_(True))
                    .order_by(RunnerPool.created_at.asc())
                    .limit(1)
                )
            ).scalar_one_or_none()
            if resolved_pool is None:
                raise ValidationError("Active runner pool required for execution_mode='runner'")
        if request.runner_image_digest:
            validate_pinned_image_digest(
                request.runner_image_digest,
                cfg.runner_allowed_image_digests,
            )

    stage_to_tool = {
        "sast": "opengrep",
        "secrets": "gitleaks",
        "sbom": "syft",
        "sca": "grype",
        "iac": "checkov",
    }
    raw_stage_tokens = [
        str(s).strip().lower() for s in ((profile.configuration or {}).get("stages") or [])
    ]
    selected_tools: list[str] = []
    if "sca" in raw_stage_tokens and "sbom" not in raw_stage_tokens:
        selected_tools.append("syft")
    for tok in raw_stage_tokens:
        mapped_tool = stage_to_tool.get(tok)
        if mapped_tool and mapped_tool not in selected_tools:
            selected_tools.append(mapped_tool)
    run_coverage_summary: dict[str, Any] = {}
    if source_snapshot is not None and request.execution_mode == "runner" and selected_tools:
        lang_meta = source_snapshot.detected_languages or {}
        cov_meta = source_snapshot.coverage_report or {}
        discovery = SourceDiscoveryReport(
            files_total_eligible=int(lang_meta.get("files_total_eligible", 0)),
            files_skipped_symlinks=int(cov_meta.get("files_skipped_symlinks", 0)),
            files_truncated=bool(cov_meta.get("files_truncated", False)),
            languages=dict(lang_meta.get("languages") or {}),
            manifests_detected=tuple(lang_meta.get("manifests_detected") or ()),
            ecosystems_detected=tuple(lang_meta.get("ecosystems_detected") or ()),
            excluded_directories=dict(lang_meta.get("excluded_directories") or {}),
        )
        run_coverage_summary = evaluate_coverage(discovery, selected_tools=selected_tools)

    target_auth_profile_id = request.auth_profile_id or (profile.configuration or {}).get(
        "auth_profile_id"
    )
    resolved_auth_profile_id: uuid.UUID | None = None
    if target_auth_profile_id:
        try:
            auth_pid = uuid.UUID(str(target_auth_profile_id))
        except (ValueError, TypeError) as exc:
            raise ValidationError(
                f"Invalid auth_profile_id format: {target_auth_profile_id}"
            ) from exc
        auth_prof = (
            await db.execute(
                select(AuthProfile).where(
                    AuthProfile.id == auth_pid,
                    AuthProfile.organization_id == org_id,
                    AuthProfile.environment_id == env.id,
                )
            )
        ).scalar_one_or_none()
        if auth_prof is None:
            raise NotFoundError(f"AuthProfile {auth_pid} not found for this environment")
        if auth_prof.status != AuthProfileStatus.ACTIVE.value:
            raise ConflictError(f"AuthProfile {auth_pid} is inactive")
        resolved_auth_profile_id = auth_prof.id

    resolved_pins = await resolve_active_tool_pins(db, settings=cfg, use_canary=False)

    raw_pack_ids = (profile.configuration or {}).get("rule_pack_version_ids")
    rule_pack_version_ids: list[uuid.UUID] = []
    if raw_pack_ids is not None:
        if not isinstance(raw_pack_ids, list):
            raise ValidationError("ScanProfile rule_pack_version_ids must be a list of UUIDs")
        seen_pack_ids: set[uuid.UUID] = set()
        for pid in raw_pack_ids:
            try:
                parsed_pid = uuid.UUID(str(pid))
            except ValueError as exc:
                raise ValidationError(
                    "ScanProfile rule_pack_version_ids must contain valid UUIDs"
                ) from exc
            if parsed_pid not in seen_pack_ids:
                seen_pack_ids.add(parsed_pid)
                rule_pack_version_ids.append(parsed_pid)
    resolved_rule_pack_pins = await resolve_and_verify_rule_packs_for_scan(
        db,
        organization_id=org_id,
        rule_pack_version_ids=rule_pack_version_ids,
        settings=cfg,
    )
    pinned_tools = dict(resolved_pins.provenance_manifest.get("tools") or {})
    tool_versions_map = {
        slug: str(info.get("version_tag"))
        for slug, info in pinned_tools.items()
        if isinstance(info, dict) and info.get("version_tag")
    }
    adapter_versions_map = {
        slug: str(info.get("adapter_version"))
        for slug, info in pinned_tools.items()
        if isinstance(info, dict) and info.get("adapter_version")
    }
    plan = build_declarative_scan_plan(
        profile=profile,
        asset=asset,
        execution_mode=request.execution_mode,
        runner_pool_slug=resolved_pool.slug if resolved_pool else "control-preflight",
        runner_image_digest=request.runner_image_digest,
        opengrep_image_digest=resolved_pins.image_refs["opengrep"],
        gitleaks_image_digest=resolved_pins.image_refs["gitleaks"],
        syft_image_digest=resolved_pins.image_refs["syft"],
        grype_image_digest=resolved_pins.image_refs["grype"],
        checkov_image_digest=resolved_pins.image_refs["checkov"],
        zap_image_digest=resolved_pins.image_refs["zap"],
        nuclei_image_digest=resolved_pins.image_refs["nuclei"],
        nmap_image_digest=resolved_pins.image_refs["nmap"],
        testssl_image_digest=resolved_pins.image_refs["testssl"],
        tool_versions=tool_versions_map,
        adapter_versions=adapter_versions_map,
        allowed_image_digests=resolved_pins.allowed_image_digests,
        source_snapshot_present=source_snapshot is not None,
        coverage_summary=run_coverage_summary,
        simulation_mode=request.simulation_mode,
        simulation_delay_ms=request.simulation_delay_ms,
        timeout_seconds_override=request.timeout_seconds_override,
        max_attempts=request.max_attempts,
    )
    if request.execution_mode == "runner":
        for stage_spec in plan.stages:
            for job_spec in stage_spec.jobs:
                validate_pinned_image_digest(
                    job_spec.image_digest,
                    resolved_pins.allowed_image_digests,
                )

    resolver = dns_resolver or SystemDnsResolver()
    client = opa_client or OpaScopeClient(
        base_url=cfg.opa_url,
        timeout_seconds=cfg.opa_timeout_seconds,
    )
    active_signer = signer or SnapshotSigner.from_settings(cfg)

    snapshot_check = await verify_snapshot(
        db,
        org_id=org_id,
        snapshot_id=snapshot.id,
        actor_id=actor_id,
        actor_role=actor_role,
        revalidate_dns=request.revalidate_dns,
        correlation_id=correlation_id,
        settings=cfg,
        dns_resolver=resolver,
        opa_client=client,
        signer=active_signer,
        skip_rbac=True,
    )

    profile_cfg = profile.configuration or {}
    passive_only = bool(profile_cfg.get("passive_only", True))
    requested_stages = [
        str(s).strip().lower() for s in (profile_cfg.get("stages") or []) if str(s).strip()
    ]
    normalized_requested = [cap.value for cap in normalize_capabilities(requested_stages)]

    effective_intensity = request.requested_intensity or (
        IntensityLevel.PASSIVE if passive_only else IntensityLevel(snapshot.permitted_intensity)
    )
    if passive_only and effective_intensity != IntensityLevel.PASSIVE:
        raise ValidationError(
            "Cannot request non-passive intensity with a passive_only scan profile"
        )

    scope_eval = await evaluate_scope(
        db,
        org_id=org_id,
        actor_id=actor_id,
        actor_role=actor_role,
        request=ScopeEvaluateRequest(
            asset_id=asset.id,
            authorization_id=auth.id,
            scan_profile_id=profile.id,
            snapshot_id=snapshot.id,
            target_type=_resolve_target_type(snapshot.target_type, snapshot.canonical_locator),
            raw_target=snapshot.canonical_locator,
            requested_capabilities=normalized_requested,
            requested_intensity=effective_intensity,
            resolve_dns=request.revalidate_dns,
        ),
        correlation_id=correlation_id,
        settings=cfg,
        dns_resolver=resolver,
        opa_client=client,
        signer=active_signer,
    )

    if not snapshot_check.valid or scope_eval.outcome != "ALLOW" or not scope_eval.allowed:
        reasons = [r.code for r in snapshot_check.reasons] + [r.code for r in scope_eval.reasons]
        await record_audit_event(
            db,
            organization_id=org_id,
            actor_id=actor_id,
            correlation_id=correlation_id,
            action="scan_run.rejected",
            resource_type="scope_snapshot",
            resource_id=snapshot.id,
            outcome=AuditOutcome.DENIED,
            metadata={
                "snapshot_valid": snapshot_check.valid,
                "scope_outcome": scope_eval.outcome,
                "reason_codes": sorted(set(reasons)),
            },
        )
        await db.commit()
        raise ForbiddenError(
            "Pre-dispatch authorization and scope enforcement denied scan creation"
        )

    run_id = uuid.uuid4()
    scan_run = ScanRun(
        id=run_id,
        organization_id=org_id,
        project_id=project.id,
        environment_id=env.id,
        scan_profile_id=profile.id,
        auth_profile_id=resolved_auth_profile_id,
        authorization_id=auth.id,
        scope_snapshot_id=snapshot.id,
        source_snapshot_id=source_snapshot.id if source_snapshot else None,
        requested_by=actor_id,
        status=ScanRunStatus.QUEUED.value,
        coverage_status=CoverageStatus.PENDING.value,
        coverage_summary=run_coverage_summary,
        source_snapshot_hash=source_snapshot.archive_sha256 if source_snapshot else None,
        runner_pool=plan.runner_pool,
        target_snapshot={
            "asset_id": str(asset.id),
            "asset_type": asset.asset_type,
            "normalized_locator": asset.normalized_locator,
            "resolved_ips": snapshot_check.resolved_ips,
            "environment_type": env.environment_type,
        },
        profile_snapshot={
            "id": str(profile.id),
            "name": profile.name,
            "version": profile.version,
            "configuration": profile.configuration,
            "requested_intensity": effective_intensity.value,
        },
        plan_manifest=plan.manifest,
        tool_version_pins=resolved_pins.provenance_manifest,
        rule_pack_pins=resolved_rule_pack_pins,
        policy_snapshot_hash=snapshot.payload_sha256,
        policy_version=cfg.policy_bundle_version,
        idempotency_key=cleaned_key,
        request_fingerprint=fingerprint,
    )
    db.add(scan_run)
    await db.flush()

    first_stage_jobs: list[RunnerJob] = []
    for stage_spec in plan.stages:
        stage_id = uuid.uuid4()
        is_root = stage_spec.depends_on_stage_key is None
        stage = ScanStage(
            id=stage_id,
            organization_id=org_id,
            scan_run_id=run_id,
            stage_key=stage_spec.stage_key,
            stage_order=stage_spec.stage_order,
            stage_kind=stage_spec.stage_kind,
            depends_on_stage_key=stage_spec.depends_on_stage_key,
            requires_target_lease=stage_spec.requires_target_lease,
            lease_risk_class=stage_spec.lease_risk_class,
            status=(ScanStageStatus.QUEUED.value if is_root else ScanStageStatus.PENDING.value),
        )
        db.add(stage)
        await db.flush()

        for job_idx, job_spec in enumerate(stage_spec.jobs):
            job_id = uuid.uuid4()
            job = RunnerJob(
                id=job_id,
                organization_id=org_id,
                scan_run_id=run_id,
                scan_stage_id=stage_id,
                job_type=job_spec.job_type,
                tool_id=job_spec.tool_id,
                tool_version=job_spec.tool_version,
                image_digest=job_spec.image_digest,
                adapter_version=job_spec.adapter_version,
                status=RunnerJobStatus.PENDING.value,
                attempt_count=0,
                max_attempts=job_spec.max_attempts,
                timeout_seconds=job_spec.timeout_seconds,
                idempotency_key=f"job:{run_id}:{stage_spec.stage_key}:{job_idx}",
                job_configuration=job_spec.configuration,
                execution_mode=request.execution_mode,
                target_pool_id=resolved_pool.id if resolved_pool else None,
            )
            db.add(job)
            await db.flush()
            if is_root:
                first_stage_jobs.append(job)

    for job in first_stage_jobs:
        event_idempotency = f"dispatch:{job.id}:attempt:1"
        db.add(
            OutboxEvent(
                id=uuid.uuid4(),
                organization_id=org_id,
                scan_run_id=run_id,
                runner_job_id=job.id,
                event_type="scan.job.dispatch",
                routing_key=DISPATCH_ROUTING_KEY,
                idempotency_key=event_idempotency,
                payload={
                    "event_type": "scan.job.dispatch",
                    "organization_id": str(org_id),
                    "scan_run_id": str(run_id),
                    "scan_stage_id": str(job.scan_stage_id),
                    "runner_job_id": str(job.id),
                    "idempotency_key": job.idempotency_key,
                    "dispatch_key": event_idempotency,
                    "job_type": job.job_type,
                    "correlation_id": correlation_id or "",
                },
                status=OutboxEventStatus.PENDING.value,
            )
        )

    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        action="scan_run.created",
        resource_type="scan_run",
        resource_id=run_id,
        outcome=AuditOutcome.SUCCESS,
        metadata={
            "project_id": str(project.id),
            "environment_id": str(env.id),
            "scan_profile_id": str(profile.id),
            "scope_snapshot_id": str(snapshot.id),
            "stage_count": len(plan.stages),
            "simulated": request.execution_mode == "simulated",
        },
    )

    loaded = await _load_run_with_relations(db, org_id=org_id, scan_run_id=run_id)
    if loaded is None:
        raise RuntimeError("Failed to reload newly created scan run")
    return ScanCreationResult(scan_run=loaded, idempotent_replay=False)


async def list_scan_runs(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_role: Role,
    limit: int = 50,
    offset: int = 0,
    status_filter: str | None = None,
) -> tuple[list[ScanRun], int]:
    """List scan runs for an organization with total count."""
    assert_permission(actor_role, Permission.SCAN_READ)
    filters = [ScanRun.organization_id == org_id]
    if status_filter:
        filters.append(ScanRun.status == status_filter)

    total = int((await db.execute(select(func.count(ScanRun.id)).where(*filters))).scalar_one())
    items = (
        (
            await db.execute(
                select(ScanRun)
                .where(*filters)
                .order_by(ScanRun.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return list(items), total


async def get_scan_run(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    scan_run_id: uuid.UUID,
    actor_role: Role,
) -> ScanRun:
    """Return full orchestration details (stages, jobs, leases) for a scan run."""
    assert_permission(actor_role, Permission.SCAN_READ)
    run = await _load_run_with_relations(db, org_id=org_id, scan_run_id=scan_run_id)
    if run is None:
        raise NotFoundError("Scan run not found")
    return run


async def list_target_leases(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    actor_role: Role,
    status_filter: str | None = None,
    limit: int = 100,
) -> list[ScanTargetLease]:
    """List target leases within the caller's organization."""
    assert_permission(actor_role, Permission.SCAN_READ)
    filters = [ScanTargetLease.organization_id == org_id]
    if status_filter:
        filters.append(ScanTargetLease.status == status_filter)
    rows = (
        (
            await db.execute(
                select(ScanTargetLease)
                .where(*filters)
                .order_by(ScanTargetLease.acquired_at.desc())
                .limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


async def list_scan_health_probes(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    scan_run_id: uuid.UUID,
    actor_role: Role,
) -> list[TargetHealthProbe]:
    """List target health safety probes recorded for a scan run."""
    assert_permission(actor_role, Permission.SCAN_READ)
    rows = (
        (
            await db.execute(
                select(TargetHealthProbe)
                .where(
                    TargetHealthProbe.organization_id == org_id,
                    TargetHealthProbe.scan_run_id == scan_run_id,
                )
                .order_by(TargetHealthProbe.created_at.asc())
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


async def request_cancel_scan_run(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    scan_run_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    reason: str | None,
    correlation_id: str | None,
) -> ScanRun:
    """Request safe cancellation of an active or queued scan run."""
    assert_permission(actor_role, Permission.SCAN_CANCEL)
    now = datetime.now(UTC)
    run = (
        await db.execute(
            select(ScanRun)
            .where(ScanRun.id == scan_run_id, ScanRun.organization_id == org_id)
            .with_for_update()
        )
    ).scalar_one_or_none()
    if run is None:
        raise NotFoundError("Scan run not found")

    if run.status == ScanRunStatus.CANCELLED.value:
        loaded = await _load_run_with_relations(db, org_id=org_id, scan_run_id=run.id)
        assert loaded is not None
        return loaded

    if run.status in RUN_TERMINAL_STATUSES:
        raise ConflictError(f"Scan run is already in terminal state '{run.status}'")

    if run.status != ScanRunStatus.CANCELLING.value:
        run.status = validate_run_transition(run.status, ScanRunStatus.CANCELLING.value)
    run.cancel_requested_by = actor_id
    run.cancel_reason = reason or run.cancel_reason or "Cancelled by operator"

    jobs = (
        (
            await db.execute(
                select(RunnerJob)
                .where(RunnerJob.scan_run_id == run.id, RunnerJob.organization_id == org_id)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    has_live_leased_or_running = False
    for job in jobs:
        if job.status in JOB_TERMINAL_STATUSES:
            continue
        if job.status in {
            RunnerJobStatus.PENDING.value,
            RunnerJobStatus.DISPATCHED.value,
            RunnerJobStatus.RETRY_SCHEDULED.value,
        } or (
            job.status == RunnerJobStatus.LEASED.value
            and job.execution_mode == "runner"
            and job.claimed_by_runner_id is None
        ):
            job.status = validate_job_transition(job.status, RunnerJobStatus.CANCELLED.value)
            job.completed_at = now
            job.lease_owner = None
            job.lease_expires_at = None
        else:
            if job.cancel_requested_at is None:
                job.cancel_requested_at = now
            has_live_leased_or_running = True

    if not has_live_leased_or_running:
        await _finalize_run_cancellation(db, run=run, org_id=org_id, now=now)

    await db.flush()
    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        correlation_id=correlation_id,
        action="scan_run.cancel_requested",
        resource_type="scan_run",
        resource_id=run.id,
        outcome=AuditOutcome.SUCCESS,
        metadata={
            "status": run.status,
            "reason": run.cancel_reason or "",
        },
    )
    loaded = await _load_run_with_relations(db, org_id=org_id, scan_run_id=run.id)
    assert loaded is not None
    return loaded


async def _finalize_run_cancellation(
    db: AsyncSession,
    *,
    run: ScanRun,
    org_id: uuid.UUID,
    now: datetime,
) -> None:
    stages = (
        (
            await db.execute(
                select(ScanStage)
                .where(ScanStage.scan_run_id == run.id, ScanStage.organization_id == org_id)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    for stage in stages:
        if stage.status in {
            ScanStageStatus.PENDING.value,
            ScanStageStatus.QUEUED.value,
            ScanStageStatus.RUNNING.value,
        }:
            stage.status = validate_stage_transition(stage.status, ScanStageStatus.CANCELLED.value)
            stage.completed_at = stage.completed_at or now

    await db.execute(
        update(ScanTargetLease)
        .where(
            ScanTargetLease.organization_id == org_id,
            ScanTargetLease.scan_run_id == run.id,
            ScanTargetLease.status == TargetLeaseStatus.ACTIVE.value,
        )
        .values(status=TargetLeaseStatus.REVOKED.value, released_at=now)
    )
    await db.execute(
        update(OutboxEvent)
        .where(
            OutboxEvent.organization_id == org_id,
            OutboxEvent.scan_run_id == run.id,
            OutboxEvent.status == OutboxEventStatus.PENDING.value,
        )
        .values(status=OutboxEventStatus.PUBLISHED.value, published_at=now)
    )
    if run.status != ScanRunStatus.CANCELLED.value:
        run.status = validate_run_transition(run.status, ScanRunStatus.CANCELLED.value)
    if run.coverage_status == CoverageStatus.PENDING.value:
        run.coverage_status = CoverageStatus.PARTIAL.value
    run.completed_at = run.completed_at or now


async def _list_due_work(
    session: AsyncSession,
    *,
    limit: int = 100,
    work_kinds: list[str] | None = None,
) -> list[tuple[str, uuid.UUID, uuid.UUID]]:
    sql = text(
        "SELECT work_kind, record_id, organization_id "
        "FROM public.list_due_orchestration_work(:limit, :work_kinds)"
    )
    rows = (await session.execute(sql, {"limit": limit, "work_kinds": work_kinds})).all()
    return [(str(r[0]), _as_uuid(r[1]), _as_uuid(r[2])) for r in rows]


async def dispatch_pending_outbox_once(
    session_factory: async_sessionmaker[AsyncSession],
    broker: OrchestrationBroker,
    settings: Settings | None = None,
    *,
    limit: int = 50,
    dispatch_lease_seconds: int = 60,
) -> int:
    """Publish due transactional outbox events to RabbitMQ inside RLS-scoped transactions."""
    _ = settings
    async with session_factory() as discovery_session:
        due = await _list_due_work(
            discovery_session,
            limit=limit,
            work_kinds=["outbox_dispatch"],
        )
    outbox_items = [(rec_id, org_id) for _, rec_id, org_id in due]

    published_count = 0
    for event_id, org_id in outbox_items:
        now = datetime.now(UTC)
        async with session_factory() as session:
            async with session.begin():
                await set_db_context(session, org_id=org_id)
                ref = (
                    await session.execute(
                        select(OutboxEvent.scan_run_id, OutboxEvent.runner_job_id).where(
                            OutboxEvent.id == event_id,
                            OutboxEvent.organization_id == org_id,
                        )
                    )
                ).first()
                if ref is None:
                    continue
                scan_run_id_ref, job_id_ref = ref

                # Canonical lock order: ScanRun -> RunnerJob -> OutboxEvent
                run = (
                    await session.execute(
                        select(ScanRun)
                        .where(
                            ScanRun.id == scan_run_id_ref,
                            ScanRun.organization_id == org_id,
                        )
                        .with_for_update()
                    )
                ).scalar_one_or_none()
                job: RunnerJob | None = None
                if job_id_ref is not None:
                    job = (
                        await session.execute(
                            select(RunnerJob)
                            .where(
                                RunnerJob.id == job_id_ref,
                                RunnerJob.organization_id == org_id,
                            )
                            .with_for_update()
                        )
                    ).scalar_one_or_none()

                event = (
                    await session.execute(
                        select(OutboxEvent)
                        .where(OutboxEvent.id == event_id, OutboxEvent.organization_id == org_id)
                        .with_for_update(skip_locked=True)
                    )
                ).scalar_one_or_none()
                if event is None or event.status != OutboxEventStatus.PENDING.value:
                    continue
                if event.next_attempt_at > now:
                    continue

                if (
                    run is None
                    or run.status in RUN_TERMINAL_STATUSES
                    or run.status == ScanRunStatus.CANCELLING.value
                    or job is None
                    or job.status in JOB_TERMINAL_STATUSES
                ):
                    event.status = OutboxEventStatus.PUBLISHED.value
                    event.published_at = now
                    continue

                try:
                    await broker.publish(
                        routing_key=event.routing_key,
                        payload=event.payload,
                        message_id=event.idempotency_key,
                        correlation_id=str(event.payload.get("correlation_id", "")) or None,
                    )
                except Exception as exc:  # noqa: BLE001
                    event.retry_count += 1
                    event.last_error = f"publish_failed:{type(exc).__name__}"
                    if event.retry_count >= event.max_retries:
                        event.status = OutboxEventStatus.DEAD_LETTER.value
                    else:
                        backoff = min(60, 2**event.retry_count)
                        event.next_attempt_at = now + timedelta(seconds=backoff)
                    logger.warning(
                        "outbox_publish_retry event_id=%s retry=%s err=%s",
                        event.id,
                        event.retry_count,
                        type(exc).__name__,
                    )
                    continue

                if job.status in {
                    RunnerJobStatus.PENDING.value,
                    RunnerJobStatus.RETRY_SCHEDULED.value,
                }:
                    job.status = validate_job_transition(
                        job.status, RunnerJobStatus.DISPATCHED.value
                    )
                    job.dispatched_at = now
                    job.lease_expires_at = now + timedelta(seconds=dispatch_lease_seconds)

                event.status = OutboxEventStatus.PUBLISHED.value
                event.published_at = now
                event.last_error = None
                published_count += 1

    return published_count


async def process_dispatch_message(
    session_factory: async_sessionmaker[AsyncSession],
    payload: dict[str, Any],
    *,
    worker_id: str,
    settings: Settings | None = None,
    lease_ttl_seconds: int = 30,
    retry_backoff_seconds: int = 1,
    lease_retry_delay_seconds: int = 1,
    pre_dispatch_hook: Callable[[ScanRun, RunnerJob], Awaitable[bool]] | None = None,
) -> str:
    """Execute one Phase 3 dummy orchestration job idempotently under target lease safety."""
    cfg = settings or get_settings()
    try:
        org_id = _as_uuid(payload["organization_id"])
        job_id = _as_uuid(payload["runner_job_id"])
        scan_run_id = _as_uuid(payload["scan_run_id"])
    except (KeyError, ValueError):
        logger.warning("invalid_dispatch_payload")
        return "invalid_payload"

    now = datetime.now(UTC)
    requires_lease = False
    asset_id: uuid.UUID | None = None
    target_locator = ""
    lease_risk_class: str | None = None
    lease_id: uuid.UUID | None = None
    attempt_number = 0
    sim_mode = "success"
    sim_delay_ms = 0

    async with session_factory() as session:
        async with session.begin():
            await set_db_context(session, org_id=org_id)
            run = (
                await session.execute(
                    select(ScanRun)
                    .where(ScanRun.id == scan_run_id, ScanRun.organization_id == org_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            job = (
                await session.execute(
                    select(RunnerJob)
                    .where(RunnerJob.id == job_id, RunnerJob.organization_id == org_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if run is None or job is None:
                return "not_found"

            stage = (
                await session.execute(
                    select(ScanStage)
                    .where(
                        ScanStage.id == job.scan_stage_id,
                        ScanStage.organization_id == org_id,
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if stage is None:
                return "stage_not_found"

            # Strict idempotency guard: duplicate/re-delivered messages must never re-execute.
            if job.status in JOB_TERMINAL_STATUSES or job.status == RunnerJobStatus.RUNNING.value:
                return "already_handled"

            if (
                job.status == RunnerJobStatus.LEASED.value
                and job.lease_expires_at is not None
                and job.lease_expires_at > now
                and job.lease_owner not in {None, worker_id}
            ):
                return "lease_held_by_other"

            if run.status in RUN_TERMINAL_STATUSES or run.status == ScanRunStatus.CANCELLING.value:
                if job.status not in JOB_TERMINAL_STATUSES:
                    job.status = validate_job_transition(
                        job.status, RunnerJobStatus.CANCELLED.value
                    )
                    job.completed_at = now
                if run.status == ScanRunStatus.CANCELLING.value:
                    await _finalize_run_cancellation(db=session, run=run, org_id=org_id, now=now)
                return "cancelled"

            if pre_dispatch_hook is not None:
                allowed = await pre_dispatch_hook(run, job)
                if not allowed:
                    job.status = validate_job_transition(job.status, RunnerJobStatus.FAILED.value)
                    job.last_error_code = "pre_dispatch_policy_denied"
                    job.last_error_message = "Pre-dispatch verification rejected execution"
                    job.completed_at = now
                    await _fail_stage_and_run(
                        session,
                        org_id=org_id,
                        run=run,
                        stage=stage,
                        now=now,
                        error_summary="Pre-dispatch verification failed",
                    )
                    return "policy_denied"

            if job.status == RunnerJobStatus.PENDING.value:
                job.status = validate_job_transition(job.status, RunnerJobStatus.DISPATCHED.value)
                job.dispatched_at = job.dispatched_at or now

            if stage.requires_target_lease and stage.lease_risk_class:
                requires_lease = True
                lease_risk_class = stage.lease_risk_class
                target_snap = run.target_snapshot or {}
                raw_asset_id = target_snap.get("asset_id")
                target_locator = str(target_snap.get("normalized_locator", ""))
                if not raw_asset_id:
                    raise ValidationError("ScanRun missing asset_id in target_snapshot")
                asset_id = _as_uuid(raw_asset_id)

                candidate_lease_id = uuid.uuid4()
                stmt = (
                    pg_insert(ScanTargetLease)
                    .values(
                        id=candidate_lease_id,
                        organization_id=org_id,
                        scan_run_id=run.id,
                        runner_job_id=job.id,
                        asset_id=asset_id,
                        target_locator=target_locator,
                        lease_risk_class=lease_risk_class,
                        lease_owner=worker_id,
                        status=TargetLeaseStatus.ACTIVE.value,
                        acquired_at=now,
                        heartbeat_at=now,
                        expires_at=now + timedelta(seconds=lease_ttl_seconds),
                    )
                    .on_conflict_do_nothing(
                        index_elements=["asset_id", "lease_risk_class"],
                        index_where=text("status = 'active'"),
                    )
                    .returning(ScanTargetLease.id)
                )
                inserted_lease = (await session.execute(stmt)).scalar_one_or_none()
                if inserted_lease is None:
                    job.status = validate_job_transition(
                        job.status, RunnerJobStatus.RETRY_SCHEDULED.value
                    )
                    job.next_retry_at = now + timedelta(seconds=max(1, lease_retry_delay_seconds))
                    job.lease_owner = None
                    job.lease_expires_at = None
                    job.last_error_code = "target_lease_busy"
                    job.last_error_message = (
                        f"Exclusive target lease busy for risk class '{lease_risk_class}'"
                    )
                    return "target_lease_busy"
                lease_id = _as_uuid(inserted_lease)

            job.status = validate_job_transition(job.status, RunnerJobStatus.LEASED.value)
            job.lease_owner = "awaiting_runner" if job.execution_mode == "runner" else worker_id
            job.lease_expires_at = now + timedelta(seconds=lease_ttl_seconds)
            job.heartbeat_at = now
            job.attempt_count += 1
            attempt_number = job.attempt_count

            if job.execution_mode == "runner":
                snapshot = (
                    await session.execute(
                        select(ScopeSnapshot).where(
                            ScopeSnapshot.id == run.scope_snapshot_id,
                            ScopeSnapshot.organization_id == org_id,
                        )
                    )
                ).scalar_one_or_none()
                if snapshot is None:
                    raise NotFoundError("Scope snapshot not found for runner manifest signing")
                resolved_pins = await resolve_active_tool_pins(
                    session, settings=cfg, use_canary=False
                )
                signed = sign_execution_manifest(
                    run=run,
                    job=job,
                    snapshot=snapshot,
                    settings=cfg,
                    now=now,
                    allowed_image_digests=resolved_pins.allowed_image_digests,
                )
                job.manifest_sha256 = signed.bundle.payload_sha256
                job.manifest_signature = signed.bundle.signature
                job.manifest_signing_key_id = signed.bundle.signing_key_id
                job.manifest_expires_at = signed.expires_at
                job.job_configuration = {
                    **(job.job_configuration or {}),
                    "signed_manifest": signed.manifest,
                }
                if stage.status == ScanStageStatus.PENDING.value:
                    stage.status = validate_stage_transition(
                        stage.status, ScanStageStatus.QUEUED.value
                    )
                if run.status == ScanRunStatus.QUEUED.value:
                    run.status = validate_run_transition(
                        run.status, ScanRunStatus.PROVISIONING.value
                    )
                return "leased_for_runner"

            job.status = validate_job_transition(job.status, RunnerJobStatus.RUNNING.value)
            job.started_at = job.started_at or now

            if stage.status in {ScanStageStatus.PENDING.value, ScanStageStatus.QUEUED.value}:
                stage.status = validate_stage_transition(
                    stage.status, ScanStageStatus.RUNNING.value
                )
                stage.started_at = stage.started_at or now

            if run.status in {ScanRunStatus.QUEUED.value, ScanRunStatus.PROVISIONING.value}:
                run.status = validate_run_transition(run.status, ScanRunStatus.RUNNING.value)
                run.started_at = run.started_at or now

            job_cfg = job.job_configuration or {}
            sim_mode = str(job_cfg.get("simulation_mode", "success"))
            raw_delay = int(job_cfg.get("simulation_delay_ms", 0))
            sim_delay_ms = max(0, min(raw_delay, 5000))
            if cfg.vforge_env.strip().lower() in _PRODUCTION_ENVS:
                sim_mode = "success"
                sim_delay_ms = 0

    # Simulated crash/hang for lease-expiration & reconciliation verification.
    if sim_mode == "timeout_hold":
        return "timeout_held"

    if sim_delay_ms > 0:
        await asyncio.sleep(sim_delay_ms / 1000.0)

    finish_now = datetime.now(UTC)
    async with session_factory() as session:
        async with session.begin():
            await set_db_context(session, org_id=org_id)
            run = (
                await session.execute(
                    select(ScanRun)
                    .where(ScanRun.id == scan_run_id, ScanRun.organization_id == org_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            job = (
                await session.execute(
                    select(RunnerJob)
                    .where(RunnerJob.id == job_id, RunnerJob.organization_id == org_id)
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if run is None or job is None:
                return "not_found"

            stage = (
                await session.execute(
                    select(ScanStage)
                    .where(
                        ScanStage.id == job.scan_stage_id,
                        ScanStage.organization_id == org_id,
                    )
                    .with_for_update()
                )
            ).scalar_one_or_none()
            if stage is None:
                return "stage_not_found"

            # Fencing check: verify lease ownership, attempt number, and lease TTL did not shift.
            if (
                job.status != RunnerJobStatus.RUNNING.value
                or job.lease_owner != worker_id
                or job.attempt_count != attempt_number
                or job.lease_expires_at is None
                or job.lease_expires_at <= finish_now
            ):
                return "fenced_out"

            if requires_lease and lease_id is not None:
                released_lease = (
                    await session.execute(
                        update(ScanTargetLease)
                        .where(
                            ScanTargetLease.id == lease_id,
                            ScanTargetLease.organization_id == org_id,
                            ScanTargetLease.status == TargetLeaseStatus.ACTIVE.value,
                        )
                        .values(
                            status=(
                                TargetLeaseStatus.REVOKED.value
                                if run.status == ScanRunStatus.CANCELLING.value
                                else TargetLeaseStatus.RELEASED.value
                            ),
                            released_at=finish_now,
                        )
                        .returning(ScanTargetLease.id)
                    )
                ).scalar_one_or_none()
                if released_lease is None:
                    return "fenced_out"

            if run.status == ScanRunStatus.CANCELLING.value:
                job.status = validate_job_transition(job.status, RunnerJobStatus.CANCELLED.value)
                job.completed_at = finish_now
                job.lease_owner = None
                job.lease_expires_at = None
                await _finalize_run_cancellation(db=session, run=run, org_id=org_id, now=finish_now)
                return "cancelled"

            if (
                sim_mode == "transient_fail_once"
                and attempt_number == 1
                and attempt_number < job.max_attempts
            ):
                job.status = validate_job_transition(
                    job.status, RunnerJobStatus.RETRY_SCHEDULED.value
                )
                retry_delta = timedelta(seconds=max(0, retry_backoff_seconds))
                job.next_retry_at = finish_now + retry_delta
                job.lease_owner = None
                job.lease_expires_at = None
                job.last_error_code = "simulated_transient_failure"
                job.last_error_message = "Simulated transient orchestration error on attempt 1"
                return "retry_scheduled"

            if sim_mode == "permanent_fail":
                if attempt_number < job.max_attempts:
                    job.status = validate_job_transition(
                        job.status, RunnerJobStatus.RETRY_SCHEDULED.value
                    )
                    retry_delta = timedelta(seconds=max(0, retry_backoff_seconds))
                    job.next_retry_at = finish_now + retry_delta
                    job.lease_owner = None
                    job.lease_expires_at = None
                    job.last_error_code = "simulated_permanent_failure"
                    job.last_error_message = (
                        f"Simulated failure on attempt {attempt_number}/{job.max_attempts}"
                    )
                    return "retry_scheduled"

                job.status = validate_job_transition(job.status, RunnerJobStatus.FAILED.value)
                job.completed_at = finish_now
                job.lease_owner = None
                job.lease_expires_at = None
                job.last_error_code = "simulated_permanent_failure"
                job.last_error_message = "Exhausted bounded retry attempts"
                await _fail_stage_and_run(
                    session,
                    org_id=org_id,
                    run=run,
                    stage=stage,
                    now=finish_now,
                    error_summary=job.last_error_message,
                )
                return "failed"

            # Success completion of dummy Phase 3 orchestration job.
            job.execution_count += 1
            job.status = validate_job_transition(job.status, RunnerJobStatus.COMPLETED.value)
            job.completed_at = finish_now
            job.heartbeat_at = finish_now
            job.lease_owner = None
            job.lease_expires_at = None
            job.last_error_code = None
            job.last_error_message = None
            job.result_summary = {
                "simulated": True,
                "scanners_enabled": False,
                "findings_count": 0,
                "stage": stage.stage_key,
                "attempt_number": attempt_number,
                "completed_by": worker_id,
            }
            await session.flush()

            stage_jobs = (
                (
                    await session.execute(
                        select(RunnerJob).where(
                            RunnerJob.scan_stage_id == stage.id,
                            RunnerJob.organization_id == org_id,
                        )
                    )
                )
                .scalars()
                .all()
            )
            if all(j.status == RunnerJobStatus.COMPLETED.value for j in stage_jobs):
                stage.status = validate_stage_transition(
                    stage.status, ScanStageStatus.COMPLETED.value
                )
                stage.completed_at = finish_now
                await session.flush()
                await _advance_run_after_stage_complete(
                    session,
                    org_id=org_id,
                    run=run,
                    completed_stage=stage,
                    now=finish_now,
                )

    return "completed"


async def _fail_stage_and_run(
    session: AsyncSession,
    *,
    org_id: uuid.UUID,
    run: ScanRun,
    stage: ScanStage,
    now: datetime,
    error_summary: str,
) -> None:
    if stage.status not in {
        ScanStageStatus.COMPLETED.value,
        ScanStageStatus.FAILED.value,
        ScanStageStatus.SKIPPED.value,
        ScanStageStatus.CANCELLED.value,
    }:
        if stage.status == ScanStageStatus.PENDING.value:
            stage.status = validate_stage_transition(stage.status, ScanStageStatus.QUEUED.value)
        stage.status = validate_stage_transition(stage.status, ScanStageStatus.FAILED.value)
        stage.completed_at = now

    later_stages = (
        (
            await session.execute(
                select(ScanStage)
                .where(
                    ScanStage.scan_run_id == run.id,
                    ScanStage.organization_id == org_id,
                    ScanStage.status == ScanStageStatus.PENDING.value,
                )
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    for later in later_stages:
        later.status = validate_stage_transition(later.status, ScanStageStatus.SKIPPED.value)
        later.completed_at = now

    later_jobs = (
        (
            await session.execute(
                select(RunnerJob)
                .where(
                    RunnerJob.scan_run_id == run.id,
                    RunnerJob.organization_id == org_id,
                    RunnerJob.status == RunnerJobStatus.PENDING.value,
                )
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    for pending_job in later_jobs:
        pending_job.status = validate_job_transition(
            pending_job.status, RunnerJobStatus.CANCELLED.value
        )
        pending_job.completed_at = now

    if run.status not in RUN_TERMINAL_STATUSES:
        run.status = validate_run_transition(run.status, ScanRunStatus.FAILED.value)
        run.coverage_status = CoverageStatus.FAILED.value
        run.error_summary = error_summary
        run.completed_at = now


async def _advance_run_after_stage_complete(
    session: AsyncSession,
    *,
    org_id: uuid.UUID,
    run: ScanRun,
    completed_stage: ScanStage,
    now: datetime,
) -> None:
    next_stages = (
        (
            await session.execute(
                select(ScanStage)
                .where(
                    ScanStage.scan_run_id == run.id,
                    ScanStage.organization_id == org_id,
                    ScanStage.depends_on_stage_key == completed_stage.stage_key,
                    ScanStage.status == ScanStageStatus.PENDING.value,
                )
                .order_by(ScanStage.stage_order)
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    if next_stages:
        for next_stage in next_stages:
            next_stage.status = validate_stage_transition(
                next_stage.status, ScanStageStatus.QUEUED.value
            )
            jobs = (
                (
                    await session.execute(
                        select(RunnerJob)
                        .where(
                            RunnerJob.scan_stage_id == next_stage.id,
                            RunnerJob.organization_id == org_id,
                            RunnerJob.status == RunnerJobStatus.PENDING.value,
                        )
                        .with_for_update()
                    )
                )
                .scalars()
                .all()
            )
            for job in jobs:
                attempt = job.attempt_count + 1
                dispatch_key = f"dispatch:{job.id}:attempt:{attempt}"
                session.add(
                    OutboxEvent(
                        id=uuid.uuid4(),
                        organization_id=org_id,
                        scan_run_id=run.id,
                        runner_job_id=job.id,
                        event_type="scan.job.dispatch",
                        routing_key=DISPATCH_ROUTING_KEY,
                        idempotency_key=dispatch_key,
                        payload={
                            "event_type": "scan.job.dispatch",
                            "organization_id": str(org_id),
                            "scan_run_id": str(run.id),
                            "scan_stage_id": str(next_stage.id),
                            "runner_job_id": str(job.id),
                            "idempotency_key": job.idempotency_key,
                            "dispatch_key": dispatch_key,
                            "job_type": job.job_type,
                            "correlation_id": "",
                        },
                        status=OutboxEventStatus.PENDING.value,
                    )
                )
        return

    remaining_stages = (
        (
            await session.execute(
                select(ScanStage).where(
                    ScanStage.scan_run_id == run.id,
                    ScanStage.organization_id == org_id,
                    ScanStage.status.notin_(
                        [
                            ScanStageStatus.COMPLETED.value,
                            ScanStageStatus.FAILED.value,
                            ScanStageStatus.SKIPPED.value,
                            ScanStageStatus.CANCELLED.value,
                        ]
                    ),
                )
            )
        )
        .scalars()
        .all()
    )
    if not remaining_stages and run.status not in RUN_TERMINAL_STATUSES:
        run.status = validate_run_transition(run.status, ScanRunStatus.COMPLETED.value)
        run.coverage_status = resolve_scan_run_coverage_status(
            coverage_summary=run.coverage_summary,
            has_errors=False,
        )
        run.completed_at = now


async def reconcile_orchestration_once(
    session_factory: async_sessionmaker[AsyncSession],
    settings: Settings | None = None,
    *,
    limit: int = 100,
) -> dict[str, int]:
    """Recover due retries, expired job leases, expired target leases, and cancelling runs."""
    _ = settings
    per_kind_limit = max(1, min(limit, 250))
    due: list[tuple[str, uuid.UUID, uuid.UUID]] = []
    async with session_factory() as discovery_session:
        for work_kind_group in (
            ["target_lease_expired"],
            ["job_lease_expired"],
            ["job_retry_due"],
            ["run_cancelling_reconcile"],
        ):
            due.extend(
                await _list_due_work(
                    discovery_session,
                    limit=per_kind_limit,
                    work_kinds=work_kind_group,
                )
            )

    counts = {
        "target_leases_expired": 0,
        "job_leases_expired": 0,
        "jobs_requeued": 0,
        "runs_cancelled": 0,
    }
    now = datetime.now(UTC)

    for work_kind, record_id, org_id in due:
        if work_kind == "target_lease_expired":
            async with session_factory() as session:
                async with session.begin():
                    await set_db_context(session, org_id=org_id)
                    lease = (
                        await session.execute(
                            select(ScanTargetLease)
                            .where(
                                ScanTargetLease.id == record_id,
                                ScanTargetLease.organization_id == org_id,
                            )
                            .with_for_update(skip_locked=True)
                        )
                    ).scalar_one_or_none()
                    if (
                        lease is not None
                        and lease.status == TargetLeaseStatus.ACTIVE.value
                        and lease.expires_at <= now
                    ):
                        lease.status = TargetLeaseStatus.EXPIRED.value
                        lease.released_at = now
                        counts["target_leases_expired"] += 1

        elif work_kind == "job_lease_expired":
            async with session_factory() as session:
                async with session.begin():
                    await set_db_context(session, org_id=org_id)
                    job_ref = (
                        await session.execute(
                            select(RunnerJob.scan_run_id, RunnerJob.scan_stage_id).where(
                                RunnerJob.id == record_id,
                                RunnerJob.organization_id == org_id,
                            )
                        )
                    ).first()
                    if job_ref is None:
                        continue
                    ref_run_id, ref_stage_id = job_ref

                    # Canonical lock order: ScanRun -> ScanStage -> RunnerJob
                    run = (
                        await session.execute(
                            select(ScanRun)
                            .where(
                                ScanRun.id == ref_run_id,
                                ScanRun.organization_id == org_id,
                            )
                            .with_for_update()
                        )
                    ).scalar_one_or_none()
                    stage = (
                        await session.execute(
                            select(ScanStage)
                            .where(
                                ScanStage.id == ref_stage_id,
                                ScanStage.organization_id == org_id,
                            )
                            .with_for_update()
                        )
                    ).scalar_one_or_none()
                    job = (
                        await session.execute(
                            select(RunnerJob)
                            .where(
                                RunnerJob.id == record_id,
                                RunnerJob.organization_id == org_id,
                            )
                            .with_for_update(skip_locked=True)
                        )
                    ).scalar_one_or_none()
                    if (
                        run is None
                        or stage is None
                        or job is None
                        or job.status
                        not in {
                            RunnerJobStatus.DISPATCHED.value,
                            RunnerJobStatus.LEASED.value,
                            RunnerJobStatus.RUNNING.value,
                        }
                        or job.lease_expires_at is None
                        or job.lease_expires_at > now
                    ):
                        continue

                    await session.execute(
                        update(ScanTargetLease)
                        .where(
                            ScanTargetLease.organization_id == org_id,
                            ScanTargetLease.runner_job_id == job.id,
                            ScanTargetLease.status == TargetLeaseStatus.ACTIVE.value,
                        )
                        .values(status=TargetLeaseStatus.EXPIRED.value, released_at=now)
                    )

                    if run.status in {
                        ScanRunStatus.CANCELLING.value,
                        ScanRunStatus.CANCELLED.value,
                    }:
                        job.status = validate_job_transition(
                            job.status, RunnerJobStatus.CANCELLED.value
                        )
                        job.completed_at = now
                        job.lease_owner = None
                        job.lease_expires_at = None
                        if run.status == ScanRunStatus.CANCELLING.value:
                            await session.flush()
                            other_live = (
                                await session.execute(
                                    select(RunnerJob.id).where(
                                        RunnerJob.scan_run_id == run.id,
                                        RunnerJob.organization_id == org_id,
                                        RunnerJob.status.notin_(list(JOB_TERMINAL_STATUSES)),
                                    )
                                )
                            ).scalar_one_or_none()
                            if other_live is None:
                                await _finalize_run_cancellation(
                                    db=session, run=run, org_id=org_id, now=now
                                )
                        counts["job_leases_expired"] += 1
                        continue

                    exceeded_timeout = (
                        job.started_at is not None
                        and (now - job.started_at).total_seconds() >= job.timeout_seconds
                    )
                    exhausted_attempts = job.attempt_count >= job.max_attempts
                    if exceeded_timeout or exhausted_attempts:
                        terminal = (
                            RunnerJobStatus.TIMED_OUT.value
                            if job.started_at is not None
                            else RunnerJobStatus.ABANDONED.value
                        )
                        job.status = validate_job_transition(job.status, terminal)
                        job.completed_at = now
                        job.lease_owner = None
                        job.lease_expires_at = None
                        job.last_error_code = (
                            "job_timed_out"
                            if terminal == RunnerJobStatus.TIMED_OUT.value
                            else "job_lease_abandoned"
                        )
                        job.last_error_message = (
                            "Job execution exceeded timeout_seconds"
                            if exceeded_timeout
                            else "Worker lease expired and max attempts reached"
                        )
                        await _fail_stage_and_run(
                            session,
                            org_id=org_id,
                            run=run,
                            stage=stage,
                            now=now,
                            error_summary=job.last_error_message,
                        )
                    else:
                        job.status = validate_job_transition(
                            job.status, RunnerJobStatus.RETRY_SCHEDULED.value
                        )
                        job.next_retry_at = now
                        job.lease_owner = None
                        job.lease_expires_at = None
                        job.last_error_code = "worker_lease_expired"
                        job.last_error_message = "Worker lease expired; retry scheduled"
                    counts["job_leases_expired"] += 1

        elif work_kind == "job_retry_due":
            async with session_factory() as session:
                async with session.begin():
                    await set_db_context(session, org_id=org_id)
                    retry_ref = (
                        await session.execute(
                            select(RunnerJob.scan_run_id).where(
                                RunnerJob.id == record_id,
                                RunnerJob.organization_id == org_id,
                            )
                        )
                    ).scalar_one_or_none()
                    if retry_ref is None:
                        continue

                    # Canonical lock order: ScanRun -> RunnerJob
                    run = (
                        await session.execute(
                            select(ScanRun)
                            .where(
                                ScanRun.id == retry_ref,
                                ScanRun.organization_id == org_id,
                            )
                            .with_for_update()
                        )
                    ).scalar_one_or_none()
                    job = (
                        await session.execute(
                            select(RunnerJob)
                            .where(
                                RunnerJob.id == record_id,
                                RunnerJob.organization_id == org_id,
                            )
                            .with_for_update(skip_locked=True)
                        )
                    ).scalar_one_or_none()
                    if (
                        job is None
                        or job.status != RunnerJobStatus.RETRY_SCHEDULED.value
                        or job.next_retry_at is None
                        or job.next_retry_at > now
                    ):
                        continue
                    if (
                        run is None
                        or run.status in RUN_TERMINAL_STATUSES
                        or run.status == ScanRunStatus.CANCELLING.value
                    ):
                        job.status = validate_job_transition(
                            job.status, RunnerJobStatus.CANCELLED.value
                        )
                        job.completed_at = now
                        continue

                    next_attempt = job.attempt_count + 1
                    ts_ms = int(now.timestamp() * 1000)
                    dispatch_key = f"dispatch:{job.id}:attempt:{next_attempt}:ts:{ts_ms}"
                    job.status = validate_job_transition(job.status, RunnerJobStatus.PENDING.value)
                    job.next_retry_at = None
                    session.add(
                        OutboxEvent(
                            id=uuid.uuid4(),
                            organization_id=org_id,
                            scan_run_id=run.id,
                            runner_job_id=job.id,
                            event_type="scan.job.dispatch",
                            routing_key=DISPATCH_ROUTING_KEY,
                            idempotency_key=dispatch_key,
                            payload={
                                "event_type": "scan.job.dispatch",
                                "organization_id": str(org_id),
                                "scan_run_id": str(run.id),
                                "scan_stage_id": str(job.scan_stage_id),
                                "runner_job_id": str(job.id),
                                "idempotency_key": job.idempotency_key,
                                "dispatch_key": dispatch_key,
                                "job_type": job.job_type,
                                "correlation_id": "",
                            },
                            status=OutboxEventStatus.PENDING.value,
                        )
                    )
                    counts["jobs_requeued"] += 1

        elif work_kind == "run_cancelling_reconcile":
            async with session_factory() as session:
                async with session.begin():
                    await set_db_context(session, org_id=org_id)
                    run = (
                        await session.execute(
                            select(ScanRun)
                            .where(
                                ScanRun.id == record_id,
                                ScanRun.organization_id == org_id,
                            )
                            .with_for_update(skip_locked=True)
                        )
                    ).scalar_one_or_none()
                    if run is None or run.status != ScanRunStatus.CANCELLING.value:
                        continue
                    jobs = (
                        (
                            await session.execute(
                                select(RunnerJob)
                                .where(
                                    RunnerJob.scan_run_id == run.id,
                                    RunnerJob.organization_id == org_id,
                                )
                                .with_for_update()
                            )
                        )
                        .scalars()
                        .all()
                    )
                    still_live = False
                    for job in jobs:
                        if job.status in JOB_TERMINAL_STATUSES:
                            continue
                        if job.status in {
                            RunnerJobStatus.PENDING.value,
                            RunnerJobStatus.DISPATCHED.value,
                            RunnerJobStatus.RETRY_SCHEDULED.value,
                        } or (
                            job.status == RunnerJobStatus.LEASED.value
                            and job.execution_mode == "runner"
                            and job.claimed_by_runner_id is None
                        ):
                            job.status = validate_job_transition(
                                job.status, RunnerJobStatus.CANCELLED.value
                            )
                            job.completed_at = now
                            job.lease_owner = None
                            job.lease_expires_at = None
                        else:
                            still_live = True
                    if not still_live:
                        await _finalize_run_cancellation(
                            db=session, run=run, org_id=org_id, now=now
                        )
                        counts["runs_cancelled"] += 1

    return counts


advance_run_after_stage_complete = _advance_run_after_stage_complete
fail_stage_and_run = _fail_stage_and_run
finalize_run_cancellation = _finalize_run_cancellation
