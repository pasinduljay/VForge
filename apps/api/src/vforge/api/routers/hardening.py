"""Control-plane API routes for Phase 14 Hardening, Key Rotation, Certs, and DR."""

from __future__ import annotations

from typing import Any

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
from vforge.hardening.service import (
    create_encrypted_backup_manifest,
    execute_key_rewrap_drill,
    get_certificate_posture,
    get_hardening_overview,
    register_or_rotate_key_record,
    rewrap_persisted_artifact_deks,
    run_backup_restore_drill,
)
from vforge.schemas import (
    BackupManifestCreateRequest,
    BackupManifestOut,
    EncryptionKeyRecordOut,
    EncryptionKeyRegisterRequest,
    HardeningAuditEventOut,
    HardeningOverviewOut,
    KeyRewrapDrillOut,
    KeyRewrapDrillRequest,
    PersistedDekRewrapOut,
    PersistedDekRewrapRequest,
    RestoreDrillCreateRequest,
    RestoreDrillRecordOut,
)

router = APIRouter(prefix="/api/v1/organizations/{org_id}/hardening", tags=["hardening"])


@router.get("/overview", response_model=HardeningOverviewOut)
async def hardening_overview(
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> HardeningOverviewOut:
    assert_permission(ctx.role, Permission.HARDENING_READ)
    overview = await get_hardening_overview(
        db,
        organization_id=ctx.org_id,
        settings=settings,
        actor_id=ctx.user.id,
        actor_role=ctx.role.value,
    )
    return HardeningOverviewOut(
        crypto_agility=overview["crypto_agility"],
        secret_and_runtime_posture=overview["secret_and_runtime_posture"],
        certificate_posture=overview["certificate_posture"],
        keys=[EncryptionKeyRecordOut.model_validate(k) for k in overview["keys"]],
        backup_manifests=[
            BackupManifestOut.model_validate(m) for m in overview["backup_manifests"]
        ],
        restore_drills=[
            RestoreDrillRecordOut.model_validate(d) for d in overview["restore_drills"]
        ],
        audit_events=[HardeningAuditEventOut.model_validate(e) for e in overview["audit_events"]],
    )


@router.get("/certs/posture")
async def cert_posture(
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> dict[str, Any]:
    assert_permission(ctx.role, Permission.HARDENING_READ)
    return await get_certificate_posture(
        db,
        organization_id=ctx.org_id,
        settings=settings,
        actor_id=ctx.user.id,
        actor_role=ctx.role.value,
    )


@router.post(
    "/keys",
    response_model=EncryptionKeyRecordOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def register_key_epoch(
    payload: EncryptionKeyRegisterRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> EncryptionKeyRecordOut:
    assert_permission(ctx.role, Permission.HARDENING_MANAGE)
    record = await register_or_rotate_key_record(
        db,
        organization_id=ctx.org_id,
        key_id=payload.key_id,
        purpose=payload.purpose,
        algorithm_suite=payload.algorithm_suite,
        pqc_readiness_status=payload.pqc_readiness_status,
        cryptoperiod_days=payload.cryptoperiod_days,
        key_fingerprint_sha256=payload.key_fingerprint_sha256,
        fips_validated_claim=payload.fips_validated_claim,
        pqc_experimental_custom_protocol=payload.pqc_experimental_custom_protocol,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
        actor_role=ctx.role.value,
        settings=settings,
    )
    out = EncryptionKeyRecordOut.model_validate(record)
    await db.commit()
    return out


@router.post(
    "/keys/rewrap-drill",
    response_model=KeyRewrapDrillOut,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def key_rewrap_drill(
    payload: KeyRewrapDrillRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> KeyRewrapDrillOut:
    assert_permission(ctx.role, Permission.HARDENING_MANAGE)
    res = await execute_key_rewrap_drill(
        db,
        organization_id=ctx.org_id,
        new_kek_id=payload.new_kek_id,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
        actor_role=ctx.role.value,
        settings=settings,
    )
    await db.commit()
    return KeyRewrapDrillOut(**res)


@router.post(
    "/keys/rewrap-persisted",
    response_model=PersistedDekRewrapOut,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def rewrap_persisted_deks(
    payload: PersistedDekRewrapRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> PersistedDekRewrapOut:
    assert_permission(ctx.role, Permission.HARDENING_MANAGE)
    res = await rewrap_persisted_artifact_deks(
        db,
        organization_id=ctx.org_id,
        source_key_id=payload.source_key_id,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
        actor_role=ctx.role.value,
        settings=settings,
    )
    await db.commit()
    return PersistedDekRewrapOut(**res)


@router.post(
    "/backups",
    response_model=BackupManifestOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def create_backup_manifest(
    payload: BackupManifestCreateRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> BackupManifestOut:
    assert_permission(ctx.role, Permission.HARDENING_MANAGE)
    manifest = await create_encrypted_backup_manifest(
        db,
        organization_id=ctx.org_id,
        backup_scope=payload.backup_scope,
        rpo_target_minutes=payload.rpo_target_minutes,
        rto_target_minutes=payload.rto_target_minutes,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
        actor_role=ctx.role.value,
        settings=settings,
    )
    out = BackupManifestOut.model_validate(manifest)
    await db.commit()
    return out


@router.post(
    "/drills",
    response_model=RestoreDrillRecordOut,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(enforce_sensitive_rate_limit)],
)
async def trigger_restore_drill(
    payload: RestoreDrillCreateRequest,
    ctx: TenantContext = Depends(get_tenant_context),  # noqa: B008
    db: AsyncSession = Depends(get_db),  # noqa: B008
    settings: Settings = Depends(get_settings),  # noqa: B008
) -> RestoreDrillRecordOut:
    assert_permission(ctx.role, Permission.HARDENING_MANAGE)
    drill = await run_backup_restore_drill(
        db,
        organization_id=ctx.org_id,
        manifest_id=payload.manifest_id,
        drill_mode=payload.drill_mode,
        actor_id=ctx.user.id,
        actor_email=ctx.user.email,
        actor_role=ctx.role.value,
        settings=settings,
    )
    out = RestoreDrillRecordOut.model_validate(drill)
    await db.commit()
    return out
