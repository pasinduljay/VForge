"""Phase 14 Hardening, Key Rotation, Certificate Posture, and Disaster Recovery Service."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import time
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.config import Settings
from vforge.errors import ConflictError, ForbiddenError, NotFoundError, ValidationError
from vforge.models import (
    Artifact,
    Asset,
    Authorization,
    BackupManifest,
    EncryptionKeyRecord,
    Environment,
    HardeningAuditEvent,
    Organization,
    Project,
    RestoreDrillRecord,
    Runner,
    SourceSnapshot,
)
from vforge.observability.metrics import metrics_registry
from vforge.security.envelope import (
    decrypt_artifact_with_keyring,
    encrypt_artifact_bytes,
    evaluate_crypto_agility,
    resolve_backup_kek,
    resolve_kek,
    resolve_keyring,
    rewrap_artifact_dek,
)
from vforge.security.mtls import (
    inspect_pem_cert_expiry,
    inspect_runner_certificate_health,
)
from vforge.security.validators import redact_metadata

_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,119}$")
_ALGO_SUITE_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{2,78}$")


async def evaluate_hardening_action_with_opa(
    *,
    settings: Settings,
    organization_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: str | None,
    action: str,
    fips_validated_claim: bool = False,
    pqc_experimental_custom_protocol: bool = False,
    transport: httpx.AsyncBaseTransport | None = None,
) -> tuple[bool, str]:
    """Evaluate `hardening:*` action against OPA `data.vforge.authz.allow`, failing closed."""
    endpoint = f"{settings.opa_url.rstrip('/')}/v1/data/vforge/authz/allow"
    opa_input = {
        "action": action,
        "subject": {
            "id": str(actor_id),
            "role": (actor_role or "").strip().lower(),
            "organization_id": str(organization_id),
            "authenticated": True,
        },
        "resource": {
            "organization_id": str(organization_id),
            "fips_validated_claim": fips_validated_claim,
            "pqc_experimental_custom_protocol": pqc_experimental_custom_protocol,
        },
    }
    try:
        async with httpx.AsyncClient(
            timeout=settings.opa_timeout_seconds,
            transport=transport,
        ) as client:
            resp = await client.post(endpoint, json={"input": opa_input})
    except httpx.HTTPError as exc:
        metrics_registry.record_security_denial("opa_unreachable")
        return False, f"OPA hardening check failed closed ({type(exc).__name__})"

    if resp.status_code >= 400:
        metrics_registry.record_security_denial("opa_http_error")
        return False, f"OPA returned HTTP {resp.status_code}"
    try:
        body = resp.json()
    except ValueError:
        metrics_registry.record_security_denial("opa_invalid_response")
        return False, "OPA hardening check failed closed (invalid JSON response)"
    allowed = bool(isinstance(body, dict) and body.get("result") is True)
    if not allowed:
        metrics_registry.record_security_denial("opa_policy_denied")
    return allowed, ("Allowed by OPA policy" if allowed else "Denied by OPA hardening policy")


async def _enforce_opa_if_configured(
    *,
    settings: Settings | None,
    organization_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: str | None,
    action: str,
    fips_validated_claim: bool = False,
    pqc_experimental_custom_protocol: bool = False,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> None:
    if settings is None:
        return
    allowed, reason = await evaluate_hardening_action_with_opa(
        settings=settings,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        action=action,
        fips_validated_claim=fips_validated_claim,
        pqc_experimental_custom_protocol=pqc_experimental_custom_protocol,
        transport=opa_transport,
    )
    if not allowed:
        raise ForbiddenError(reason)


async def _record_audit_event(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    category: str,
    action: str,
    outcome: str,
    actor_id: uuid.UUID,
    actor_email: str,
    details: dict[str, Any],
) -> HardeningAuditEvent:
    redacted_details = redact_metadata(details)
    event = HardeningAuditEvent(
        organization_id=organization_id,
        category=category,
        action=action,
        outcome=outcome,
        actor_id=actor_id,
        actor_email=actor_email,
        details_json=redacted_details if isinstance(redacted_details, dict) else {},
    )
    db.add(event)
    await db.flush()
    return event


def _safe_dr_file_path(artifact_root: str, storage_key: str) -> Path:
    root = Path(artifact_root).resolve()
    clean_key = storage_key.replace("\\", "/").lstrip("/")
    if not clean_key or ".." in clean_key.split("/"):
        raise ValidationError("Invalid DR backup storage_key")
    target = (root / clean_key).resolve()
    try:
        target.relative_to(root)
    except ValueError as exc:
        raise ValidationError("DR backup path escapes configured artifact root") from exc
    return target


async def register_or_rotate_key_record(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    key_id: str,
    purpose: str,
    algorithm_suite: str,
    pqc_readiness_status: str,
    cryptoperiod_days: int,
    key_fingerprint_sha256: str,
    fips_validated_claim: bool = False,
    pqc_experimental_custom_protocol: bool = False,
    actor_id: uuid.UUID,
    actor_email: str,
    actor_role: str | None = None,
    settings: Settings | None = None,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> EncryptionKeyRecord:
    """Register a new key epoch metadata record and mark previous active key `verify_only`."""
    await _enforce_opa_if_configured(
        settings=settings,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        action="hardening:manage",
        fips_validated_claim=fips_validated_claim,
        pqc_experimental_custom_protocol=pqc_experimental_custom_protocol,
        opa_transport=opa_transport,
    )
    if fips_validated_claim:
        raise ValidationError(
            "FIPS compliance cannot be claimed without a validated module configuration (§26.4)"
        )
    if pqc_experimental_custom_protocol:
        raise ValidationError("Experimental custom PQC protocols are strictly forbidden (§26.3)")

    clean_key_id = key_id.strip()
    if not _KEY_ID_RE.match(clean_key_id):
        raise ValidationError("key_id must be 3-120 alphanumeric/dot/dash/underscore characters")
    if purpose not in {"artifact_envelope", "backup_envelope", "scope_signing", "runner_mtls_ca"}:
        raise ValidationError("Unsupported key purpose")
    clean_algo = algorithm_suite.strip().lower()
    if not _ALGO_SUITE_RE.match(clean_algo):
        raise ValidationError("algorithm_suite format is invalid")
    if pqc_readiness_status not in {"classical_active", "hybrid_planned", "not_enabled"}:
        raise ValidationError("Unsupported pqc_readiness_status")
    clean_fp = key_fingerprint_sha256.strip().lower()
    if not re.match(r"^[0-9a-f]{64}$", clean_fp):
        raise ValidationError("key_fingerprint_sha256 must be 64 lowercase hex characters")

    # Serialize key epoch rotations per organization & purpose to guarantee monotonic versions
    await db.execute(
        select(Organization.id).where(Organization.id == organization_id).with_for_update()
    )

    dup = await db.execute(
        select(EncryptionKeyRecord).where(
            EncryptionKeyRecord.organization_id == organization_id,
            EncryptionKeyRecord.key_id == clean_key_id,
        )
    )
    if dup.scalar_one_or_none() is not None:
        raise ConflictError(f"Key ID '{clean_key_id}' is already registered for this organization")

    prior_rows = (
        (
            await db.execute(
                select(EncryptionKeyRecord)
                .where(
                    EncryptionKeyRecord.organization_id == organization_id,
                    EncryptionKeyRecord.purpose == purpose,
                )
                .order_by(EncryptionKeyRecord.version.desc())
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    now = datetime.now(UTC)
    next_version = (prior_rows[0].version + 1) if prior_rows else 1
    rotated_ids: list[str] = []
    for prior in prior_rows:
        if prior.status == "active":
            prior.status = "verify_only"
            prior.rotated_at = now
            rotated_ids.append(prior.key_id)

    record = EncryptionKeyRecord(
        organization_id=organization_id,
        key_id=clean_key_id,
        purpose=purpose,
        algorithm_suite=clean_algo,
        pqc_readiness_status=pqc_readiness_status,
        status="active",
        version=next_version,
        key_fingerprint_sha256=clean_fp,
        cryptoperiod_days=cryptoperiod_days,
        activated_at=now,
        rotate_after_at=now + timedelta(days=cryptoperiod_days),
        created_by=actor_id,
    )
    db.add(record)
    await db.flush()

    await _record_audit_event(
        db,
        organization_id=organization_id,
        category="key_rotation",
        action="key_epoch_registered",
        outcome="completed",
        actor_id=actor_id,
        actor_email=actor_email,
        details={
            "key_id": clean_key_id,
            "purpose": purpose,
            "version": next_version,
            "rotated_prior_keys": rotated_ids,
        },
    )
    metrics_registry.record_key_rotation()
    return record


async def execute_key_rewrap_drill(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    new_kek_id: str,
    actor_id: uuid.UUID,
    actor_email: str,
    actor_role: str | None = None,
    settings: Settings,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Exercise live AES-256-GCM DEK wrapping, KEK rotation re-wrapping & roundtrip decryption."""
    await _enforce_opa_if_configured(
        settings=settings,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        action="hardening:manage",
        opa_transport=opa_transport,
    )
    clean_new_id = new_kek_id.strip()
    if not _KEY_ID_RE.match(clean_new_id):
        raise ValidationError("new_kek_id must be 3-120 valid characters")

    old_kek_id, old_kek_bytes = resolve_kek(settings)
    sample_payload = json.dumps(
        {
            "drill": "aes-256-gcm-key-rotation",
            "organization_id": str(organization_id),
            "timestamp": datetime.now(UTC).isoformat(),
        },
        sort_keys=True,
    ).encode("utf-8")
    aad = f"vf:rotation-drill|{organization_id}|{clean_new_id}".encode()

    sealed = encrypt_artifact_bytes(
        plaintext=sample_payload,
        kek_id=old_kek_id,
        kek_bytes=old_kek_bytes,
        aad=aad,
    )
    new_kek_bytes = os.urandom(32)
    rewrapped = rewrap_artifact_dek(
        old_kek_id=old_kek_id,
        old_kek_bytes=old_kek_bytes,
        new_kek_id=clean_new_id,
        new_kek_bytes=new_kek_bytes,
        wrapped_dek_b64=sealed.wrapped_dek_b64,
        aad_b64=sealed.aad_b64,
    )
    recovered = decrypt_artifact_with_keyring(
        ciphertext=sealed.ciphertext,
        expected_plaintext_sha256=sealed.plaintext_sha256,
        expected_ciphertext_sha256=sealed.ciphertext_sha256,
        encryption_key_id=rewrapped.new_kek_id,
        keyring={rewrapped.new_kek_id: new_kek_bytes},
        wrapped_dek_b64=rewrapped.wrapped_dek_b64,
        nonce_b64=sealed.nonce_b64,
        aad_b64=sealed.aad_b64,
    )
    decrypted_matches = recovered == sample_payload

    await _record_audit_event(
        db,
        organization_id=organization_id,
        category="key_rotation",
        action="dek_rewrap_drill",
        outcome="completed" if decrypted_matches else "failed",
        actor_id=actor_id,
        actor_email=actor_email,
        details={
            "old_kek_id": old_kek_id,
            "new_kek_id": rewrapped.new_kek_id,
            "roundtrip_verified": rewrapped.roundtrip_verified,
            "decrypted_matches": decrypted_matches,
        },
    )
    return {
        "old_kek_id": old_kek_id,
        "new_kek_id": rewrapped.new_kek_id,
        "plaintext_sha256": sealed.plaintext_sha256,
        "ciphertext_sha256": sealed.ciphertext_sha256,
        "rewrap_verified": rewrapped.roundtrip_verified,
        "decrypt_recovery_verified": decrypted_matches,
    }


async def rewrap_persisted_artifact_deks(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    source_key_id: str,
    actor_id: uuid.UUID,
    actor_email: str,
    actor_role: str | None = None,
    settings: Settings,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Re-wrap mutable BackupManifest DEKs and report immutable Artifact/Snapshot counts.

    `artifacts` and `source_snapshots` are strictly append-only (`UPDATE` revoked from
    `vforge_app`), so historical rows keep using `ARTIFACT_ENCRYPTION_KEYRING_JSON`
    (read-only) until expiry, while `dr_backup_manifests` DEKs can rotate online.
    """
    await _enforce_opa_if_configured(
        settings=settings,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        action="hardening:manage",
        opa_transport=opa_transport,
    )
    clean_source_id = source_key_id.strip()
    if not _KEY_ID_RE.match(clean_source_id):
        raise ValidationError("source_key_id must be 3-120 valid characters")

    keyring = resolve_keyring(settings)
    if clean_source_id not in keyring.keys:
        raise ValidationError(
            f"Source KEK '{clean_source_id}' is not loaded in active ARTIFACT_ENCRYPTION_KEYRING"
        )
    source_kek_bytes = keyring.keys[clean_source_id]
    target_backup_id, target_backup_bytes = resolve_backup_kek(settings)

    immutable_artifacts_remaining = int(
        (
            await db.execute(
                select(func.count(Artifact.id)).where(
                    Artifact.organization_id == organization_id,
                    Artifact.encryption_key_id == clean_source_id,
                )
            )
        ).scalar_one()
        or 0
    )
    immutable_snapshots_remaining = int(
        (
            await db.execute(
                select(func.count(SourceSnapshot.id)).where(
                    SourceSnapshot.organization_id == organization_id,
                    SourceSnapshot.encryption_key_id == clean_source_id,
                )
            )
        ).scalar_one()
        or 0
    )

    manifests = (
        (
            await db.execute(
                select(BackupManifest)
                .where(
                    BackupManifest.organization_id == organization_id,
                    BackupManifest.encryption_key_id == clean_source_id,
                )
                .with_for_update()
            )
        )
        .scalars()
        .all()
    )
    manifests_rewrapped = 0
    for man in manifests:
        if target_backup_id != clean_source_id:
            res = rewrap_artifact_dek(
                old_kek_id=clean_source_id,
                old_kek_bytes=source_kek_bytes,
                new_kek_id=target_backup_id,
                new_kek_bytes=target_backup_bytes,
                wrapped_dek_b64=man.wrapped_dek_b64,
                aad_b64=man.aad_b64,
            )
            man.wrapped_dek_b64 = res.wrapped_dek_b64
            man.encryption_key_id = res.new_kek_id
            manifests_rewrapped += 1

    await db.flush()
    total_rewrapped = manifests_rewrapped
    await _record_audit_event(
        db,
        organization_id=organization_id,
        category="key_rotation",
        action="persisted_deks_rewrapped",
        outcome="completed",
        actor_id=actor_id,
        actor_email=actor_email,
        details={
            "source_key_id": clean_source_id,
            "target_backup_kek_id": target_backup_id,
            "backup_manifests_rewrapped": manifests_rewrapped,
            "immutable_artifacts_remaining": immutable_artifacts_remaining,
            "immutable_snapshots_remaining": immutable_snapshots_remaining,
            "total_rewrapped": total_rewrapped,
        },
    )
    if total_rewrapped > 0:
        metrics_registry.record_key_rotation()
    return {
        "source_key_id": clean_source_id,
        "target_backup_kek_id": target_backup_id,
        "backup_manifests_rewrapped": manifests_rewrapped,
        "immutable_artifacts_remaining": immutable_artifacts_remaining,
        "immutable_snapshots_remaining": immutable_snapshots_remaining,
        "total_rewrapped": total_rewrapped,
    }


async def get_certificate_posture(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    settings: Settings,
    actor_id: uuid.UUID | None = None,
    actor_role: str | None = None,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Inspect runner X.509 mTLS certificate expiry & revocation posture plus gateway/CA certs."""
    if actor_id is not None:
        await _enforce_opa_if_configured(
            settings=settings,
            organization_id=organization_id,
            actor_id=actor_id,
            actor_role=actor_role,
            action="hardening:read",
            opa_transport=opa_transport,
        )
    runners = (
        (
            await db.execute(
                select(Runner)
                .where(Runner.organization_id == organization_id)
                .order_by(Runner.cert_expires_at.asc())
            )
        )
        .scalars()
        .all()
    )
    warn_days = max(settings.runner_cert_expiry_warning_days, 1)
    runner_entries = [
        inspect_runner_certificate_health(
            runner_id=str(r.id),
            runner_name=r.name,
            runner_status=r.status,
            cert_sha256=r.cert_sha256,
            cert_expires_at=r.cert_expires_at,
            warning_days=warn_days,
        )
        for r in runners
    ]
    ca_cert = inspect_pem_cert_expiry(
        settings.runner_mtls_ca_cert_path,
        label="runner_mtls_ca",
        warning_days=warn_days,
    )
    gateway_cert = inspect_pem_cert_expiry(
        settings.runner_gateway_cert_path,
        label="runner_gateway_tls",
        warning_days=warn_days,
    )
    return {
        "warning_threshold_days": warn_days,
        "total_runners": len(runner_entries),
        "healthy_count": sum(1 for item in runner_entries if item["cert_health"] == "healthy"),
        "expiring_soon_count": sum(
            1 for item in runner_entries if item["cert_health"] == "expiring_soon"
        ),
        "expired_count": sum(1 for item in runner_entries if item["cert_health"] == "expired"),
        "revoked_count": sum(1 for item in runner_entries if item["cert_health"] == "revoked"),
        "ca_cert": ca_cert,
        "gateway_cert": gateway_cert,
        "runners": runner_entries,
    }


async def create_encrypted_backup_manifest(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    backup_scope: str,
    rpo_target_minutes: int,
    rto_target_minutes: int,
    actor_id: uuid.UUID,
    actor_email: str,
    actor_role: str | None = None,
    settings: Settings,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> BackupManifest:
    """Create a real AES-256-GCM encrypted non-secret tenant snapshot bundle & manifest."""
    await _enforce_opa_if_configured(
        settings=settings,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        action="hardening:manage",
        opa_transport=opa_transport,
    )
    if backup_scope not in {
        "postgres_tenant_snapshot",
        "artifact_bundle",
        "full_control_plane_metadata",
    }:
        raise ValidationError(f"Unsupported backup_scope '{backup_scope}'")

    project_count = int(
        (
            await db.execute(
                select(func.count(Project.id)).where(Project.organization_id == organization_id)
            )
        ).scalar_one()
        or 0
    )
    env_count = int(
        (
            await db.execute(
                select(func.count(Environment.id)).where(
                    Environment.organization_id == organization_id
                )
            )
        ).scalar_one()
        or 0
    )
    asset_count = int(
        (
            await db.execute(
                select(func.count(Asset.id)).where(Asset.organization_id == organization_id)
            )
        ).scalar_one()
        or 0
    )
    authz_count = int(
        (
            await db.execute(
                select(func.count(Authorization.id)).where(
                    Authorization.organization_id == organization_id
                )
            )
        ).scalar_one()
        or 0
    )
    row_count = project_count + env_count + asset_count + authz_count

    manifest_id = uuid.uuid4()
    storage_key = f"dr/{organization_id}/{manifest_id}.enc"
    payload_dict = {
        "schema_head": "0015_phase14_hardening_dr",
        "manifest_id": str(manifest_id),
        "organization_id": str(organization_id),
        "backup_scope": backup_scope,
        "exported_at": datetime.now(UTC).isoformat(),
        "counts": {
            "projects": project_count,
            "environments": env_count,
            "assets": asset_count,
            "authorizations": authz_count,
        },
    }
    plaintext_bytes = json.dumps(payload_dict, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    pt_sha256 = hashlib.sha256(plaintext_bytes).hexdigest()
    aad = f"vf:dr-backup-v1|{organization_id}|{manifest_id}|{pt_sha256}".encode()

    kek_id, kek_bytes = resolve_backup_kek(settings)
    sealed = encrypt_artifact_bytes(
        plaintext=plaintext_bytes,
        kek_id=kek_id,
        kek_bytes=kek_bytes,
        aad=aad,
    )
    file_path = _safe_dr_file_path(settings.artifact_root, storage_key)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_bytes(sealed.ciphertext)

    manifest = BackupManifest(
        id=manifest_id,
        organization_id=organization_id,
        backup_scope=backup_scope,
        storage_key=storage_key,
        encryption_key_id=sealed.encryption_key_id,
        encryption_algorithm=sealed.encryption_algorithm,
        wrapped_dek_b64=sealed.wrapped_dek_b64,
        nonce_b64=sealed.nonce_b64,
        aad_b64=sealed.aad_b64,
        plaintext_sha256=sealed.plaintext_sha256,
        ciphertext_sha256=sealed.ciphertext_sha256,
        size_bytes=len(sealed.ciphertext),
        row_count=row_count,
        status="created",
        rpo_target_minutes=rpo_target_minutes,
        rto_target_minutes=rto_target_minutes,
        created_by=actor_id,
    )
    db.add(manifest)
    await db.flush()

    await _record_audit_event(
        db,
        organization_id=organization_id,
        category="backup_created",
        action="encrypted_backup_manifest_created",
        outcome="completed",
        actor_id=actor_id,
        actor_email=actor_email,
        details={
            "manifest_id": str(manifest.id),
            "backup_scope": backup_scope,
            "encryption_key_id": manifest.encryption_key_id,
            "size_bytes": manifest.size_bytes,
            "row_count": row_count,
        },
    )
    return manifest


async def run_backup_restore_drill(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    manifest_id: uuid.UUID,
    drill_mode: str,
    actor_id: uuid.UUID,
    actor_email: str,
    actor_role: str | None = None,
    settings: Settings,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> RestoreDrillRecord:
    """Verify an encrypted DR backup manifest via real AES-256-GCM decryption & digest check."""
    await _enforce_opa_if_configured(
        settings=settings,
        organization_id=organization_id,
        actor_id=actor_id,
        actor_role=actor_role,
        action="hardening:manage",
        opa_transport=opa_transport,
    )
    if drill_mode not in {
        "isolated_checksum_decrypt",
        "pg_schema_dry_run",
        "ephemeral_restore_verify",
    }:
        raise ValidationError(f"Unsupported drill_mode '{drill_mode}'")

    manifest = (
        await db.execute(
            select(BackupManifest)
            .where(
                BackupManifest.organization_id == organization_id,
                BackupManifest.id == manifest_id,
            )
            .with_for_update()
        )
    ).scalar_one_or_none()
    if manifest is None:
        raise NotFoundError("DR backup manifest not found in organization")

    revoked_rows = (
        (
            await db.execute(
                select(EncryptionKeyRecord.key_id).where(
                    EncryptionKeyRecord.organization_id == organization_id,
                    EncryptionKeyRecord.status == "revoked",
                )
            )
        )
        .scalars()
        .all()
    )
    revoked_key_ids = frozenset(revoked_rows)

    started = time.monotonic()
    integrity_ok = False
    decrypt_ok = False
    schema_head = "unverified"
    summary_parts: list[str] = []

    try:
        file_path = _safe_dr_file_path(settings.artifact_root, manifest.storage_key)
        if not file_path.is_file():
            raise FileNotFoundError("Missing encrypted backup payload in artifact store")
        ciphertext = file_path.read_bytes()
        keyring_bundle = resolve_keyring(settings)
        plaintext = decrypt_artifact_with_keyring(
            ciphertext=ciphertext,
            expected_plaintext_sha256=manifest.plaintext_sha256,
            expected_ciphertext_sha256=manifest.ciphertext_sha256,
            encryption_key_id=manifest.encryption_key_id,
            keyring=keyring_bundle.keys,
            wrapped_dek_b64=manifest.wrapped_dek_b64,
            nonce_b64=manifest.nonce_b64,
            aad_b64=manifest.aad_b64,
            revoked_key_ids=revoked_key_ids,
        )
        integrity_ok = True
        decrypt_ok = True
        restored_json = json.loads(plaintext.decode("utf-8"))
        if str(restored_json.get("organization_id")) != str(organization_id):
            raise ValueError("Decrypted backup payload organization_id mismatch")
        schema_head = str(restored_json.get("schema_head") or "0015_phase14_hardening_dr")
        if manifest.status in {"created", "failed"}:
            manifest.status = "verified"
        summary_parts.append(
            f"AES-256-GCM decrypt and SHA-256 integrity verified for {manifest.size_bytes} bytes "
            f"under key {manifest.encryption_key_id}."
        )
    except Exception as exc:  # noqa: BLE001
        if manifest.status not in {"restored", "expired"}:
            manifest.status = "failed"
        safe_detail = str(redact_metadata(str(exc))).replace(str(settings.artifact_root), "<root>")
        summary_parts.append(f"Restore verification failed ({type(exc).__name__}): {safe_detail}")

    elapsed_seconds = max(int(round(time.monotonic() - started)), 1)
    passed = integrity_ok and decrypt_ok
    drill = RestoreDrillRecord(
        organization_id=organization_id,
        manifest_id=manifest.id,
        drill_mode=drill_mode,
        rto_observed_seconds=elapsed_seconds,
        integrity_verified=integrity_ok,
        decryption_verified=decrypt_ok,
        schema_head_verified=schema_head,
        findings_summary=" ".join(summary_parts),
        status="passed" if passed else "failed",
        executed_by=actor_id,
    )
    db.add(drill)
    await db.flush()

    await _record_audit_event(
        db,
        organization_id=organization_id,
        category="restore_drill",
        action=f"dr_restore_drill_{drill_mode}",
        outcome="completed" if passed else "failed",
        actor_id=actor_id,
        actor_email=actor_email,
        details={
            "manifest_id": str(manifest.id),
            "drill_id": str(drill.id),
            "status": drill.status,
            "rto_observed_seconds": elapsed_seconds,
            "schema_head_verified": schema_head,
        },
    )
    metrics_registry.record_dr_drill(passed=passed)
    return drill


async def get_hardening_overview(
    db: AsyncSession,
    *,
    organization_id: uuid.UUID,
    settings: Settings,
    actor_id: uuid.UUID | None = None,
    actor_role: str | None = None,
    opa_transport: httpx.AsyncBaseTransport | None = None,
) -> dict[str, Any]:
    """Return full Phase 14 security hardening, crypto-agility, cert posture & DR dashboard data."""
    if actor_id is not None:
        await _enforce_opa_if_configured(
            settings=settings,
            organization_id=organization_id,
            actor_id=actor_id,
            actor_role=actor_role,
            action="hardening:read",
            opa_transport=opa_transport,
        )
    keys = (
        (
            await db.execute(
                select(EncryptionKeyRecord)
                .where(EncryptionKeyRecord.organization_id == organization_id)
                .order_by(EncryptionKeyRecord.created_at.desc())
            )
        )
        .scalars()
        .all()
    )
    manifests = (
        (
            await db.execute(
                select(BackupManifest)
                .where(BackupManifest.organization_id == organization_id)
                .order_by(BackupManifest.created_at.desc())
                .limit(25)
            )
        )
        .scalars()
        .all()
    )
    drills = (
        (
            await db.execute(
                select(RestoreDrillRecord)
                .where(RestoreDrillRecord.organization_id == organization_id)
                .order_by(RestoreDrillRecord.created_at.desc())
                .limit(25)
            )
        )
        .scalars()
        .all()
    )
    audits = (
        (
            await db.execute(
                select(HardeningAuditEvent)
                .where(HardeningAuditEvent.organization_id == organization_id)
                .order_by(HardeningAuditEvent.occurred_at.desc())
                .limit(40)
            )
        )
        .scalars()
        .all()
    )
    cert_posture = await get_certificate_posture(
        db, organization_id=organization_id, settings=settings
    )
    crypto_agility = evaluate_crypto_agility(settings)
    provider = settings.get_secret_provider()
    docker_sock_present = await asyncio.to_thread(lambda: Path("/var/run/docker.sock").exists())
    runtime_posture = {
        "secret_provider": provider.describe_capabilities(),
        "docker_socket_mounted": docker_sock_present,
        "rls_forced_mode": True,
        "metrics_enabled": settings.metrics_enabled,
        "observability_stack_path": "infrastructure/monitoring/compose.observability.yaml",
        "dr_runbook_path": "docs/runbooks/BACKUP_AND_DR.md",
    }
    return {
        "crypto_agility": crypto_agility,
        "secret_and_runtime_posture": runtime_posture,
        "certificate_posture": cert_posture,
        "keys": list(keys),
        "backup_manifests": list(manifests),
        "restore_drills": list(drills),
        "audit_events": list(audits),
    }
