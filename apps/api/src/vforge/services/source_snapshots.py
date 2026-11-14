"""Phase 5 immutable read-only source snapshot intake, inspection, and encrypted storage."""

from __future__ import annotations

import base64
import hashlib
import shutil
import tempfile
import uuid
from pathlib import Path
from typing import Any

from vforge_scanners import (
    UnsafeArchiveError,
    canonicalize_source_archive,
    detect_repository_languages,
    evaluate_coverage,
    safe_extract_archive_bytes,
)
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from vforge.auth.rbac import Permission, assert_permission
from vforge.config import Settings, get_settings
from vforge.errors import NotFoundError, ValidationError
from vforge.models.domain import Asset, Environment, Project
from vforge.models.enums import Role, SourceSnapshotStatus
from vforge.models.scanner import SourceSnapshot
from vforge.schemas import SourceSnapshotCreate
from vforge.security.envelope import (
    decrypt_artifact_with_keyring,
    encrypt_artifact_bytes,
    resolve_kek,
    resolve_keyring,
)
from vforge.services.audit import record_audit_event


def _snapshot_storage_path(cfg: Settings, storage_key: str) -> Path:
    root = Path(cfg.artifact_root).resolve()
    target = (root / storage_key).resolve()
    if not target.is_relative_to(root):
        raise ValidationError("Invalid source snapshot storage path")
    return target


async def create_source_snapshot(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    actor_id: uuid.UUID,
    actor_role: Role,
    payload: SourceSnapshotCreate,
    correlation_id: str | None = None,
    settings: Settings | None = None,
) -> SourceSnapshot:
    """Validate, canonicalize, analyze languages, encrypt, and persist a source snapshot."""
    assert_permission(actor_role, Permission.SOURCE_SNAPSHOT_CREATE)
    cfg = settings or get_settings()

    project = (
        await db.execute(
            select(Project).where(Project.id == project_id, Project.organization_id == org_id)
        )
    ).scalar_one_or_none()
    if project is None:
        raise NotFoundError("Project not found")

    asset = (
        await db.execute(
            select(Asset)
            .join(
                Environment,
                (Environment.id == Asset.environment_id)
                & (Environment.organization_id == Asset.organization_id),
            )
            .where(
                Asset.id == payload.asset_id,
                Asset.organization_id == org_id,
                Environment.project_id == project_id,
            )
        )
    ).scalar_one_or_none()
    if asset is None:
        raise NotFoundError("Asset not found in project")

    try:
        raw_archive = base64.b64decode(payload.content_b64, validate=True)
    except Exception as exc:  # noqa: BLE001
        raise ValidationError("Invalid base64 source archive encoding") from exc

    try:
        canonical = canonicalize_source_archive(
            raw_archive,
            source_type=payload.source_type,
            max_compressed_bytes=cfg.source_snapshot_max_archive_bytes,
            max_extracted_bytes=cfg.source_snapshot_max_extracted_bytes,
            max_files=cfg.source_snapshot_max_files,
        )
    except UnsafeArchiveError as exc:
        raise ValidationError(str(exc)) from exc

    # Inspect languages/manifests from a temp extraction without executing any scripts.
    tmp_dir = Path(tempfile.mkdtemp(prefix="vf-src-inspect-"))
    try:
        safe_extract_archive_bytes(
            canonical.canonical_tar_gz,
            tmp_dir,
            source_type="archive_tar_gz",
            max_compressed_bytes=cfg.source_snapshot_max_archive_bytes,
            max_extracted_bytes=cfg.source_snapshot_max_extracted_bytes,
            max_files=cfg.source_snapshot_max_files,
            read_only=False,
        )
        discovery = detect_repository_languages(tmp_dir)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    coverage_report = evaluate_coverage(discovery, selected_tools=("opengrep", "gitleaks"))
    archive_sha256 = hashlib.sha256(canonical.canonical_tar_gz).hexdigest()

    snap_id = uuid.uuid4()
    storage_key = f"snapshots/{org_id}/{snap_id}.tar.gz.enc"
    kek_id, kek_bytes = resolve_kek(cfg)
    aad = f"vf:v1|source_snapshot|{org_id}|{project_id}|{snap_id}|{archive_sha256}".encode("ascii")
    sealed = encrypt_artifact_bytes(
        plaintext=canonical.canonical_tar_gz,
        kek_id=kek_id,
        kek_bytes=kek_bytes,
        aad=aad,
    )

    dest_path = _snapshot_storage_path(cfg, storage_key)
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    dest_path.write_bytes(sealed.ciphertext)

    snapshot = SourceSnapshot(
        id=snap_id,
        organization_id=org_id,
        project_id=project_id,
        asset_id=asset.id,
        source_type=payload.source_type,
        commit_sha=payload.commit_sha.strip() if payload.commit_sha else None,
        branch=payload.branch.strip() if payload.branch else None,
        archive_sha256=archive_sha256,
        storage_key=storage_key,
        ciphertext_sha256=sealed.ciphertext_sha256,
        encryption_algorithm=sealed.encryption_algorithm,
        encryption_key_id=sealed.encryption_key_id,
        wrapped_dek_b64=sealed.wrapped_dek_b64,
        nonce_b64=sealed.nonce_b64,
        aad_b64=sealed.aad_b64,
        file_count=canonical.file_count,
        total_bytes=canonical.total_bytes,
        detected_languages={
            "languages": discovery.languages,
            "files_total_eligible": discovery.files_total_eligible,
            "manifests_detected": list(discovery.manifests_detected),
            "ecosystems_detected": list(discovery.ecosystems_detected),
            "excluded_directories": discovery.excluded_directories,
        },
        coverage_report=coverage_report,
        status=SourceSnapshotStatus.READY.value,
        created_by=actor_id,
    )
    db.add(snapshot)
    await db.flush()

    await record_audit_event(
        db,
        organization_id=org_id,
        actor_id=actor_id,
        action="source_snapshot.create",
        resource_type="source_snapshot",
        resource_id=snapshot.id,
        metadata={
            "project_id": str(project_id),
            "asset_id": str(asset.id),
            "archive_sha256": archive_sha256,
            "file_count": canonical.file_count,
            "coverage_status": coverage_report.get("assessment_coverage_status"),
        },
        correlation_id=correlation_id,
    )
    return snapshot


async def list_source_snapshots(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    project_id: uuid.UUID,
    actor_role: Role,
    limit: int = 50,
    offset: int = 0,
) -> tuple[list[SourceSnapshot], int]:
    """List immutable source snapshots for a project within the current tenant."""
    assert_permission(actor_role, Permission.SOURCE_SNAPSHOT_READ)
    filters: list[Any] = [
        SourceSnapshot.organization_id == org_id,
        SourceSnapshot.project_id == project_id,
    ]
    total = int(
        (await db.execute(select(func.count(SourceSnapshot.id)).where(*filters))).scalar_one()
    )
    rows = (
        (
            await db.execute(
                select(SourceSnapshot)
                .where(*filters)
                .order_by(SourceSnapshot.created_at.desc())
                .limit(limit)
                .offset(offset)
            )
        )
        .scalars()
        .all()
    )
    return list(rows), total


async def get_source_snapshot(
    db: AsyncSession,
    *,
    org_id: uuid.UUID,
    snapshot_id: uuid.UUID,
    actor_role: Role,
) -> SourceSnapshot:
    """Retrieve a single source snapshot inside the current tenant."""
    assert_permission(actor_role, Permission.SOURCE_SNAPSHOT_READ)
    snap = (
        await db.execute(
            select(SourceSnapshot).where(
                SourceSnapshot.id == snapshot_id,
                SourceSnapshot.organization_id == org_id,
            )
        )
    ).scalar_one_or_none()
    if snap is None:
        raise NotFoundError("Source snapshot not found")
    return snap


async def read_decrypted_source_snapshot_bytes(
    snapshot: SourceSnapshot,
    *,
    settings: Settings | None = None,
) -> bytes:
    """Decrypt and verify integrity of stored canonical source snapshot `.tar.gz` bytes."""
    cfg = settings or get_settings()
    src_path = _snapshot_storage_path(cfg, snapshot.storage_key)
    if not src_path.exists():
        raise NotFoundError("Stored encrypted source snapshot blob is missing")
    ciphertext = src_path.read_bytes()
    keyring = resolve_keyring(cfg)
    plaintext = decrypt_artifact_with_keyring(
        ciphertext=ciphertext,
        expected_plaintext_sha256=snapshot.archive_sha256,
        expected_ciphertext_sha256=snapshot.ciphertext_sha256,
        encryption_key_id=snapshot.encryption_key_id or keyring.active_kek_id,
        keyring=keyring.keys,
        wrapped_dek_b64=snapshot.wrapped_dek_b64,
        nonce_b64=snapshot.nonce_b64,
        aad_b64=snapshot.aad_b64,
    )
    return plaintext
