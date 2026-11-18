"""Phase 14 cryptographic key-epoch registry, DR backup manifests, drills, and audit models."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKeyConstraint,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from vforge.db import Base


class EncryptionKeyRecord(Base):
    """Non-secret metadata registry for KEK epochs, signing keys, and PQC readiness.

    Key material is NEVER stored inside PostgreSQL (`§26.2`); only key IDs,
    public fingerprints/digests, algorithm agility descriptors, cryptoperiod
    schedules, and rotation status are recorded here.
    """

    __tablename__ = "encryption_key_records"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
            name="fk_ekr_org",
        ),
        UniqueConstraint("organization_id", "key_id", name="uq_ekr_org_key_id"),
        CheckConstraint(
            "purpose IN ("
            "'artifact_envelope', 'backup_envelope', 'scope_signing', 'runner_mtls_ca'"
            ")",
            name="ck_ekr_purpose",
        ),
        CheckConstraint(
            "pqc_readiness_status IN ('classical_active', 'hybrid_planned', 'not_enabled')",
            name="ck_ekr_pqc_status",
        ),
        CheckConstraint(
            "status IN ('active', 'verify_only', 'rotated_out', 'revoked')",
            name="ck_ekr_status",
        ),
        CheckConstraint("version >= 1", name="ck_ekr_version_pos"),
        CheckConstraint("cryptoperiod_days >= 1", name="ck_ekr_cryptoperiod_pos"),
        Index("ix_ekr_org_purpose_status", "organization_id", "purpose", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    key_id: Mapped[str] = mapped_column(String(120), nullable=False)
    purpose: Mapped[str] = mapped_column(String(40), nullable=False)
    algorithm_suite: Mapped[str] = mapped_column(String(80), nullable=False)
    pqc_readiness_status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="classical_active",
        server_default=text("'classical_active'"),
    )
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="active", server_default=text("'active'")
    )
    version: Mapped[int] = mapped_column(
        Integer, nullable=False, default=1, server_default=text("1")
    )
    key_fingerprint_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    owner_role: Mapped[str] = mapped_column(
        String(64), nullable=False, default="security_ops", server_default=text("'security_ops'")
    )
    cryptoperiod_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=90, server_default=text("90")
    )
    activated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    rotate_after_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    rotated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class BackupManifest(Base):
    """Tenant-scoped AES-256-GCM encrypted backup bundle manifest for DR verification."""

    __tablename__ = "dr_backup_manifests"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
            name="fk_dbm_org",
        ),
        UniqueConstraint("organization_id", "id", name="uq_dbm_org_id_id"),
        CheckConstraint(
            "backup_scope IN ("
            "'postgres_tenant_snapshot', 'artifact_bundle', 'full_control_plane_metadata'"
            ")",
            name="ck_dbm_scope",
        ),
        CheckConstraint(
            "status IN ('created', 'verified', 'restored', 'failed', 'expired')",
            name="ck_dbm_status",
        ),
        CheckConstraint("size_bytes >= 0", name="ck_dbm_size_nonneg"),
        CheckConstraint("row_count >= 0", name="ck_dbm_rows_nonneg"),
        Index("ix_dbm_org_created", "organization_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    backup_scope: Mapped[str] = mapped_column(String(48), nullable=False)
    storage_key: Mapped[str] = mapped_column(String(255), nullable=False)
    encryption_key_id: Mapped[str] = mapped_column(String(120), nullable=False)
    encryption_algorithm: Mapped[str] = mapped_column(
        String(32), nullable=False, default="AES-256-GCM", server_default=text("'AES-256-GCM'")
    )
    wrapped_dek_b64: Mapped[str] = mapped_column(Text, nullable=False)
    nonce_b64: Mapped[str] = mapped_column(String(64), nullable=False)
    aad_b64: Mapped[str] = mapped_column(Text, nullable=False)
    plaintext_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    ciphertext_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(
        BigInteger, nullable=False, default=0, server_default=text("0")
    )
    row_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    status: Mapped[str] = mapped_column(
        String(24), nullable=False, default="created", server_default=text("'created'")
    )
    rpo_target_minutes: Mapped[int] = mapped_column(
        Integer, nullable=False, default=60, server_default=text("60")
    )
    rto_target_minutes: Mapped[int] = mapped_column(
        Integer, nullable=False, default=30, server_default=text("30")
    )
    created_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class RestoreDrillRecord(Base):
    """Immutable append-only DR restore and integrity verification drill record."""

    __tablename__ = "dr_restore_drills"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "manifest_id"],
            ["dr_backup_manifests.organization_id", "dr_backup_manifests.id"],
            ondelete="RESTRICT",
            name="fk_drd_org_manifest",
        ),
        CheckConstraint(
            "drill_mode IN ("
            "'isolated_checksum_decrypt', 'pg_schema_dry_run', 'ephemeral_restore_verify'"
            ")",
            name="ck_drd_mode",
        ),
        CheckConstraint("status IN ('passed', 'failed')", name="ck_drd_status"),
        Index("ix_drd_org_created", "organization_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    manifest_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    drill_mode: Mapped[str] = mapped_column(String(48), nullable=False)
    rto_observed_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    integrity_verified: Mapped[bool] = mapped_column(Boolean, nullable=False)
    decryption_verified: Mapped[bool] = mapped_column(Boolean, nullable=False)
    schema_head_verified: Mapped[str] = mapped_column(String(80), nullable=False)
    findings_summary: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(24), nullable=False)
    executed_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class HardeningAuditEvent(Base):
    """Immutable append-only audit trail for Phase 14 key, cert, DR, and security ops."""

    __tablename__ = "hardening_audit_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
            name="fk_hae_org",
        ),
        CheckConstraint(
            "category IN ("
            "'key_rotation', 'cert_monitoring', 'openbao_check', "
            "'backup_created', 'restore_drill', 'security_self_test', 'crypto_agility'"
            ")",
            name="ck_hae_category",
        ),
        CheckConstraint(
            "outcome IN ('allowed', 'denied', 'completed', 'failed')",
            name="ck_hae_outcome",
        ),
        Index("ix_hae_org_occurred", "organization_id", "occurred_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    category: Mapped[str] = mapped_column(String(40), nullable=False)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    outcome: Mapped[str] = mapped_column(String(24), nullable=False)
    actor_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    actor_email: Mapped[str] = mapped_column(String(320), nullable=False)
    details_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
