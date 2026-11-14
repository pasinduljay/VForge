"""Phase 4 runner pools, mTLS runner identities, heartbeats, events, executions, and artifacts."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
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


class RunnerPool(Base):
    """Tenant-scoped execution pool grouping runners with shared network/isolation posture."""

    __tablename__ = "runner_pools"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
            name="fk_runner_pools_org",
        ),
        UniqueConstraint("organization_id", "slug", name="uq_runner_pools_org_slug"),
        UniqueConstraint("organization_id", "id", name="uq_runner_pools_org_id_id"),
        CheckConstraint(
            "pool_type IN ('standard', 'dast_egress', 'airgapped')",
            name="ck_runner_pools_type",
        ),
        CheckConstraint("max_concurrent_jobs >= 1", name="ck_runner_pools_conc_pos"),
        Index("ix_runner_pools_org", "organization_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False)
    pool_type: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="standard",
        server_default=text("'standard'"),
    )
    max_concurrent_jobs: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=4,
        server_default=text("4"),
    )
    active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class Runner(Base):
    """mTLS-authenticated isolated runner agent bound to one tenant and pool."""

    __tablename__ = "runners"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "pool_id"],
            ["runner_pools.organization_id", "runner_pools.id"],
            ondelete="RESTRICT",
            name="fk_runners_org_pool",
        ),
        UniqueConstraint("organization_id", "id", name="uq_runners_org_id_id"),
        UniqueConstraint("cert_sha256", name="uq_runners_cert_sha256"),
        UniqueConstraint("runner_identity", name="uq_runners_identity"),
        CheckConstraint(
            "status IN ('pending', 'active', 'draining', 'revoked')",
            name="ck_runners_status",
        ),
        Index("ix_runners_org_status", "organization_id", "status"),
        Index("ix_runners_pool", "pool_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    pool_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    runner_identity: Mapped[str] = mapped_column(String(255), nullable=False)
    cert_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    cert_subject: Mapped[str] = mapped_column(String(255), nullable=False)
    cert_expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="active",
        server_default=text("'active'"),
    )
    version: Mapped[str] = mapped_column(String(64), nullable=False)
    capabilities_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    last_heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_users.id", ondelete="RESTRICT"),
    )
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revocation_reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


class RunnerHeartbeat(Base):
    """Liveness heartbeat telemetry submitted by an active runner agent."""

    __tablename__ = "runner_heartbeats"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "runner_id"],
            ["runners.organization_id", "runners.id"],
            ondelete="CASCADE",
            name="fk_runner_hb_org_runner",
        ),
        ForeignKeyConstraint(
            ["organization_id", "runner_job_id"],
            ["runner_jobs.organization_id", "runner_jobs.id"],
            ondelete="SET NULL",
            name="fk_runner_hb_org_job",
        ),
        Index("ix_runner_hb_runner_time", "runner_id", "recorded_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    runner_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    runner_job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    cpu_percent: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    memory_mb: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    active_containers: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    metrics_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    recorded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class RunnerEvent(Base):
    """Append-only runner lifecycle and security event log."""

    __tablename__ = "runner_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "runner_id"],
            ["runners.organization_id", "runners.id"],
            ondelete="RESTRICT",
            name="fk_runner_events_org_runner",
        ),
        ForeignKeyConstraint(
            ["organization_id", "runner_job_id"],
            ["runner_jobs.organization_id", "runner_jobs.id"],
            ondelete="SET NULL",
            name="fk_runner_events_org_job",
        ),
        CheckConstraint(
            "severity IN ('info', 'warning', 'security')",
            name="ck_runner_events_severity",
        ),
        Index("ix_runner_events_org_created", "organization_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    runner_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    runner_job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    severity: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="info",
        server_default=text("'info'"),
    )
    details_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class ToolExecution(Base):
    """Execution provenance record linking a runner job and ephemeral container invocation."""

    __tablename__ = "tool_executions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "runner_job_id"],
            ["runner_jobs.organization_id", "runner_jobs.id"],
            ondelete="CASCADE",
            name="fk_tool_exec_org_job",
        ),
        ForeignKeyConstraint(
            ["organization_id", "runner_id"],
            ["runners.organization_id", "runners.id"],
            ondelete="RESTRICT",
            name="fk_tool_exec_org_runner",
        ),
        UniqueConstraint("organization_id", "id", name="uq_tool_executions_org_id_id"),
        CheckConstraint(
            "status IN ('running', 'completed', 'failed', 'timed_out', 'cancelled')",
            name="ck_tool_exec_status",
        ),
        Index("ix_tool_exec_job", "runner_job_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    runner_job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    runner_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    tool_id: Mapped[str] = mapped_column(String(100), nullable=False)
    tool_version: Mapped[str] = mapped_column(String(100), nullable=False)
    image_digest: Mapped[str] = mapped_column(Text, nullable=False)
    adapter_version: Mapped[str] = mapped_column(String(50), nullable=False)
    config_hash: Mapped[str | None] = mapped_column(String(128))
    rule_pack_hash: Mapped[str | None] = mapped_column(String(128))
    template_snapshot_hash: Mapped[str | None] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="running",
        server_default=text("'running'"),
    )
    exit_code: Mapped[int | None] = mapped_column(Integer)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    execution_metrics: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class Artifact(Base):
    """Immutable metadata for an envelope-encrypted, SHA-256 verified execution artifact."""

    __tablename__ = "artifacts"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "scan_run_id"],
            ["scan_runs.organization_id", "scan_runs.id"],
            ondelete="CASCADE",
            name="fk_artifacts_org_run",
        ),
        ForeignKeyConstraint(
            ["organization_id", "runner_job_id"],
            ["runner_jobs.organization_id", "runner_jobs.id"],
            ondelete="SET NULL",
            name="fk_artifacts_org_job",
        ),
        ForeignKeyConstraint(
            ["organization_id", "execution_id"],
            ["tool_executions.organization_id", "tool_executions.id"],
            ondelete="SET NULL",
            name="fk_artifacts_org_exec",
        ),
        UniqueConstraint("storage_key", name="uq_artifacts_storage_key"),
        UniqueConstraint("organization_id", "id", name="uq_artifacts_org_id_id"),
        CheckConstraint(
            "artifact_type IN ('raw_output', 'execution_log', 'manifest', 'sbom', 'report')",
            name="ck_artifacts_type",
        ),
        CheckConstraint("size_bytes >= 0", name="ck_artifacts_size_nonneg"),
        Index("ix_artifacts_org_run", "organization_id", "scan_run_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    scan_run_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    runner_job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    execution_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    artifact_type: Mapped[str] = mapped_column(String(50), nullable=False)
    storage_key: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    ciphertext_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    encryption_algorithm: Mapped[str] = mapped_column(String(40), nullable=False)
    encryption_key_id: Mapped[str] = mapped_column(String(120), nullable=False)
    wrapped_dek_b64: Mapped[str] = mapped_column(Text, nullable=False)
    nonce_b64: Mapped[str] = mapped_column(String(64), nullable=False)
    aad_b64: Mapped[str] = mapped_column(Text, nullable=False)
    content_type: Mapped[str] = mapped_column(String(150), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
