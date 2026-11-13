"""Phase 3 orchestration SQLAlchemy models: runs, stages, jobs, target leases, outbox."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
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
from sqlalchemy.orm import Mapped, mapped_column, relationship

from vforge.db import Base


class ScanRun(Base):
    """Authoritative orchestration state machine root record for a requested assessment."""

    __tablename__ = "scan_runs"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["projects.organization_id", "projects.id"],
            ondelete="RESTRICT",
            name="fk_scan_runs_org_project",
        ),
        ForeignKeyConstraint(
            ["organization_id", "environment_id"],
            ["environments.organization_id", "environments.id"],
            ondelete="RESTRICT",
            name="fk_scan_runs_org_environment",
        ),
        ForeignKeyConstraint(
            ["organization_id", "scan_profile_id"],
            ["scan_profiles.organization_id", "scan_profiles.id"],
            ondelete="RESTRICT",
            name="fk_scan_runs_org_scan_profile",
        ),
        ForeignKeyConstraint(
            ["organization_id", "authorization_id"],
            ["authorizations.organization_id", "authorizations.id"],
            ondelete="RESTRICT",
            name="fk_scan_runs_org_authorization",
        ),
        ForeignKeyConstraint(
            ["organization_id", "scope_snapshot_id"],
            ["scope_snapshots.organization_id", "scope_snapshots.id"],
            ondelete="RESTRICT",
            name="fk_scan_runs_org_snapshot",
        ),
        ForeignKeyConstraint(
            ["organization_id", "source_snapshot_id"],
            ["source_snapshots.organization_id", "source_snapshots.id"],
            ondelete="RESTRICT",
            name="fk_scan_runs_org_source_snapshot",
        ),
        ForeignKeyConstraint(
            ["organization_id", "auth_profile_id"],
            ["auth_profiles.organization_id", "auth_profiles.id"],
            ondelete="RESTRICT",
            name="fk_scan_runs_org_auth_profile",
        ),
        UniqueConstraint("organization_id", "id", name="uq_scan_runs_org_id_id"),
        UniqueConstraint("organization_id", "idempotency_key", name="uq_scan_runs_org_idemp"),
        CheckConstraint(
            "status IN ('draft', 'scope_validation', 'awaiting_approval', 'queued', "
            "'provisioning', 'running', 'collecting', 'normalizing', 'correlating', "
            "'reporting', 'cancelling', 'completed', 'completed_with_errors', 'partial', "
            "'failed', 'rejected', 'cancelled')",
            name="ck_scan_runs_status",
        ),
        CheckConstraint(
            "coverage_status IN ('pending', 'complete', 'partial', 'failed', 'not_applicable')",
            name="ck_scan_runs_coverage_status",
        ),
        Index("ix_scan_runs_org_created", "organization_id", "created_at"),
        Index("ix_scan_runs_org_status", "organization_id", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    project_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    environment_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    scan_profile_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    authorization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    scope_snapshot_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    requested_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
        default="queued",
        server_default=text("'queued'"),
    )
    coverage_status: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
        default="pending",
        server_default=text("'pending'"),
    )
    runner_pool: Mapped[str] = mapped_column(
        String(80),
        nullable=False,
        default="control-preflight",
        server_default=text("'control-preflight'"),
    )
    source_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    auth_profile_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    source_snapshot_hash: Mapped[str | None] = mapped_column(String(128))
    coverage_summary: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    target_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    profile_snapshot: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    plan_manifest: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    tool_version_pins: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    rule_pack_pins: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
    )
    policy_snapshot_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    policy_version: Mapped[str] = mapped_column(String(50), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False)
    request_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    cancel_requested_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_users.id", ondelete="RESTRICT"),
    )
    cancel_reason: Mapped[str | None] = mapped_column(Text)
    error_summary: Mapped[str | None] = mapped_column(Text)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
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

    stages: Mapped[list[ScanStage]] = relationship(
        back_populates="scan_run",
        order_by="ScanStage.stage_order",
    )
    jobs: Mapped[list[RunnerJob]] = relationship(
        back_populates="scan_run",
        order_by="RunnerJob.created_at",
    )
    leases: Mapped[list[ScanTargetLease]] = relationship(
        back_populates="scan_run",
        order_by="ScanTargetLease.acquired_at",
    )
    health_probes: Mapped[list[TargetHealthProbe]] = relationship(
        back_populates="scan_run",
        order_by="TargetHealthProbe.created_at",
    )


class ScanStage(Base):
    """Ordered stage within a declarative scan plan."""

    __tablename__ = "scan_stages"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "scan_run_id"],
            ["scan_runs.organization_id", "scan_runs.id"],
            ondelete="CASCADE",
            name="fk_scan_stages_org_run",
        ),
        UniqueConstraint("scan_run_id", "stage_key", name="uq_scan_stages_run_key"),
        UniqueConstraint("organization_id", "id", name="uq_scan_stages_org_id_id"),
        CheckConstraint(
            "status IN ('pending', 'queued', 'running', 'completed', "
            "'failed', 'skipped', 'cancelled')",
            name="ck_scan_stages_status",
        ),
        CheckConstraint(
            "lease_risk_class IS NULL OR "
            "lease_risk_class IN ('active_http', 'network_scan', 'ai_sandbox')",
            name="ck_scan_stages_lease_risk_class",
        ),
        Index("ix_scan_stages_run_order", "scan_run_id", "stage_order"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    scan_run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    stage_key: Mapped[str] = mapped_column(String(100), nullable=False)
    stage_order: Mapped[int] = mapped_column(Integer, nullable=False)
    stage_kind: Mapped[str] = mapped_column(String(40), nullable=False)
    depends_on_stage_key: Mapped[str | None] = mapped_column(String(100))
    requires_target_lease: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    lease_risk_class: Mapped[str | None] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="pending",
        server_default=text("'pending'"),
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
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

    scan_run: Mapped[ScanRun] = relationship(back_populates="stages")
    jobs: Mapped[list[RunnerJob]] = relationship(back_populates="stage", overlaps="jobs,scan_run")


class RunnerJob(Base):
    """Idempotent unit of orchestration work backed by PostgreSQL leases and retries."""

    __tablename__ = "runner_jobs"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "scan_run_id"],
            ["scan_runs.organization_id", "scan_runs.id"],
            ondelete="CASCADE",
            name="fk_runner_jobs_org_run",
        ),
        ForeignKeyConstraint(
            ["organization_id", "scan_stage_id"],
            ["scan_stages.organization_id", "scan_stages.id"],
            ondelete="CASCADE",
            name="fk_runner_jobs_org_stage",
        ),
        UniqueConstraint("organization_id", "id", name="uq_runner_jobs_org_id_id"),
        CheckConstraint(
            "status IN ('pending', 'dispatched', 'leased', 'running', 'completed', "
            "'retry_scheduled', 'failed', 'timed_out', 'cancelled', 'abandoned')",
            name="ck_runner_jobs_status",
        ),
        CheckConstraint("attempt_count >= 0", name="ck_runner_jobs_attempt_nonneg"),
        CheckConstraint("max_attempts >= 1", name="ck_runner_jobs_max_attempts_pos"),
        CheckConstraint("timeout_seconds >= 1", name="ck_runner_jobs_timeout_pos"),
        CheckConstraint("execution_count >= 0", name="ck_runner_jobs_exec_count_nonneg"),
        CheckConstraint(
            "execution_mode IN ('simulated', 'runner')", name="ck_runner_jobs_exec_mode"
        ),
        ForeignKeyConstraint(
            ["organization_id", "target_pool_id"],
            ["runner_pools.organization_id", "runner_pools.id"],
            ondelete="RESTRICT",
            name="fk_runner_jobs_org_pool",
        ),
        ForeignKeyConstraint(
            ["organization_id", "claimed_by_runner_id"],
            ["runners.organization_id", "runners.id"],
            ondelete="RESTRICT",
            name="fk_runner_jobs_org_runner",
        ),
        Index("ix_runner_jobs_org_status", "organization_id", "status"),
        Index("ix_runner_jobs_run", "scan_run_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    scan_run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    scan_stage_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    job_type: Mapped[str] = mapped_column(
        String(60),
        nullable=False,
        default="dummy_orchestration_task",
        server_default=text("'dummy_orchestration_task'"),
    )
    tool_id: Mapped[str] = mapped_column(String(100), nullable=False)
    tool_version: Mapped[str] = mapped_column(String(100), nullable=False)
    image_digest: Mapped[str] = mapped_column(Text, nullable=False)
    adapter_version: Mapped[str] = mapped_column(String(50), nullable=False)
    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="pending",
        server_default=text("'pending'"),
    )
    attempt_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    max_attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=3,
        server_default=text("3"),
    )
    lease_owner: Mapped[str | None] = mapped_column(String(200))
    lease_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    next_retry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    timeout_seconds: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=300,
        server_default=text("300"),
    )
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    job_configuration: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    execution_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    result_summary: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    last_error_code: Mapped[str | None] = mapped_column(String(80))
    last_error_message: Mapped[str | None] = mapped_column(Text)
    execution_mode: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="simulated",
        server_default=text("'simulated'"),
    )
    target_pool_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    claimed_by_runner_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    manifest_sha256: Mapped[str | None] = mapped_column(String(64))
    manifest_signature: Mapped[str | None] = mapped_column(Text)
    manifest_signing_key_id: Mapped[str | None] = mapped_column(String(120))
    manifest_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    cancel_requested_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
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

    scan_run: Mapped[ScanRun] = relationship(back_populates="jobs", overlaps="jobs,stage")
    stage: Mapped[ScanStage] = relationship(back_populates="jobs", overlaps="jobs,scan_run")


class ScanTargetLease(Base):
    """PostgreSQL-backed mutually exclusive active scan lease per (asset, risk_class)."""

    __tablename__ = "scan_target_leases"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "scan_run_id"],
            ["scan_runs.organization_id", "scan_runs.id"],
            ondelete="CASCADE",
            name="fk_target_leases_org_run",
        ),
        ForeignKeyConstraint(
            ["organization_id", "runner_job_id"],
            ["runner_jobs.organization_id", "runner_jobs.id"],
            ondelete="CASCADE",
            name="fk_target_leases_org_job",
        ),
        ForeignKeyConstraint(
            ["organization_id", "asset_id"],
            ["assets.organization_id", "assets.id"],
            ondelete="RESTRICT",
            name="fk_target_leases_org_asset",
        ),
        CheckConstraint(
            "lease_risk_class IN ('active_http', 'network_scan', 'ai_sandbox')",
            name="ck_target_leases_risk_class",
        ),
        CheckConstraint(
            "status IN ('active', 'released', 'expired', 'revoked')",
            name="ck_target_leases_status",
        ),
        Index(
            "uq_active_target_lease",
            "asset_id",
            "lease_risk_class",
            unique=True,
            postgresql_where=text("status = 'active'"),
        ),
        Index("ix_target_leases_org_status", "organization_id", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    scan_run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    runner_job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    target_locator: Mapped[str] = mapped_column(Text, nullable=False)
    lease_risk_class: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
        default="active_http",
        server_default=text("'active_http'"),
    )
    lease_owner: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="active",
        server_default=text("'active'"),
    )
    acquired_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    heartbeat_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    scan_run: Mapped[ScanRun] = relationship(back_populates="leases")


class OutboxEvent(Base):
    """Transactional outbox record reliably bridged to RabbitMQ."""

    __tablename__ = "outbox_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "scan_run_id"],
            ["scan_runs.organization_id", "scan_runs.id"],
            ondelete="CASCADE",
            name="fk_outbox_org_run",
        ),
        ForeignKeyConstraint(
            ["organization_id", "runner_job_id"],
            ["runner_jobs.organization_id", "runner_jobs.id"],
            ondelete="CASCADE",
            name="fk_outbox_org_job",
        ),
        CheckConstraint(
            "status IN ('pending', 'published', 'dead_letter')",
            name="ck_outbox_status",
        ),
        CheckConstraint("retry_count >= 0", name="ck_outbox_retry_nonneg"),
        Index(
            "ix_outbox_pending_due",
            "status",
            "next_attempt_at",
            postgresql_where=text("status = 'pending'"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    scan_run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    runner_job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    event_type: Mapped[str] = mapped_column(String(80), nullable=False)
    routing_key: Mapped[str] = mapped_column(String(120), nullable=False)
    idempotency_key: Mapped[str] = mapped_column(String(200), nullable=False, unique=True)
    payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="pending",
        server_default=text("'pending'"),
    )
    retry_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    max_retries: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=5,
        server_default=text("5"),
    )
    next_attempt_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    last_error: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class TargetHealthProbe(Base):
    """Immutable target health probe record for DAST safety monitoring and emergency aborts."""

    __tablename__ = "target_health_probes"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "scan_run_id"],
            ["scan_runs.organization_id", "scan_runs.id"],
            ondelete="CASCADE",
            name="fk_target_health_probes_org_run",
        ),
        ForeignKeyConstraint(
            ["organization_id", "runner_job_id"],
            ["runner_jobs.organization_id", "runner_jobs.id"],
            ondelete="SET NULL",
            name="fk_target_health_probes_org_job",
        ),
        ForeignKeyConstraint(
            ["organization_id", "asset_id"],
            ["assets.organization_id", "assets.id"],
            ondelete="RESTRICT",
            name="fk_target_health_probes_org_asset",
        ),
        UniqueConstraint("organization_id", "id", name="uq_target_health_probes_org_id_id"),
        CheckConstraint(
            "probe_type IN ('baseline', 'periodic', 'tripwire', 'post_scan')",
            name="ck_target_health_probes_type",
        ),
        CheckConstraint("latency_ms >= 0", name="ck_target_health_probes_latency_nonneg"),
        Index(
            "ix_target_health_probes_org_run_created",
            "organization_id",
            "scan_run_id",
            "created_at",
        ),
        Index("ix_target_health_probes_healthy", "organization_id", "healthy"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    scan_run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    runner_job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    probe_type: Mapped[str] = mapped_column(String(30), nullable=False)
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer)
    latency_ms: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    healthy: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
    )
    error_message: Mapped[str | None] = mapped_column(Text)
    probe_metadata: Mapped[dict[str, Any]] = mapped_column(
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

    scan_run: Mapped[ScanRun] = relationship(back_populates="health_probes")
