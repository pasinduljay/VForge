"""SQLAlchemy 2 models for Phase 13 Isolated Learning Lab & Self-Scan Verification."""

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
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from vforge.db import Base


class LabChallenge(Base):
    """Curated beginner-to-expert defensive learning challenges for isolated lab targets."""

    __tablename__ = "lab_challenges"
    __table_args__ = (
        CheckConstraint(
            "track_level IN ('beginner', 'intermediate', 'advanced', 'expert_practice')",
            name="ck_lc_track_level",
        ),
        CheckConstraint(
            "target_app IN ('juice_shop', 'crapi', 'webgoat', 'vforge_sample')",
            name="ck_lc_target_app",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    slug: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    track_level: Mapped[str] = mapped_column(String(32), nullable=False)
    target_app: Mapped[str] = mapped_column(String(40), nullable=False)
    cwe_id: Mapped[str] = mapped_column(String(32), nullable=False)
    learning_goal: Mapped[str] = mapped_column(Text, nullable=False)
    preconditions_json: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    permitted_target: Mapped[str] = mapped_column(String(255), nullable=False)
    test_identities_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, nullable=False
    )
    test_data_json: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    permitted_tools_json: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    expected_finding_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False
    )
    safe_evidence_criteria: Mapped[str] = mapped_column(Text, nullable=False)
    remediation_exercise: Mapped[str] = mapped_column(Text, nullable=False)
    retest_instructions: Mapped[str] = mapped_column(Text, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class LabWorkspace(Base):
    """Tenant-isolated disposable lab workspace bound to egress-denied bridge configuration."""

    __tablename__ = "lab_workspaces"
    __table_args__ = (
        UniqueConstraint("organization_id", "environment_slug", name="uq_lw_org_slug"),
        UniqueConstraint("organization_id", "id", name="uq_lw_org_id"),
        CheckConstraint("egress_denied IS TRUE", name="ck_lw_egress_denied"),
        CheckConstraint("public_exposure_blocked IS TRUE", name="ck_lw_no_public_exposure"),
        CheckConstraint("reset_epoch >= 1", name="ck_lw_reset_epoch"),
        CheckConstraint(
            "state IN ('ready', 'running', 'resetting', 'stopped')",
            name="ck_lw_state",
        ),
        Index("ix_lw_org_state", "organization_id", "state"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    environment_slug: Mapped[str] = mapped_column(String(80), nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    isolation_network_name: Mapped[str] = mapped_column(
        String(80), default="vforge_lab_internal", nullable=False
    )
    egress_denied: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    public_exposure_blocked: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    consent_to_persist_progress: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )
    disposable_account_prefix: Mapped[str] = mapped_column(String(64), nullable=False)
    reset_epoch: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    state: Mapped[str] = mapped_column(String(32), default="ready", nullable=False)
    disposable_identities_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, default=list, nullable=False
    )
    last_reset_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class LabChallengeProgress(Base):
    """Per-organization consented challenge progression within an isolated lab workspace."""

    __tablename__ = "lab_challenge_progress"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "workspace_id"],
            ["lab_workspaces.organization_id", "lab_workspaces.id"],
            name="fk_lcp_org_workspace",
            ondelete="CASCADE",
        ),
        UniqueConstraint("organization_id", "workspace_id", "challenge_id", name="uq_lcp_ws_ch"),
        CheckConstraint("consent_granted IS TRUE", name="ck_lcp_consent_granted"),
        CheckConstraint(
            "status IN ('not_started', 'in_progress', 'validated', 'remediated', 'retested')",
            name="ck_lcp_status",
        ),
        Index("ix_lcp_org_ws", "organization_id", "workspace_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    challenge_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("lab_challenges.id", ondelete="RESTRICT"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(32), default="not_started", nullable=False)
    consent_granted: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    reset_epoch: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    validated_evidence_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, default=dict, nullable=False
    )
    remediation_notes: Mapped[str] = mapped_column(Text, default="", nullable=False)
    retest_passed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    attempts_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    updated_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )


class LabValidationRun(Base):
    """Immutable log of safe, non-destructive minimum-evidence validations inside the lab."""

    __tablename__ = "lab_validation_runs"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "workspace_id"],
            ["lab_workspaces.organization_id", "lab_workspaces.id"],
            name="fk_lvr_org_workspace",
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "action_type IN ('baseline_probe', 'auth_token_check', 'idor_read_check', "
            "'sqli_error_probe', 'xss_reflection_probe', 'remediation_retest')",
            name="ck_lvr_safe_action_type",
        ),
        CheckConstraint("safety_boundary_verified IS TRUE", name="ck_lvr_boundary_verified"),
        Index("ix_lvr_org_created", "organization_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    workspace_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    challenge_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("lab_challenges.id", ondelete="RESTRICT"),
        nullable=False,
    )
    reset_epoch: Mapped[int] = mapped_column(Integer, nullable=False)
    tool_slug: Mapped[str] = mapped_column(String(64), nullable=False)
    target_url: Mapped[str] = mapped_column(String(255), nullable=False)
    disposable_identity_used: Mapped[str] = mapped_column(String(120), nullable=False)
    action_type: Mapped[str] = mapped_column(String(48), nullable=False)
    safety_boundary_verified: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    evidence_summary_redacted: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    finding_confirmed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    remediation_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="completed", nullable=False)
    executed_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class LabSelfScan(Base):
    """Immutable verification record of VForge self-assessment campaigns against itself."""

    __tablename__ = "lab_self_scans"
    __table_args__ = (
        CheckConstraint(
            "target_component IN ('control_plane_api', 'control_plane_web', "
            "'scanner_contracts', 'runner_agent', 'opa_policies')",
            name="ck_lss_component",
        ),
        Index("ix_lss_org_created", "organization_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    target_component: Mapped[str] = mapped_column(String(80), nullable=False)
    profile_name: Mapped[str] = mapped_column(String(80), nullable=False)
    checks_executed: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    issues_found: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical_high_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    findings_json: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, nullable=False)
    remediation_summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    regression_verified: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="completed", nullable=False)
    executed_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class LabAuditEvent(Base):
    """Append-only audit trail for Phase 13 lab lifecycle, resets, validations, and self-scans."""

    __tablename__ = "lab_audit_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "workspace_id"],
            ["lab_workspaces.organization_id", "lab_workspaces.id"],
            name="fk_lae_org_workspace",
            ondelete="RESTRICT",
        ),
        Index("ix_lae_org_occurred", "organization_id", "occurred_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    workspace_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    actor_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    actor_email: Mapped[str] = mapped_column(String(320), nullable=False)
    target_url: Mapped[str | None] = mapped_column(String(255), nullable=True)
    details_json: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
