"""Phase 10 Release & Update Lifecycle Management models."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
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


class ToolCatalog(Base):
    """Registered scanner engine, rule pack, feed, or platform dependency channel."""

    __tablename__ = "tool_catalog"
    __table_args__ = (
        UniqueConstraint("tool_slug", name="uq_tool_catalog_slug"),
        CheckConstraint(
            "stream IN ("
            "'engines_and_base_images', 'rules_templates_addons', "
            "'vulnerability_intel_dbs', 'adapters_and_dependencies')",
            name="ck_tool_catalog_stream",
        ),
        CheckConstraint(
            "update_channel IN ("
            "'scanner_engine_versions', 'container_base_images', "
            "'scanner_addons', 'scanner_rules_and_templates', "
            "'vulnerability_databases', 'threat_intelligence_feeds', "
            "'ai_models', 'ai_rule_packs_and_skills', "
            "'application_dependencies', 'cryptographic_and_security_components')",
            name="ck_tool_catalog_channel",
        ),
        Index("ix_tool_catalog_stream_active", "stream", "is_active"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    tool_slug: Mapped[str] = mapped_column(String(80), nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False)
    stream: Mapped[str] = mapped_column(String(50), nullable=False)
    update_channel: Mapped[str] = mapped_column(String(60), nullable=False)
    adapter_family: Mapped[str] = mapped_column(String(80), nullable=False)
    source_registry: Mapped[str] = mapped_column(Text, nullable=False)
    automerge_allowed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class ToolVersion(Base):
    """Immutable digest-pinned tool/component version with canary & stable channel flags."""

    __tablename__ = "tool_versions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tool_id"],
            ["tool_catalog.id"],
            name="fk_tool_versions_tool",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["previous_stable_version_id"],
            ["tool_versions.id"],
            name="fk_tool_versions_prev_stable",
            ondelete="SET NULL",
        ),
        UniqueConstraint("tool_id", "image_digest", name="uq_tool_versions_tool_digest"),
        CheckConstraint(
            "lower(btrim(version_tag)) <> 'latest' AND lower(btrim(version_tag)) !~ ':latest$'",
            name="ck_tool_versions_not_latest_tag",
        ),
        CheckConstraint(
            "lower(btrim(image_repository)) !~ ':latest$'",
            name="ck_tool_versions_not_latest_repo",
        ),
        CheckConstraint(
            "image_digest ~ '^sha256:[0-9a-f]{64}$'",
            name="ck_tool_versions_sha256_digest",
        ),
        CheckConstraint(
            "approval_channel IN ("
            "'candidate', 'validated', 'approved', 'canary', 'stable', 'rejected', 'rolled_back')",
            name="ck_tool_versions_approval_channel",
        ),
        Index(
            "uq_tool_versions_active_stable",
            "tool_id",
            unique=True,
            postgresql_where=text("is_active_stable = true"),
        ),
        Index(
            "uq_tool_versions_active_canary",
            "tool_id",
            unique=True,
            postgresql_where=text("is_active_canary = true"),
        ),
        Index("ix_tool_versions_tool_channel", "tool_id", "approval_channel", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    tool_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    version_tag: Mapped[str] = mapped_column(String(80), nullable=False)
    image_repository: Mapped[str] = mapped_column(Text, nullable=False)
    image_digest: Mapped[str] = mapped_column(String(80), nullable=False)
    adapter_version: Mapped[str] = mapped_column(String(40), nullable=False, default="1.0.0")
    approval_channel: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="candidate",
        server_default=text("'candidate'"),
    )
    is_active_stable: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    is_active_canary: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    previous_stable_version_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        nullable=True,
    )
    signature_verified: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    sbom_digest: Mapped[str | None] = mapped_column(String(80), nullable=True)
    release_notes_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    promoted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rolled_back_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class ToolUpdate(Base):
    """Tracked candidate update workflow from detection through promotion or rollback."""

    __tablename__ = "tool_updates"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tool_id"],
            ["tool_catalog.id"],
            name="fk_tool_updates_tool",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["candidate_version_id"],
            ["tool_versions.id"],
            name="fk_tool_updates_candidate_version",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["previous_version_id"],
            ["tool_versions.id"],
            name="fk_tool_updates_previous_version",
            ondelete="SET NULL",
        ),
        ForeignKeyConstraint(
            ["approved_by_user_id"],
            ["app_users.id"],
            name="fk_tool_updates_approved_by",
            ondelete="SET NULL",
        ),
        ForeignKeyConstraint(
            ["promoted_by_user_id"],
            ["app_users.id"],
            name="fk_tool_updates_promoted_by",
            ondelete="SET NULL",
        ),
        ForeignKeyConstraint(
            ["rolled_back_by_user_id"],
            ["app_users.id"],
            name="fk_tool_updates_rolled_back_by",
            ondelete="SET NULL",
        ),
        CheckConstraint(
            "stream IN ("
            "'engines_and_base_images', 'rules_templates_addons', "
            "'vulnerability_intel_dbs', 'adapters_and_dependencies')",
            name="ck_tool_updates_stream",
        ),
        CheckConstraint(
            "change_type IN ('patch', 'minor', 'major', 'security', 'feed_refresh')",
            name="ck_tool_updates_change_type",
        ),
        CheckConstraint(
            "status IN ("
            "'detected', 'validating', 'validated', 'approved', "
            "'canary', 'stable', 'rejected', 'rolled_back')",
            name="ck_tool_updates_status",
        ),
        Index("ix_tool_updates_status_created", "status", "created_at"),
        Index("ix_tool_updates_tool_created", "tool_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    tool_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    candidate_version_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    previous_version_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    stream: Mapped[str] = mapped_column(String(50), nullable=False)
    update_channel: Mapped[str] = mapped_column(String(60), nullable=False)
    change_type: Mapped[str] = mapped_column(String(30), nullable=False, default="patch")
    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="detected",
        server_default=text("'detected'"),
    )
    is_emergency: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    emergency_justification: Mapped[str | None] = mapped_column(Text, nullable=True)
    detected_from: Mapped[str] = mapped_column(
        String(120),
        nullable=False,
        default="update-controller",
        server_default=text("'update-controller'"),
    )
    approved_by_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    promoted_by_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    promoted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rolled_back_by_user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    rolled_back_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rollback_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


class FeedSnapshot(Base):
    """Versioned vulnerability database & rule/template bundle snapshot with rollback pointer."""

    __tablename__ = "feed_snapshots"
    __table_args__ = (
        ForeignKeyConstraint(
            ["tool_id"],
            ["tool_catalog.id"],
            name="fk_feed_snapshots_tool",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["previous_stable_snapshot_id"],
            ["feed_snapshots.id"],
            name="fk_feed_snapshots_prev_stable",
            ondelete="SET NULL",
        ),
        UniqueConstraint("feed_slug", "snapshot_tag", name="uq_feed_snapshots_slug_tag"),
        CheckConstraint(
            "lower(btrim(snapshot_tag)) <> 'latest' AND lower(btrim(snapshot_tag)) !~ ':latest$'",
            name="ck_feed_snapshots_not_latest_tag",
        ),
        CheckConstraint(
            "archive_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_feed_snapshots_sha256",
        ),
        CheckConstraint(
            "approval_channel IN ("
            "'candidate', 'validated', 'approved', 'canary', 'stable', 'rejected', 'rolled_back')",
            name="ck_feed_snapshots_approval_channel",
        ),
        Index(
            "uq_feed_snapshots_active_stable",
            "feed_slug",
            unique=True,
            postgresql_where=text("is_active_stable = true"),
        ),
        Index(
            "uq_feed_snapshots_active_canary",
            "feed_slug",
            unique=True,
            postgresql_where=text("is_active_canary = true"),
        ),
        Index("ix_feed_snapshots_slug_created", "feed_slug", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    tool_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    feed_slug: Mapped[str] = mapped_column(String(80), nullable=False)
    stream: Mapped[str] = mapped_column(String(50), nullable=False)
    update_channel: Mapped[str] = mapped_column(String(60), nullable=False)
    snapshot_tag: Mapped[str] = mapped_column(String(100), nullable=False)
    archive_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(40), nullable=False, default="v1")
    record_count: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    approval_channel: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="candidate",
        server_default=text("'candidate'"),
    )
    is_active_stable: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    is_active_canary: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    previous_stable_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), nullable=True
    )
    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    promoted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rolled_back_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class UpdateTestResult(Base):
    """Append-only validation gate evidence for candidate tool versions and updates."""

    __tablename__ = "update_test_results"
    __table_args__ = (
        ForeignKeyConstraint(
            ["update_id"],
            ["tool_updates.id"],
            name="fk_update_test_results_update",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tool_version_id"],
            ["tool_versions.id"],
            name="fk_update_test_results_version",
            ondelete="RESTRICT",
        ),
        CheckConstraint(
            "test_category IN ("
            "'signature_provenance', 'sbom_and_image_scan', "
            "'adapter_contract', 'regression_corpus')",
            name="ck_update_test_results_category",
        ),
        CheckConstraint(
            "outcome IN ('passed', 'failed', 'skipped')",
            name="ck_update_test_results_outcome",
        ),
        Index("ix_update_test_results_update_exec", "update_id", "executed_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    update_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    tool_version_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    test_category: Mapped[str] = mapped_column(String(50), nullable=False)
    outcome: Mapped[str] = mapped_column(String(20), nullable=False)
    summary: Mapped[str] = mapped_column(Text, nullable=False)
    details_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    executed_by: Mapped[str] = mapped_column(String(120), nullable=False)
    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )


class UpdateAuditEvent(Base):
    """Append-only audit trail for update detections, approvals, promotions, and rollbacks."""

    __tablename__ = "update_audit_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["update_id"],
            ["tool_updates.id"],
            name="fk_update_audit_events_update",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tool_id"],
            ["tool_catalog.id"],
            name="fk_update_audit_events_tool",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["tool_version_id"],
            ["tool_versions.id"],
            name="fk_update_audit_events_version",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["feed_snapshot_id"],
            ["feed_snapshots.id"],
            name="fk_update_audit_events_feed",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["actor_user_id"],
            ["app_users.id"],
            name="fk_update_audit_events_actor",
            ondelete="SET NULL",
        ),
        CheckConstraint(
            "action IN ("
            "'candidate_detected', 'validation_recorded', 'approved', 'emergency_approved', "
            "'promoted_canary', 'promoted_stable', 'rejected', 'rolled_back', "
            "'feed_promoted', 'feed_rolled_back')",
            name="ck_update_audit_events_action",
        ),
        Index("ix_update_audit_events_tool_occurred", "tool_id", "occurred_at"),
        Index("ix_update_audit_events_update_occurred", "update_id", "occurred_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    update_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    tool_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    tool_version_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    feed_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    action: Mapped[str] = mapped_column(String(40), nullable=False)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    actor_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    details_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
