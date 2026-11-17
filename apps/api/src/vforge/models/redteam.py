"""Phase 15 optional AI red-team session governance models.

These tables govern *whether and how* an isolated AI red-team agent may run against the
learning lab. They never store agent prompts, model keys, or raw exploit output. Evidence is
stored only as redacted summaries with a SHA-256 digest, and AI-originated observations stay
``hypothesis`` until a different human reviewer confirms them.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
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


class RedTeamSession(Base):
    """Human-approved, budgeted, time-boxed AI red-team session (lab targets only)."""

    __tablename__ = "ai_redteam_sessions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id"], ["organizations.id"], ondelete="CASCADE", name="fk_rts_org"
        ),
        UniqueConstraint("organization_id", "id", name="uq_rts_org_id_id"),
        CheckConstraint("engine IN ('strix', 'pentagi')", name="ck_rts_engine"),
        CheckConstraint(
            "status IN ('requested', 'approved', 'running', 'completed', "
            "'terminated', 'expired', 'rejected')",
            name="ck_rts_status",
        ),
        CheckConstraint(
            "approved_by IS NULL OR approved_by <> requested_by",
            name="ck_rts_approver_not_requester",
        ),
        CheckConstraint("max_duration_seconds BETWEEN 60 AND 3600", name="ck_rts_duration_bounds"),
        CheckConstraint("max_tool_calls BETWEEN 1 AND 500", name="ck_rts_tool_call_bounds"),
        CheckConstraint("max_tokens BETWEEN 1000 AND 2000000", name="ck_rts_token_bounds"),
        CheckConstraint("tool_calls_used >= 0 AND tokens_used >= 0", name="ck_rts_usage_nonneg"),
        CheckConstraint(
            "status NOT IN ('approved', 'running', 'completed') OR approved_by IS NOT NULL",
            name="ck_rts_approval_required",
        ),
        CheckConstraint(
            "status NOT IN ('completed', 'terminated') OR cleanup_attested = true",
            name="ck_rts_cleanup_attested_on_close",
        ),
        Index("ix_rts_org_status", "organization_id", "status"),
        Index("ix_rts_org_created", "organization_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    objective: Mapped[str] = mapped_column(String(1000), nullable=False)
    engine: Mapped[str] = mapped_column(String(16), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="requested", server_default=text("'requested'")
    )
    tool_allowlist: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    target_urls: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    max_duration_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    max_tool_calls: Mapped[int] = mapped_column(Integer, nullable=False)
    max_tokens: Mapped[int] = mapped_column(Integer, nullable=False)
    tool_calls_used: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    tokens_used: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0, server_default=text("0")
    )
    requested_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approval_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    end_reason: Mapped[str | None] = mapped_column(String(200), nullable=True)
    cleanup_attested: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    cleanup_summary: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        server_default=func.now(),
        nullable=False,
    )


class RedTeamObservation(Base):
    """AI-originated observation: hypothesis until a different human confirms or rejects it."""

    __tablename__ = "ai_redteam_observations"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "session_id"],
            ["ai_redteam_sessions.organization_id", "ai_redteam_sessions.id"],
            ondelete="CASCADE",
            name="fk_rto_org_session",
        ),
        UniqueConstraint("organization_id", "id", name="uq_rto_org_id_id"),
        CheckConstraint(
            "classification IN ('hypothesis', 'confirmed', 'rejected')",
            name="ck_rto_classification",
        ),
        CheckConstraint(
            "severity IN ('info', 'low', 'medium', 'high', 'critical')", name="ck_rto_severity"
        ),
        CheckConstraint(
            "classification = 'hypothesis' OR (reviewed_by IS NOT NULL "
            "AND reviewed_by <> recorded_by AND char_length(btrim(review_note)) >= 12)",
            name="ck_rto_confirmed_requires_independent_review",
        ),
        CheckConstraint(
            "(classification = 'hypothesis' AND reviewed_by IS NULL) "
            "OR (classification IN ('confirmed', 'rejected') AND reviewed_by IS NOT NULL)",
            name="ck_rto_decided_has_reviewer",
        ),
        Index("ix_rto_org_session", "organization_id", "session_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    session_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    classification: Mapped[str] = mapped_column(
        String(16), nullable=False, default="hypothesis", server_default=text("'hypothesis'")
    )
    evidence_summary: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    source: Mapped[str] = mapped_column(
        String(16), nullable=False, default="ai_agent", server_default=text("'ai_agent'")
    )
    recorded_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    review_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        server_default=func.now(),
        nullable=False,
    )


class RedTeamEvent(Base):
    """Append-only audit trail for every lifecycle step and every allowed/denied tool call."""

    __tablename__ = "ai_redteam_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "session_id"],
            ["ai_redteam_sessions.organization_id", "ai_redteam_sessions.id"],
            ondelete="CASCADE",
            name="fk_rte_org_session",
        ),
        CheckConstraint(
            "outcome IN ('allowed', 'denied', 'completed', 'failed')", name="ck_rte_outcome"
        ),
        Index("ix_rte_org_session_time", "organization_id", "session_id", "occurred_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    session_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    event_type: Mapped[str] = mapped_column(String(48), nullable=False)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)
    actor_email: Mapped[str | None] = mapped_column(String(320), nullable=True)
    tool_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    target_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    details_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        server_default=func.now(),
        nullable=False,
    )


class RedTeamBenchmark(Base):
    """Immutable coverage comparison of AI red-team vs ZAP / Nuclei on known lab challenges."""

    __tablename__ = "ai_redteam_benchmarks"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "session_id"],
            ["ai_redteam_sessions.organization_id", "ai_redteam_sessions.id"],
            ondelete="CASCADE",
            name="fk_rtb_org_session",
        ),
        Index("ix_rtb_org_created", "organization_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    session_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    ground_truth_slugs: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    ai_detected_slugs: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    zap_detected_slugs: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    nuclei_detected_slugs: Mapped[list[str]] = mapped_column(JSONB, nullable=False)
    metrics_json: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    data_provenance: Mapped[str] = mapped_column(
        String(48),
        nullable=False,
        default="operator_supplied_unverified",
        server_default=text("'operator_supplied_unverified'"),
    )
    created_by: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        server_default=func.now(),
        nullable=False,
    )
