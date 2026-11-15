"""Phase 9 Threat Intelligence models: sources, sync runs, snapshots, records."""

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
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from vforge.db import Base


class IntelligenceSource(Base):
    """Platform-level external threat intelligence provider / feed definition."""

    __tablename__ = "intelligence_sources"
    __table_args__ = (
        UniqueConstraint("slug", name="uq_intelligence_sources_slug"),
        CheckConstraint(
            "source_type IN ("
            "'cve_catalog', 'exploit_catalog', 'probability_feed', "
            "'package_advisory', 'exposure_intel', 'ioc_feed')",
            name="ck_intel_sources_type",
        ),
        Index("ix_intelligence_sources_type_active", "source_type", "is_active"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    slug: Mapped[str] = mapped_column(String(50), nullable=False)
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    source_type: Mapped[str] = mapped_column(String(50), nullable=False)
    provider_url: Mapped[str] = mapped_column(Text, nullable=False)
    license_name: Mapped[str] = mapped_column(String(100), nullable=False)
    license_url: Mapped[str | None] = mapped_column(Text)
    terms_reference: Mapped[str | None] = mapped_column(Text)
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
    )
    is_gated: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    requires_scope_auth: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    allow_binary_upload: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
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


class IntelSyncRun(Base):
    """Synchronization execution record for an intelligence source."""

    __tablename__ = "intel_sync_runs"
    __table_args__ = (
        ForeignKeyConstraint(
            ["source_id"],
            ["intelligence_sources.id"],
            name="fk_intel_sync_runs_source",
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "sync_mode IN ('full', 'incremental', 'ad_hoc')",
            name="ck_intel_sync_runs_mode",
        ),
        CheckConstraint(
            "status IN ('pending', 'running', 'succeeded', 'failed', 'stale', 'quarantined')",
            name="ck_intel_sync_runs_status",
        ),
        Index("ix_intel_sync_runs_source_started", "source_id", "started_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    source_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    sync_mode: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="incremental",
        server_default=text("'incremental'"),
    )
    cursor_before: Mapped[str | None] = mapped_column(Text)
    cursor_after: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="pending",
        server_default=text("'pending'"),
    )
    records_fetched: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    records_persisted: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    error_message: Mapped[str | None] = mapped_column(Text)
    raw_payload_hash: Mapped[str | None] = mapped_column(String(64))
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class IntelSnapshot(Base):
    """Immutable point-in-time threat intelligence snapshot for deterministic scan replay."""

    __tablename__ = "intel_snapshots"
    __table_args__ = (
        ForeignKeyConstraint(
            ["source_id"],
            ["intelligence_sources.id"],
            name="fk_intel_snapshots_source",
            ondelete="CASCADE",
        ),
        UniqueConstraint(
            "source_id",
            "snapshot_tag",
            name="uq_intel_snapshots_source_tag",
        ),
        Index("ix_intel_snapshots_source_created", "source_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    source_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    snapshot_tag: Mapped[str] = mapped_column(String(100), nullable=False)
    snapshot_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    storage_uri: Mapped[str | None] = mapped_column(Text)
    record_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    is_stale: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    stale_reason: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class IntelRecord(Base):
    """Normalized threat intelligence record (CVE, KEV, EPSS, OSV, GHSA, EDB, IOC)."""

    __tablename__ = "intel_records"
    __table_args__ = (
        ForeignKeyConstraint(
            ["source_id"],
            ["intelligence_sources.id"],
            name="fk_intel_records_source",
            ondelete="CASCADE",
        ),
        UniqueConstraint(
            "source_id",
            "source_record_id",
            name="uq_intel_records_source_rec",
        ),
        CheckConstraint(
            "record_type IN ('cve', 'kev', 'epss', 'osv', 'ghsa', 'cwe', 'edb', 'ioc')",
            name="ck_intel_records_type",
        ),
        Index("ix_intel_records_source_record_id", "source_record_id"),
        Index("ix_intel_records_type_kev", "record_type", "is_known_exploited"),
        Index("ix_intel_records_type_epss", "record_type", "epss_score"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    source_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    source_record_id: Mapped[str] = mapped_column(String(100), nullable=False)
    record_type: Mapped[str] = mapped_column(String(30), nullable=False)
    title: Mapped[str | None] = mapped_column(Text)
    summary: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    cvss_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
    cvss_vector: Mapped[str | None] = mapped_column(String(100))
    epss_score: Mapped[float | None] = mapped_column(Numeric(6, 5))
    epss_percentile: Mapped[float | None] = mapped_column(Numeric(6, 5))
    is_known_exploited: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    raw_payload: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    raw_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    normalized_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    modified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    retrieved_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
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


class IntelRelationship(Base):
    """Cross-reference mapping between threat intelligence entities and standard identifiers."""

    __tablename__ = "intel_relationships"
    __table_args__ = (
        ForeignKeyConstraint(
            ["intel_record_id"],
            ["intel_records.id"],
            name="fk_intel_relationships_record",
            ondelete="CASCADE",
        ),
        CheckConstraint(
            "relationship_type IN ("
            "'cve_to_cwe', 'cve_to_epss', 'cve_to_kev', "
            "'cve_to_purl', 'cve_to_edb', 'cve_to_att_ck', 'cve_to_ghsa')",
            name="ck_intel_relationships_type",
        ),
        CheckConstraint(
            "target_identifier_type IN ('cve', 'cwe', 'purl', 'edb', 'capec', 'att_ck', 'ghsa')",
            name="ck_intel_relationships_target_type",
        ),
        Index("ix_intel_relationships_target", "target_identifier_type", "target_identifier"),
        Index("ix_intel_relationships_record_rel", "intel_record_id", "relationship_type"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    intel_record_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    relationship_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target_identifier_type: Mapped[str] = mapped_column(String(30), nullable=False)
    target_identifier: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class IntelEnrichmentEvent(Base):
    """Tenant-scoped finding enrichment event preserving exact snapshot provenance."""

    __tablename__ = "intel_enrichment_events"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_intel_enrichment_events_org_id_id"),
        ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_intel_enrichment_events_org",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["projects.organization_id", "projects.id"],
            name="fk_intel_enrichment_events_org_project",
            ondelete="RESTRICT",
        ),
        ForeignKeyConstraint(
            ["organization_id", "finding_id"],
            ["findings.organization_id", "findings.id"],
            name="fk_intel_enrichment_events_org_finding",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["intel_snapshot_id"],
            ["intel_snapshots.id"],
            name="fk_intel_enrichment_events_snapshot",
            ondelete="SET NULL",
        ),
        ForeignKeyConstraint(
            ["intel_record_id"],
            ["intel_records.id"],
            name="fk_intel_enrichment_events_record",
            ondelete="SET NULL",
        ),
        Index("ix_intel_enrichment_events_org_finding", "organization_id", "finding_id"),
        Index(
            "ix_intel_enrichment_events_org_proj_created",
            "organization_id",
            "project_id",
            "created_at",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    project_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    finding_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    intel_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    intel_record_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    enrichment_data: Mapped[dict[str, Any]] = mapped_column(
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
