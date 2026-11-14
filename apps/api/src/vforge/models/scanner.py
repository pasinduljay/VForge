"""Phase 5 SQLAlchemy models: immutable source snapshots, findings, and scanner occurrences."""

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
    Numeric,
    String,
    Text,
    UniqueConstraint,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from vforge.db import Base


class SourceSnapshot(Base):
    """Immutable validated source archive bound to an authorized repository/code asset."""

    __tablename__ = "source_snapshots"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
            name="fk_source_snapshots_org",
        ),
        ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["projects.organization_id", "projects.id"],
            ondelete="RESTRICT",
            name="fk_source_snapshots_org_project",
        ),
        ForeignKeyConstraint(
            ["organization_id", "asset_id"],
            ["assets.organization_id", "assets.id"],
            ondelete="RESTRICT",
            name="fk_source_snapshots_org_asset",
        ),
        UniqueConstraint("organization_id", "id", name="uq_source_snapshots_org_id_id"),
        CheckConstraint(
            "source_type IN ('archive_tar_gz', 'archive_zip', 'git_commit')",
            name="ck_source_snapshots_type",
        ),
        CheckConstraint(
            "status IN ('ready', 'rejected', 'purged')",
            name="ck_source_snapshots_status",
        ),
        CheckConstraint("file_count >= 0", name="ck_source_snapshots_file_count"),
        CheckConstraint("total_bytes >= 0", name="ck_source_snapshots_total_bytes"),
        Index(
            "ix_source_snapshots_org_proj_created",
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
    asset_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    source_type: Mapped[str] = mapped_column(String(30), nullable=False)
    commit_sha: Mapped[str | None] = mapped_column(String(64))
    branch: Mapped[str | None] = mapped_column(String(160))
    archive_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    storage_key: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    ciphertext_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    encryption_algorithm: Mapped[str] = mapped_column(
        String(40),
        nullable=False,
        default="AES-256-GCM",
        server_default=text("'AES-256-GCM'"),
    )
    encryption_key_id: Mapped[str] = mapped_column(String(100), nullable=False)
    wrapped_dek_b64: Mapped[str] = mapped_column(Text, nullable=False)
    nonce_b64: Mapped[str] = mapped_column(Text, nullable=False)
    aad_b64: Mapped[str] = mapped_column(Text, nullable=False)
    file_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    detected_languages: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    coverage_report: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    status: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="ready",
        server_default=text("'ready'"),
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class Finding(Base):
    """Canonical project finding deduplicated deterministically within an organization."""

    __tablename__ = "findings"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
            name="fk_findings_org",
        ),
        ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["projects.organization_id", "projects.id"],
            ondelete="RESTRICT",
            name="fk_findings_org_project",
        ),
        UniqueConstraint("organization_id", "id", name="uq_findings_org_id_id"),
        UniqueConstraint(
            "organization_id", "project_id", "fingerprint", name="uq_findings_org_proj_fp"
        ),
        CheckConstraint(
            "category IN ('sast', 'secret', 'sca', 'iac', 'dast', 'network')",
            name="ck_findings_category",
        ),
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info', 'unknown')",
            name="ck_findings_severity",
        ),
        CheckConstraint(
            "confidence IN ('high', 'medium', 'low')",
            name="ck_findings_confidence",
        ),
        CheckConstraint(
            "validation_status IN ("
            "'unverified', 'reproduced', 'human_confirmed', "
            "'false_positive', 'accepted_risk', 'fixed', 'reopened')",
            name="ck_findings_validation_status",
        ),
        CheckConstraint(
            "status IN ('open', 'in_progress', 'resolved', 'risk_accepted', 'false_positive')",
            name="ck_findings_status",
        ),
        Index("ix_findings_org_proj_sev", "organization_id", "project_id", "severity"),
        Index("ix_findings_org_status", "organization_id", "status"),
        Index("ix_findings_org_purl", "organization_id", "purl"),
        Index("ix_findings_org_sla", "organization_id", "sla_due_at", "sla_breached"),
        Index("ix_findings_org_assigned", "organization_id", "assigned_to"),
        Index("ix_findings_org_priority", "organization_id", "business_priority"),
        CheckConstraint(
            "business_priority IN ('critical', 'high', 'medium', 'low', 'info')",
            name="ck_findings_business_priority",
        ),
        CheckConstraint(
            (
                "retest_status IS NULL OR retest_status IN "
                "('pending_retest', 'retest_passed', 'retest_failed')"
            ),
            name="ck_findings_retest_status",
        ),
        ForeignKeyConstraint(
            ["organization_id", "sbom_document_id"],
            ["sbom_documents.organization_id", "sbom_documents.id"],
            ondelete="RESTRICT",
            name="fk_findings_org_sbom",
        ),
        ForeignKeyConstraint(
            ["organization_id", "vulnerability_db_snapshot_id"],
            ["vulnerability_db_snapshots.organization_id", "vulnerability_db_snapshots.id"],
            ondelete="RESTRICT",
            name="fk_findings_org_vuln_db",
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
    fingerprint: Mapped[str] = mapped_column(String(128), nullable=False)
    category: Mapped[str] = mapped_column(String(30), nullable=False)
    scanner_tool_id: Mapped[str] = mapped_column(String(100), nullable=False)
    scanner_version: Mapped[str] = mapped_column(String(100), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(200), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False)
    validation_status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="unverified",
        server_default=text("'unverified'"),
    )
    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="open",
        server_default=text("'open'"),
    )
    cwe_ids: Mapped[list[str]] = mapped_column(
        ARRAY(String(40)),
        nullable=False,
        default=list,
        server_default=text("'{}'::varchar[]"),
    )
    file_path: Mapped[str | None] = mapped_column(Text)
    start_line: Mapped[int | None] = mapped_column(Integer)
    end_line: Mapped[int | None] = mapped_column(Integer)
    code_snippet_redacted: Mapped[str | None] = mapped_column(Text)
    secret_redacted: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    remediation: Mapped[str | None] = mapped_column(Text)
    purl: Mapped[str | None] = mapped_column(Text)
    package_name: Mapped[str | None] = mapped_column(String(255))
    package_version: Mapped[str | None] = mapped_column(String(120))
    fixed_version: Mapped[str | None] = mapped_column(String(120))
    cve_id: Mapped[str | None] = mapped_column(String(64))
    iac_resource: Mapped[str | None] = mapped_column(String(255))
    sbom_document_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    vulnerability_db_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    sla_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    sla_breached: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_users.id", ondelete="SET NULL"),
    )
    remediation_notes: Mapped[str | None] = mapped_column(Text)
    retest_status: Mapped[str | None] = mapped_column(String(30))
    business_priority: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="medium",
        server_default=text("'medium'"),
    )
    cvss_score: Mapped[float | None] = mapped_column(Numeric(3, 1))
    cvss_vector: Mapped[str | None] = mapped_column(String(100))
    is_known_exploited: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    epss_score: Mapped[float | None] = mapped_column(Numeric(6, 5))
    epss_percentile: Mapped[float | None] = mapped_column(Numeric(6, 5))
    occurrence_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=1,
        server_default=text("1"),
    )
    first_seen_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    last_seen_at: Mapped[datetime] = mapped_column(
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


class FindingOccurrence(Base):
    """Immutable per-execution observation preserving exact tool/image/artifact provenance."""

    __tablename__ = "finding_occurrences"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
            name="fk_finding_occ_org",
        ),
        ForeignKeyConstraint(
            ["organization_id", "finding_id"],
            ["findings.organization_id", "findings.id"],
            ondelete="CASCADE",
            name="fk_finding_occ_org_finding",
        ),
        ForeignKeyConstraint(
            ["organization_id", "scan_run_id"],
            ["scan_runs.organization_id", "scan_runs.id"],
            ondelete="CASCADE",
            name="fk_finding_occ_org_run",
        ),
        ForeignKeyConstraint(
            ["organization_id", "execution_id"],
            ["tool_executions.organization_id", "tool_executions.id"],
            ondelete="CASCADE",
            name="fk_finding_occ_org_exec",
        ),
        ForeignKeyConstraint(
            ["organization_id", "evidence_artifact_id"],
            ["artifacts.organization_id", "artifacts.id"],
            ondelete="SET NULL",
            name="fk_finding_occ_org_artifact",
        ),
        ForeignKeyConstraint(
            ["organization_id", "sbom_document_id"],
            ["sbom_documents.organization_id", "sbom_documents.id"],
            ondelete="RESTRICT",
            name="fk_finding_occ_org_sbom",
        ),
        ForeignKeyConstraint(
            ["organization_id", "vulnerability_db_snapshot_id"],
            ["vulnerability_db_snapshots.organization_id", "vulnerability_db_snapshots.id"],
            ondelete="RESTRICT",
            name="fk_finding_occ_org_vuln_db",
        ),
        Index("ix_finding_occ_org_run", "organization_id", "scan_run_id"),
        Index("ix_finding_occ_org_finding", "organization_id", "finding_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    finding_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    scan_run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    execution_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    evidence_artifact_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    scanner_tool_id: Mapped[str] = mapped_column(String(100), nullable=False)
    scanner_version: Mapped[str] = mapped_column(String(100), nullable=False)
    image_digest: Mapped[str] = mapped_column(Text, nullable=False)
    rule_id: Mapped[str] = mapped_column(String(200), nullable=False)
    file_path: Mapped[str | None] = mapped_column(Text)
    start_line: Mapped[int | None] = mapped_column(Integer)
    end_line: Mapped[int | None] = mapped_column(Integer)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False)
    secret_redacted: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    snippet_redacted: Mapped[str | None] = mapped_column(Text)
    purl: Mapped[str | None] = mapped_column(Text)
    package_name: Mapped[str | None] = mapped_column(String(255))
    package_version: Mapped[str | None] = mapped_column(String(120))
    fixed_version: Mapped[str | None] = mapped_column(String(120))
    cve_id: Mapped[str | None] = mapped_column(String(64))
    iac_resource: Mapped[str | None] = mapped_column(String(255))
    sbom_document_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    vulnerability_db_snapshot_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    raw_finding_sanitized: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class SbomDocument(Base):
    """Immutable SBOM document metadata referencing encrypted CycloneDX/SPDX artifact bytes."""

    __tablename__ = "sbom_documents"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
            name="fk_sbom_documents_org",
        ),
        ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["projects.organization_id", "projects.id"],
            ondelete="RESTRICT",
            name="fk_sbom_documents_org_project",
        ),
        ForeignKeyConstraint(
            ["organization_id", "scan_run_id"],
            ["scan_runs.organization_id", "scan_runs.id"],
            ondelete="CASCADE",
            name="fk_sbom_documents_org_run",
        ),
        ForeignKeyConstraint(
            ["organization_id", "source_snapshot_id"],
            ["source_snapshots.organization_id", "source_snapshots.id"],
            ondelete="RESTRICT",
            name="fk_sbom_documents_org_snapshot",
        ),
        ForeignKeyConstraint(
            ["organization_id", "execution_id"],
            ["tool_executions.organization_id", "tool_executions.id"],
            ondelete="CASCADE",
            name="fk_sbom_documents_org_exec",
        ),
        ForeignKeyConstraint(
            ["organization_id", "artifact_id"],
            ["artifacts.organization_id", "artifacts.id"],
            ondelete="RESTRICT",
            name="fk_sbom_documents_org_artifact",
        ),
        UniqueConstraint("organization_id", "id", name="uq_sbom_documents_org_id_id"),
        UniqueConstraint(
            "organization_id",
            "execution_id",
            "sbom_format",
            name="uq_sbom_documents_org_exec_fmt",
        ),
        CheckConstraint(
            "sbom_format IN ('cyclonedx-json', 'spdx-json')",
            name="ck_sbom_documents_format",
        ),
        CheckConstraint("component_count >= 0", name="ck_sbom_documents_count"),
        Index("ix_sbom_documents_org_run", "organization_id", "scan_run_id"),
        Index("ix_sbom_documents_org_proj_created", "organization_id", "project_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    project_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    scan_run_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    source_snapshot_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    execution_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    artifact_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    sbom_format: Mapped[str] = mapped_column(String(30), nullable=False)
    spec_version: Mapped[str] = mapped_column(String(40), nullable=False)
    serial_number: Mapped[str | None] = mapped_column(String(120))
    bom_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    tool_id: Mapped[str] = mapped_column(String(60), nullable=False)
    tool_version: Mapped[str] = mapped_column(String(60), nullable=False)
    image_digest: Mapped[str] = mapped_column(Text, nullable=False)
    cataloger_config: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    component_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    components_summary: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default=text("'[]'::jsonb"),
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )


class VulnerabilityDbSnapshot(Base):
    """Recorded offline vulnerability DB snapshot provenance captured with SCA executions."""

    __tablename__ = "vulnerability_db_snapshots"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
            name="fk_vuln_db_snapshots_org",
        ),
        UniqueConstraint("organization_id", "id", name="uq_vuln_db_snapshots_org_id_id"),
        UniqueConstraint(
            "organization_id",
            "tool_id",
            "schema_version",
            "db_archive_sha256",
            name="uq_vuln_db_snapshots_org_tool_ver_hash",
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    tool_id: Mapped[str] = mapped_column(String(60), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(40), nullable=False)
    built_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    source_url: Mapped[str | None] = mapped_column(Text)
    db_archive_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    valid: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
        server_default=text("true"),
    )
    providers_metadata: Mapped[dict[str, Any]] = mapped_column(
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


class FindingEvent(Base):
    """Append-only lifecycle audit event recorded on finding triage, assignments, and retests."""

    __tablename__ = "finding_events"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
            name="fk_finding_events_org",
        ),
        ForeignKeyConstraint(
            ["organization_id", "finding_id"],
            ["findings.organization_id", "findings.id"],
            ondelete="CASCADE",
            name="fk_finding_events_org_finding",
        ),
        UniqueConstraint("organization_id", "id", name="uq_finding_events_org_id_id"),
        Index(
            "ix_finding_events_org_finding_created",
            "organization_id",
            "finding_id",
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
    finding_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_users.id", ondelete="SET NULL"),
    )
    event_type: Mapped[str] = mapped_column(String(50), nullable=False)
    previous_status: Mapped[str | None] = mapped_column(String(30))
    new_status: Mapped[str | None] = mapped_column(String(30))
    comment: Mapped[str | None] = mapped_column(Text)
    metadata_payload: Mapped[dict[str, Any]] = mapped_column(
        "metadata",
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


class RiskException(Base):
    """Time-bound risk acceptance requested and approved for a specific canonical finding."""

    __tablename__ = "risk_exceptions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
            name="fk_risk_exceptions_org",
        ),
        ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["projects.organization_id", "projects.id"],
            ondelete="RESTRICT",
            name="fk_risk_exceptions_org_project",
        ),
        ForeignKeyConstraint(
            ["organization_id", "finding_id"],
            ["findings.organization_id", "findings.id"],
            ondelete="CASCADE",
            name="fk_risk_exceptions_org_finding",
        ),
        UniqueConstraint("organization_id", "id", name="uq_risk_exceptions_org_id_id"),
        CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'expired', 'revoked')",
            name="ck_risk_exceptions_status",
        ),
        Index(
            "ix_risk_exceptions_org_proj_status",
            "organization_id",
            "project_id",
            "status",
        ),
        Index("ix_risk_exceptions_org_finding", "organization_id", "finding_id"),
        Index("ix_risk_exceptions_org_expires", "organization_id", "expires_at"),
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
    status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="pending",
        server_default=text("'pending'"),
    )
    requested_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_users.id", ondelete="RESTRICT"),
    )
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    mitigating_controls: Mapped[str] = mapped_column(Text, nullable=False)
    review_notes: Mapped[str | None] = mapped_column(Text)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
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


class Report(Base):
    """Executive, technical, compliance, or SARIF report generated for a project or scan run."""

    __tablename__ = "reports"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
            name="fk_reports_org",
        ),
        ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["projects.organization_id", "projects.id"],
            ondelete="RESTRICT",
            name="fk_reports_org_project",
        ),
        ForeignKeyConstraint(
            ["organization_id", "scan_run_id"],
            ["scan_runs.organization_id", "scan_runs.id"],
            ondelete="SET NULL",
            name="fk_reports_org_scan_run",
        ),
        ForeignKeyConstraint(
            ["organization_id", "artifact_id"],
            ["artifacts.organization_id", "artifacts.id"],
            ondelete="RESTRICT",
            name="fk_reports_org_artifact",
        ),
        UniqueConstraint("organization_id", "id", name="uq_reports_org_id_id"),
        CheckConstraint(
            "report_type IN ('executive', 'technical_vapt', 'compliance_summary', 'sarif_export')",
            name="ck_reports_type",
        ),
        CheckConstraint(
            "format IN ('html', 'pdf', 'json', 'sarif')",
            name="ck_reports_format",
        ),
        Index("ix_reports_org_proj_created", "organization_id", "project_id", "created_at"),
        Index("ix_reports_org_run", "organization_id", "scan_run_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    project_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    scan_run_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True))
    report_type: Mapped[str] = mapped_column(String(30), nullable=False)
    format: Mapped[str] = mapped_column(String(20), nullable=False)
    title: Mapped[str] = mapped_column(Text, nullable=False)
    summary: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    artifact_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    generated_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
