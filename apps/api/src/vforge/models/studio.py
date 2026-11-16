"""Phase 11 Rule & Skill Studio tenant-isolated SQLAlchemy models."""

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


class RulePack(Base):
    """Tenant-scoped custom or curated VForge detection rule pack."""

    __tablename__ = "rule_packs"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_rule_packs_org_id_id"),
        UniqueConstraint("organization_id", "slug", name="uq_rule_packs_org_slug"),
        Index("ix_rule_packs_org_active", "organization_id", "is_active"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    slug: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    owner_team: Mapped[str] = mapped_column(
        String(120),
        nullable=False,
        default="security-engineering",
        server_default=text("'security-engineering'"),
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(
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

    versions: Mapped[list[RulePackVersion]] = relationship(
        back_populates="rule_pack",
        cascade="all, delete-orphan",
        order_by="RulePackVersion.created_at.desc()",
    )


class RulePackVersion(Base):
    """Immutable-once-signed semantic version of a VForge RulePack."""

    __tablename__ = "rule_pack_versions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "rule_pack_id"],
            ["rule_packs.organization_id", "rule_packs.id"],
            ondelete="CASCADE",
            name="fk_rpv_org_pack",
        ),
        UniqueConstraint("organization_id", "id", name="uq_rpv_org_id_id"),
        UniqueConstraint(
            "organization_id", "rule_pack_id", "version", name="uq_rpv_org_pack_version"
        ),
        CheckConstraint(
            "semver_change_type IN ('patch', 'minor', 'major')",
            name="ck_rpv_semver_change",
        ),
        CheckConstraint(
            "channel IN ('draft', 'candidate', 'canary', 'stable', 'rolled_back', 'quarantined')",
            name="ck_rpv_channel",
        ),
        CheckConstraint(
            "review_status IN ('draft', 'pending_review', 'approved', 'rejected', "
            "'changes_requested')",
            name="ck_rpv_review_status",
        ),
        CheckConstraint(
            "creation_method IN ('human', 'ai_assisted', 'upstream')",
            name="ck_rpv_creation_method",
        ),
        CheckConstraint(
            "author_actor_type IN ('human', 'ai_agent', 'system')",
            name="ck_rpv_author_actor_type",
        ),
        CheckConstraint(
            "reviewer_id IS NULL OR reviewer_id IS DISTINCT FROM author_id",
            name="ck_rpv_reviewer_not_author",
        ),
        CheckConstraint(
            "signed_by IS NULL OR signed_by IS DISTINCT FROM author_id",
            name="ck_rpv_signer_not_author",
        ),
        CheckConstraint(
            "NOT fixture_regression_passed OR "
            "(false_positive_count = 0 AND false_negative_count = 0)",
            name="ck_rpv_regression_zero_errors",
        ),
        CheckConstraint(
            "(NOT is_active_canary OR channel = 'canary') AND "
            "(NOT is_active_stable OR channel = 'stable')",
            name="ck_rpv_channel_active_consistency",
        ),
        CheckConstraint(
            "signed_at IS NULL OR (review_status = 'approved' "
            "AND fixture_regression_passed = true)",
            name="ck_rpv_signed_requires_approval",
        ),
        CheckConstraint(
            "channel IN ('draft', 'rolled_back', 'quarantined') OR "
            "(review_status = 'approved' AND fixture_regression_passed = true "
            "AND manifest_signature IS NOT NULL)",
            name="ck_rpv_promoted_requires_signed_approval",
        ),
        Index(
            "uq_rpv_active_canary",
            "organization_id",
            "rule_pack_id",
            unique=True,
            postgresql_where=text("is_active_canary = true"),
        ),
        Index(
            "uq_rpv_active_stable",
            "organization_id",
            "rule_pack_id",
            unique=True,
            postgresql_where=text("is_active_stable = true"),
        ),
        Index("ix_rpv_org_pack_created", "organization_id", "rule_pack_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    rule_pack_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    version: Mapped[str] = mapped_column(String(40), nullable=False)
    semver_change_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="minor",
        server_default=text("'minor'"),
    )
    channel: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="draft",
        server_default=text("'draft'"),
    )
    review_status: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="draft",
        server_default=text("'draft'"),
    )
    creation_method: Mapped[str] = mapped_column(
        String(30),
        nullable=False,
        default="human",
        server_default=text("'human'"),
    )
    author_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    author_actor_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        default="human",
        server_default=text("'human'"),
    )
    reviewer_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_users.id", ondelete="RESTRICT"),
    )
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rejection_reason: Mapped[str | None] = mapped_column(Text)
    compatibility_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    validation_summary_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    ai_provenance_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    manifest_payload_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        default=dict,
        server_default=text("'{}'::jsonb"),
    )
    manifest_sha256: Mapped[str | None] = mapped_column(String(64))
    manifest_signature: Mapped[str | None] = mapped_column(Text)
    signing_key_id: Mapped[str | None] = mapped_column(String(120))
    signed_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_users.id", ondelete="RESTRICT"),
    )
    signed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    is_active_canary: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    is_active_stable: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    fixture_regression_passed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        server_default=text("false"),
    )
    true_positive_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    false_positive_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
    )
    false_negative_count: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
        server_default=text("0"),
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

    rule_pack: Mapped[RulePack] = relationship(back_populates="versions")
    rules: Mapped[list[StudioRule]] = relationship(
        back_populates="pack_version",
        cascade="all, delete-orphan",
        order_by="StudioRule.rule_key",
    )
    fixture_runs: Mapped[list[RuleFixtureRun]] = relationship(
        back_populates="pack_version",
        cascade="all, delete-orphan",
        order_by="RuleFixtureRun.created_at.desc()",
    )


class StudioRule(Base):
    """Native scanner detection rule inside a RulePackVersion."""

    __tablename__ = "rules"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "rule_pack_version_id"],
            ["rule_pack_versions.organization_id", "rule_pack_versions.id"],
            ondelete="CASCADE",
            name="fk_rules_org_version",
        ),
        UniqueConstraint("organization_id", "id", name="uq_rules_org_id_id"),
        UniqueConstraint(
            "organization_id", "rule_pack_version_id", "rule_key", name="uq_rules_org_ver_key"
        ),
        CheckConstraint(
            "engine IN ('opengrep', 'nuclei', 'checkov', 'gitleaks', 'zap', 'nmap')",
            name="ck_rules_engine",
        ),
        CheckConstraint(
            "risk_class IN ('static', 'passive', 'active', 'privileged_network')",
            name="ck_rules_risk_class",
        ),
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name="ck_rules_severity",
        ),
        CheckConstraint(
            "confidence IN ('high', 'medium', 'low', 'heuristic')",
            name="ck_rules_confidence",
        ),
        CheckConstraint(
            "timeout_seconds >= 1 AND timeout_seconds <= 3600", name="ck_rules_timeout"
        ),
        CheckConstraint(
            "memory_budget_mb >= 32 AND memory_budget_mb <= 8192", name="ck_rules_memory"
        ),
        Index("ix_rules_org_ver", "organization_id", "rule_pack_version_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    rule_pack_version_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    rule_key: Mapped[str] = mapped_column(String(120), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    engine: Mapped[str] = mapped_column(String(30), nullable=False)
    native_format: Mapped[str] = mapped_column(String(30), nullable=False)
    risk_class: Mapped[str] = mapped_column(String(30), nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    confidence: Mapped[str] = mapped_column(String(20), nullable=False)
    cwe_id: Mapped[str] = mapped_column(String(40), nullable=False)
    rationale: Mapped[str] = mapped_column(Text, nullable=False)
    target_context: Mapped[str] = mapped_column(
        String(120),
        nullable=False,
        default="source_code",
        server_default=text("'source_code'"),
    )
    network_requirements: Mapped[str] = mapped_column(
        String(120),
        nullable=False,
        default="none",
        server_default=text("'none'"),
    )
    known_limitations: Mapped[str] = mapped_column(Text, nullable=False)
    timeout_seconds: Mapped[int] = mapped_column(
        Integer, nullable=False, default=30, server_default=text("30")
    )
    memory_budget_mb: Mapped[int] = mapped_column(
        Integer, nullable=False, default=256, server_default=text("256")
    )
    native_content: Mapped[str] = mapped_column(Text, nullable=False)
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    positive_fixtures_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    negative_fixtures_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    near_miss_fixtures_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    expected_evidence_fields: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    static_validation_passed: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    static_validation_errors: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    pack_version: Mapped[RulePackVersion] = relationship(back_populates="rules")


class RuleFixtureRun(Base):
    """Immutable append-only record of fixture corpus regression execution."""

    __tablename__ = "rule_fixture_runs"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "rule_pack_version_id"],
            ["rule_pack_versions.organization_id", "rule_pack_versions.id"],
            ondelete="CASCADE",
            name="fk_rfr_org_version",
        ),
        CheckConstraint(
            "actor_type IN ('human', 'ai_agent', 'system')",
            name="ck_rfr_actor_type",
        ),
        Index("ix_rfr_org_ver_created", "organization_id", "rule_pack_version_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    rule_pack_version_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    corpus_ref: Mapped[str] = mapped_column(String(200), nullable=False)
    corpus_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    executed_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    actor_type: Mapped[str] = mapped_column(
        String(20), nullable=False, default="human", server_default=text("'human'")
    )
    total_positive: Mapped[int] = mapped_column(Integer, nullable=False)
    passed_positive: Mapped[int] = mapped_column(Integer, nullable=False)
    total_negative: Mapped[int] = mapped_column(Integer, nullable=False)
    passed_negative: Mapped[int] = mapped_column(Integer, nullable=False)
    total_near_miss: Mapped[int] = mapped_column(Integer, nullable=False)
    passed_near_miss: Mapped[int] = mapped_column(Integer, nullable=False)
    false_positives: Mapped[int] = mapped_column(Integer, nullable=False)
    false_negatives: Mapped[int] = mapped_column(Integer, nullable=False)
    total_duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    regression_passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    rule_results_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    pack_version: Mapped[RulePackVersion] = relationship(back_populates="fixture_runs")


class AssessmentSkill(Base):
    """Tenant-scoped bounded AI assessment playbook identity."""

    __tablename__ = "skills"
    __table_args__ = (
        UniqueConstraint("organization_id", "id", name="uq_skills_org_id_id"),
        UniqueConstraint("organization_id", "slug", name="uq_skills_org_slug"),
        Index("ix_skills_org_active", "organization_id", "is_active"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    slug: Mapped[str] = mapped_column(String(100), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="", server_default="")
    owner_team: Mapped[str] = mapped_column(
        String(120),
        nullable=False,
        default="appsec-ai",
        server_default=text("'appsec-ai'"),
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
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

    versions: Mapped[list[SkillVersion]] = relationship(
        back_populates="skill",
        cascade="all, delete-orphan",
        order_by="SkillVersion.created_at.desc()",
    )


class SkillVersion(Base):
    """Versioned, reviewed, and signed constrained AI assessment playbook."""

    __tablename__ = "skill_versions"
    __table_args__ = (
        ForeignKeyConstraint(
            ["organization_id", "skill_id"],
            ["skills.organization_id", "skills.id"],
            ondelete="CASCADE",
            name="fk_sv_org_skill",
        ),
        UniqueConstraint("organization_id", "id", name="uq_sv_org_id_id"),
        UniqueConstraint("organization_id", "skill_id", "version", name="uq_sv_org_skill_ver"),
        CheckConstraint(
            "channel IN ('draft', 'candidate', 'canary', 'stable', 'rolled_back', 'quarantined')",
            name="ck_sv_channel",
        ),
        CheckConstraint(
            "review_status IN ('draft', 'pending_review', 'approved', 'rejected', "
            "'changes_requested')",
            name="ck_sv_review_status",
        ),
        CheckConstraint(
            "creation_method IN ('human', 'ai_assisted', 'upstream')",
            name="ck_sv_creation_method",
        ),
        CheckConstraint(
            "author_actor_type IN ('human', 'ai_agent', 'system')",
            name="ck_sv_author_actor_type",
        ),
        CheckConstraint(
            "reviewer_id IS NULL OR reviewer_id IS DISTINCT FROM author_id",
            name="ck_sv_reviewer_not_author",
        ),
        CheckConstraint(
            "signed_by IS NULL OR signed_by IS DISTINCT FROM author_id",
            name="ck_sv_signer_not_author",
        ),
        CheckConstraint(
            "(NOT is_active_canary OR channel = 'canary') AND "
            "(NOT is_active_stable OR channel = 'stable')",
            name="ck_sv_channel_active_consistency",
        ),
        CheckConstraint(
            "signed_at IS NULL OR review_status = 'approved'",
            name="ck_sv_signed_requires_approval",
        ),
        CheckConstraint(
            "channel IN ('draft', 'rolled_back', 'quarantined') OR "
            "(review_status = 'approved' AND signature IS NOT NULL)",
            name="ck_sv_promoted_requires_signed_approval",
        ),
        Index(
            "uq_sv_active_canary",
            "organization_id",
            "skill_id",
            unique=True,
            postgresql_where=text("is_active_canary = true"),
        ),
        Index(
            "uq_sv_active_stable",
            "organization_id",
            "skill_id",
            unique=True,
            postgresql_where=text("is_active_stable = true"),
        ),
        Index("ix_sv_org_skill_created", "organization_id", "skill_id", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    skill_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    version: Mapped[str] = mapped_column(String(40), nullable=False)
    intent_description: Mapped[str] = mapped_column(Text, nullable=False)
    allowed_capabilities: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    forbidden_actions: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    supported_agent_versions: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    playbook_steps_json: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=text("'[]'::jsonb")
    )
    creation_method: Mapped[str] = mapped_column(
        String(30), nullable=False, default="human", server_default=text("'human'")
    )
    author_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    author_actor_type: Mapped[str] = mapped_column(
        String(20), nullable=False, default="human", server_default=text("'human'")
    )
    review_status: Mapped[str] = mapped_column(
        String(30), nullable=False, default="draft", server_default=text("'draft'")
    )
    reviewer_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_users.id", ondelete="RESTRICT"),
    )
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    rejection_reason: Mapped[str | None] = mapped_column(Text)
    ai_provenance_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    manifest_payload_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    signature: Mapped[str | None] = mapped_column(Text)
    signing_key_id: Mapped[str | None] = mapped_column(String(120))
    signed_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_users.id", ondelete="RESTRICT"),
    )
    signed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    channel: Mapped[str] = mapped_column(
        String(30), nullable=False, default="draft", server_default=text("'draft'")
    )
    is_active_canary: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
    )
    is_active_stable: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False, server_default=text("false")
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

    skill: Mapped[AssessmentSkill] = relationship(back_populates="versions")


class StudioAuditEvent(Base):
    """Immutable append-only audit log for Rule & Skill Studio operations."""

    __tablename__ = "studio_audit_events"
    __table_args__ = (
        CheckConstraint(
            "entity_type IN ('rule_pack', 'rule_pack_version', 'skill', 'skill_version')",
            name="ck_sae_entity_type",
        ),
        CheckConstraint(
            "actor_type IN ('human', 'ai_agent', 'system')",
            name="ck_sae_actor_type",
        ),
        Index("ix_sae_org_occurred", "organization_id", "occurred_at"),
        Index("ix_sae_org_entity", "organization_id", "entity_type", "entity_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        server_default=text("gen_random_uuid()"),
    )
    organization_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("organizations.id", ondelete="CASCADE"),
        nullable=False,
    )
    entity_type: Mapped[str] = mapped_column(String(40), nullable=False)
    entity_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)
    action: Mapped[str] = mapped_column(String(60), nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("app_users.id", ondelete="RESTRICT"),
    )
    actor_email: Mapped[str] = mapped_column(String(320), nullable=False)
    actor_type: Mapped[str] = mapped_column(
        String(20), nullable=False, default="human", server_default=text("'human'")
    )
    previous_state: Mapped[str | None] = mapped_column(String(40))
    new_state: Mapped[str | None] = mapped_column(String(40))
    details_json: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=text("'{}'::jsonb")
    )
    occurred_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
