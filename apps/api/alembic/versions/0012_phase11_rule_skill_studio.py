"""Phase 11 Rule & Skill Studio tenant-isolated schema and RLS controls."""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0012_phase11_rule_skill_studio"
down_revision = "0011_phase10_update_lifecycle"
branch_labels = None
depends_on = None

_ALL_TENANT_TABLES = (
    "rule_packs",
    "rule_pack_versions",
    "rules",
    "rule_fixture_runs",
    "skills",
    "skill_versions",
    "studio_audit_events",
)

_IMMUTABLE_TENANT_TABLES = (
    "rule_fixture_runs",
    "studio_audit_events",
)


def upgrade() -> None:
    # 1. rule_packs
    op.create_table(
        "rule_packs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("slug", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), server_default="", nullable=False),
        sa.Column(
            "owner_team",
            sa.String(length=120),
            server_default=sa.text("'security-engineering'"),
            nullable=False,
        ),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["created_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "id", name="uq_rule_packs_org_id_id"),
        sa.UniqueConstraint("organization_id", "slug", name="uq_rule_packs_org_slug"),
    )
    op.create_index("ix_rule_packs_org_active", "rule_packs", ["organization_id", "is_active"])

    # 2. rule_pack_versions
    op.create_table(
        "rule_pack_versions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("rule_pack_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version", sa.String(length=40), nullable=False),
        sa.Column(
            "semver_change_type",
            sa.String(length=20),
            server_default=sa.text("'minor'"),
            nullable=False,
        ),
        sa.Column(
            "channel", sa.String(length=30), server_default=sa.text("'draft'"), nullable=False
        ),
        sa.Column(
            "review_status",
            sa.String(length=30),
            server_default=sa.text("'draft'"),
            nullable=False,
        ),
        sa.Column(
            "creation_method",
            sa.String(length=30),
            server_default=sa.text("'human'"),
            nullable=False,
        ),
        sa.Column("author_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "author_actor_type",
            sa.String(length=20),
            server_default=sa.text("'human'"),
            nullable=False,
        ),
        sa.Column("reviewer_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column(
            "compatibility_json",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "validation_summary_json",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "ai_provenance_json",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "manifest_payload_json",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("manifest_sha256", sa.String(length=64), nullable=True),
        sa.Column("manifest_signature", sa.Text(), nullable=True),
        sa.Column("signing_key_id", sa.String(length=120), nullable=True),
        sa.Column("signed_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("signed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "is_active_canary", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column(
            "is_active_stable", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column(
            "fixture_regression_passed",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column("true_positive_count", sa.Integer(), server_default=sa.text("0"), nullable=False),
        sa.Column(
            "false_positive_count", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column(
            "false_negative_count", sa.Integer(), server_default=sa.text("0"), nullable=False
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "semver_change_type IN ('patch', 'minor', 'major')", name="ck_rpv_semver_change"
        ),
        sa.CheckConstraint(
            "channel IN ('draft', 'candidate', 'canary', 'stable', 'rolled_back', 'quarantined')",
            name="ck_rpv_channel",
        ),
        sa.CheckConstraint(
            "review_status IN ('draft', 'pending_review', 'approved', 'rejected', "
            "'changes_requested')",
            name="ck_rpv_review_status",
        ),
        sa.CheckConstraint(
            "creation_method IN ('human', 'ai_assisted', 'upstream')",
            name="ck_rpv_creation_method",
        ),
        sa.CheckConstraint(
            "author_actor_type IN ('human', 'ai_agent', 'system')",
            name="ck_rpv_author_actor_type",
        ),
        sa.CheckConstraint(
            "reviewer_id IS NULL OR reviewer_id IS DISTINCT FROM author_id",
            name="ck_rpv_reviewer_not_author",
        ),
        sa.CheckConstraint(
            "signed_by IS NULL OR signed_by IS DISTINCT FROM author_id",
            name="ck_rpv_signer_not_author",
        ),
        sa.CheckConstraint(
            "NOT fixture_regression_passed OR "
            "(false_positive_count = 0 AND false_negative_count = 0)",
            name="ck_rpv_regression_zero_errors",
        ),
        sa.CheckConstraint(
            "(NOT is_active_canary OR channel = 'canary') AND "
            "(NOT is_active_stable OR channel = 'stable')",
            name="ck_rpv_channel_active_consistency",
        ),
        sa.CheckConstraint(
            "signed_at IS NULL OR (review_status = 'approved' "
            "AND fixture_regression_passed = true)",
            name="ck_rpv_signed_requires_approval",
        ),
        sa.CheckConstraint(
            "channel IN ('draft', 'rolled_back', 'quarantined') OR "
            "(review_status = 'approved' AND fixture_regression_passed = true "
            "AND manifest_signature IS NOT NULL)",
            name="ck_rpv_promoted_requires_signed_approval",
        ),
        sa.ForeignKeyConstraint(["author_id"], ["app_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["reviewer_id"], ["app_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["signed_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["organization_id", "rule_pack_id"],
            ["rule_packs.organization_id", "rule_packs.id"],
            ondelete="CASCADE",
            name="fk_rpv_org_pack",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "id", name="uq_rpv_org_id_id"),
        sa.UniqueConstraint(
            "organization_id", "rule_pack_id", "version", name="uq_rpv_org_pack_version"
        ),
    )
    op.create_index(
        "uq_rpv_active_canary",
        "rule_pack_versions",
        ["organization_id", "rule_pack_id"],
        unique=True,
        postgresql_where=sa.text("is_active_canary = true"),
    )
    op.create_index(
        "uq_rpv_active_stable",
        "rule_pack_versions",
        ["organization_id", "rule_pack_id"],
        unique=True,
        postgresql_where=sa.text("is_active_stable = true"),
    )
    op.create_index(
        "ix_rpv_org_pack_created",
        "rule_pack_versions",
        ["organization_id", "rule_pack_id", "created_at"],
    )

    # 3. rules
    op.create_table(
        "rules",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("rule_pack_version_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("rule_key", sa.String(length=120), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("engine", sa.String(length=30), nullable=False),
        sa.Column("native_format", sa.String(length=30), nullable=False),
        sa.Column("risk_class", sa.String(length=30), nullable=False),
        sa.Column("severity", sa.String(length=20), nullable=False),
        sa.Column("confidence", sa.String(length=20), nullable=False),
        sa.Column("cwe_id", sa.String(length=40), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=False),
        sa.Column(
            "target_context",
            sa.String(length=120),
            server_default=sa.text("'source_code'"),
            nullable=False,
        ),
        sa.Column(
            "network_requirements",
            sa.String(length=120),
            server_default=sa.text("'none'"),
            nullable=False,
        ),
        sa.Column("known_limitations", sa.Text(), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), server_default=sa.text("30"), nullable=False),
        sa.Column("memory_budget_mb", sa.Integer(), server_default=sa.text("256"), nullable=False),
        sa.Column("native_content", sa.Text(), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "positive_fixtures_json",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "negative_fixtures_json",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "near_miss_fixtures_json",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "expected_evidence_fields",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "static_validation_passed",
            sa.Boolean(),
            server_default=sa.text("false"),
            nullable=False,
        ),
        sa.Column(
            "static_validation_errors",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "engine IN ('opengrep', 'nuclei', 'checkov', 'gitleaks', 'zap', 'nmap')",
            name="ck_rules_engine",
        ),
        sa.CheckConstraint(
            "risk_class IN ('static', 'passive', 'active', 'privileged_network')",
            name="ck_rules_risk_class",
        ),
        sa.CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'info')",
            name="ck_rules_severity",
        ),
        sa.CheckConstraint(
            "confidence IN ('high', 'medium', 'low', 'heuristic')",
            name="ck_rules_confidence",
        ),
        sa.CheckConstraint(
            "timeout_seconds >= 1 AND timeout_seconds <= 3600", name="ck_rules_timeout"
        ),
        sa.CheckConstraint(
            "memory_budget_mb >= 32 AND memory_budget_mb <= 8192", name="ck_rules_memory"
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "rule_pack_version_id"],
            ["rule_pack_versions.organization_id", "rule_pack_versions.id"],
            ondelete="CASCADE",
            name="fk_rules_org_version",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "id", name="uq_rules_org_id_id"),
        sa.UniqueConstraint(
            "organization_id", "rule_pack_version_id", "rule_key", name="uq_rules_org_ver_key"
        ),
    )
    op.create_index("ix_rules_org_ver", "rules", ["organization_id", "rule_pack_version_id"])

    # 4. rule_fixture_runs (immutable)
    op.create_table(
        "rule_fixture_runs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("rule_pack_version_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("corpus_ref", sa.String(length=200), nullable=False),
        sa.Column("corpus_sha256", sa.String(length=64), nullable=False),
        sa.Column("executed_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "actor_type", sa.String(length=20), server_default=sa.text("'human'"), nullable=False
        ),
        sa.Column("total_positive", sa.Integer(), nullable=False),
        sa.Column("passed_positive", sa.Integer(), nullable=False),
        sa.Column("total_negative", sa.Integer(), nullable=False),
        sa.Column("passed_negative", sa.Integer(), nullable=False),
        sa.Column("total_near_miss", sa.Integer(), nullable=False),
        sa.Column("passed_near_miss", sa.Integer(), nullable=False),
        sa.Column("false_positives", sa.Integer(), nullable=False),
        sa.Column("false_negatives", sa.Integer(), nullable=False),
        sa.Column("total_duration_ms", sa.Integer(), nullable=False),
        sa.Column("regression_passed", sa.Boolean(), nullable=False),
        sa.Column(
            "rule_results_json",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "actor_type IN ('human', 'ai_agent', 'system')", name="ck_rfr_actor_type"
        ),
        sa.ForeignKeyConstraint(["executed_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["organization_id", "rule_pack_version_id"],
            ["rule_pack_versions.organization_id", "rule_pack_versions.id"],
            ondelete="CASCADE",
            name="fk_rfr_org_version",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_rfr_org_ver_created",
        "rule_fixture_runs",
        ["organization_id", "rule_pack_version_id", "created_at"],
    )

    # 5. skills
    op.create_table(
        "skills",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("slug", sa.String(length=100), nullable=False),
        sa.Column("title", sa.String(length=200), nullable=False),
        sa.Column("description", sa.Text(), server_default="", nullable=False),
        sa.Column(
            "owner_team",
            sa.String(length=120),
            server_default=sa.text("'appsec-ai'"),
            nullable=False,
        ),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("is_active", sa.Boolean(), server_default=sa.text("true"), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["created_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "id", name="uq_skills_org_id_id"),
        sa.UniqueConstraint("organization_id", "slug", name="uq_skills_org_slug"),
    )
    op.create_index("ix_skills_org_active", "skills", ["organization_id", "is_active"])

    # 6. skill_versions
    op.create_table(
        "skill_versions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("skill_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version", sa.String(length=40), nullable=False),
        sa.Column("intent_description", sa.Text(), nullable=False),
        sa.Column(
            "allowed_capabilities",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "forbidden_actions",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "supported_agent_versions",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "playbook_steps_json",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "creation_method",
            sa.String(length=30),
            server_default=sa.text("'human'"),
            nullable=False,
        ),
        sa.Column("author_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "author_actor_type",
            sa.String(length=20),
            server_default=sa.text("'human'"),
            nullable=False,
        ),
        sa.Column(
            "review_status",
            sa.String(length=30),
            server_default=sa.text("'draft'"),
            nullable=False,
        ),
        sa.Column("reviewer_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column(
            "ai_provenance_json",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "manifest_payload_json",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("signature", sa.Text(), nullable=True),
        sa.Column("signing_key_id", sa.String(length=120), nullable=True),
        sa.Column("signed_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("signed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "channel", sa.String(length=30), server_default=sa.text("'draft'"), nullable=False
        ),
        sa.Column(
            "is_active_canary", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column(
            "is_active_stable", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "channel IN ('draft', 'candidate', 'canary', 'stable', 'rolled_back', 'quarantined')",
            name="ck_sv_channel",
        ),
        sa.CheckConstraint(
            "review_status IN ('draft', 'pending_review', 'approved', 'rejected', "
            "'changes_requested')",
            name="ck_sv_review_status",
        ),
        sa.CheckConstraint(
            "creation_method IN ('human', 'ai_assisted', 'upstream')",
            name="ck_sv_creation_method",
        ),
        sa.CheckConstraint(
            "author_actor_type IN ('human', 'ai_agent', 'system')",
            name="ck_sv_author_actor_type",
        ),
        sa.CheckConstraint(
            "reviewer_id IS NULL OR reviewer_id IS DISTINCT FROM author_id",
            name="ck_sv_reviewer_not_author",
        ),
        sa.CheckConstraint(
            "signed_by IS NULL OR signed_by IS DISTINCT FROM author_id",
            name="ck_sv_signer_not_author",
        ),
        sa.CheckConstraint(
            "(NOT is_active_canary OR channel = 'canary') AND "
            "(NOT is_active_stable OR channel = 'stable')",
            name="ck_sv_channel_active_consistency",
        ),
        sa.CheckConstraint(
            "signed_at IS NULL OR review_status = 'approved'",
            name="ck_sv_signed_requires_approval",
        ),
        sa.CheckConstraint(
            "channel IN ('draft', 'rolled_back', 'quarantined') OR "
            "(review_status = 'approved' AND signature IS NOT NULL)",
            name="ck_sv_promoted_requires_signed_approval",
        ),
        sa.ForeignKeyConstraint(["author_id"], ["app_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["reviewer_id"], ["app_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["signed_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["organization_id", "skill_id"],
            ["skills.organization_id", "skills.id"],
            ondelete="CASCADE",
            name="fk_sv_org_skill",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "id", name="uq_sv_org_id_id"),
        sa.UniqueConstraint("organization_id", "skill_id", "version", name="uq_sv_org_skill_ver"),
    )
    op.create_index(
        "uq_sv_active_canary",
        "skill_versions",
        ["organization_id", "skill_id"],
        unique=True,
        postgresql_where=sa.text("is_active_canary = true"),
    )
    op.create_index(
        "uq_sv_active_stable",
        "skill_versions",
        ["organization_id", "skill_id"],
        unique=True,
        postgresql_where=sa.text("is_active_stable = true"),
    )
    op.create_index(
        "ix_sv_org_skill_created",
        "skill_versions",
        ["organization_id", "skill_id", "created_at"],
    )

    # 7. studio_audit_events (immutable)
    op.create_table(
        "studio_audit_events",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("entity_type", sa.String(length=40), nullable=False),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("action", sa.String(length=60), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("actor_email", sa.String(length=320), nullable=False),
        sa.Column(
            "actor_type", sa.String(length=20), server_default=sa.text("'human'"), nullable=False
        ),
        sa.Column("previous_state", sa.String(length=40), nullable=True),
        sa.Column("new_state", sa.String(length=40), nullable=True),
        sa.Column(
            "details_json",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "entity_type IN ('rule_pack', 'rule_pack_version', 'skill', 'skill_version')",
            name="ck_sae_entity_type",
        ),
        sa.CheckConstraint(
            "actor_type IN ('human', 'ai_agent', 'system')",
            name="ck_sae_actor_type",
        ),
        sa.ForeignKeyConstraint(["actor_id"], ["app_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_sae_org_occurred", "studio_audit_events", ["organization_id", "occurred_at"]
    )
    op.create_index(
        "ix_sae_org_entity",
        "studio_audit_events",
        ["organization_id", "entity_type", "entity_id"],
    )

    # 8. Historical rule_pack_pins provenance column on scan_runs
    op.add_column(
        "scan_runs",
        sa.Column(
            "rule_pack_pins",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
    )

    # 9. Row-Level Security (RLS) on all Phase 11 tenant tables
    for tbl in _ALL_TENANT_TABLES:
        op.execute(f"ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {tbl} FORCE ROW LEVEL SECURITY;")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation_{tbl} ON {tbl}
            FOR ALL
            TO vforge_app
            USING (
                organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
            )
            WITH CHECK (
                organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
            );
            """
        )

    # 10. Append-only & signed-immutability triggers
    op.execute(
        """
        CREATE OR REPLACE FUNCTION prevent_phase11_immutable_mutation()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'Table % is strictly append-only; updates and deletes are forbidden.',
                TG_TABLE_NAME
                USING ERRCODE = '55000';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    for imm_table in _IMMUTABLE_TENANT_TABLES:
        op.execute(
            f"""
            CREATE TRIGGER trg_{imm_table}_append_only
            BEFORE UPDATE OR DELETE ON {imm_table}
            FOR EACH ROW EXECUTE FUNCTION prevent_phase11_immutable_mutation();
            """
        )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION prevent_phase11_signed_pack_mutation()
        RETURNS TRIGGER AS $$
        BEGIN
            IF TG_OP = 'DELETE' AND OLD.signed_at IS NOT NULL THEN
                RAISE EXCEPTION 'Signed rule_pack_versions cannot be deleted.'
                    USING ERRCODE = '55000';
            END IF;
            IF TG_OP = 'UPDATE' AND OLD.signed_at IS NOT NULL THEN
                IF NEW.version IS DISTINCT FROM OLD.version
                    OR NEW.author_id IS DISTINCT FROM OLD.author_id
                    OR NEW.reviewer_id IS DISTINCT FROM OLD.reviewer_id
                    OR NEW.review_status IS DISTINCT FROM OLD.review_status
                    OR NEW.fixture_regression_passed IS DISTINCT FROM OLD.fixture_regression_passed
                    OR NEW.true_positive_count IS DISTINCT FROM OLD.true_positive_count
                    OR NEW.false_positive_count IS DISTINCT FROM OLD.false_positive_count
                    OR NEW.false_negative_count IS DISTINCT FROM OLD.false_negative_count
                    OR NEW.compatibility_json IS DISTINCT FROM OLD.compatibility_json
                    OR NEW.manifest_payload_json IS DISTINCT FROM OLD.manifest_payload_json
                    OR NEW.manifest_sha256 IS DISTINCT FROM OLD.manifest_sha256
                    OR NEW.manifest_signature IS DISTINCT FROM OLD.manifest_signature
                    OR NEW.signing_key_id IS DISTINCT FROM OLD.signing_key_id
                    OR NEW.signed_by IS DISTINCT FROM OLD.signed_by
                    OR NEW.signed_at IS DISTINCT FROM OLD.signed_at
                THEN
                    RAISE EXCEPTION 'Signed rule_pack_versions payload is immutable.'
                        USING ERRCODE = '55000';
                END IF;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        CREATE TRIGGER trg_rule_pack_versions_signed_immutable
        BEFORE UPDATE OR DELETE ON rule_pack_versions
        FOR EACH ROW EXECUTE FUNCTION prevent_phase11_signed_pack_mutation();

        CREATE OR REPLACE FUNCTION prevent_phase11_signed_skill_mutation()
        RETURNS TRIGGER AS $$
        BEGIN
            IF TG_OP = 'DELETE' AND OLD.signed_at IS NOT NULL THEN
                RAISE EXCEPTION 'Signed skill_versions cannot be deleted.'
                    USING ERRCODE = '55000';
            END IF;
            IF TG_OP = 'UPDATE' AND OLD.signed_at IS NOT NULL THEN
                IF NEW.version IS DISTINCT FROM OLD.version
                    OR NEW.intent_description IS DISTINCT FROM OLD.intent_description
                    OR NEW.allowed_capabilities IS DISTINCT FROM OLD.allowed_capabilities
                    OR NEW.forbidden_actions IS DISTINCT FROM OLD.forbidden_actions
                    OR NEW.supported_agent_versions IS DISTINCT FROM OLD.supported_agent_versions
                    OR NEW.playbook_steps_json IS DISTINCT FROM OLD.playbook_steps_json
                    OR NEW.author_id IS DISTINCT FROM OLD.author_id
                    OR NEW.reviewer_id IS DISTINCT FROM OLD.reviewer_id
                    OR NEW.review_status IS DISTINCT FROM OLD.review_status
                    OR NEW.content_sha256 IS DISTINCT FROM OLD.content_sha256
                    OR NEW.manifest_payload_json IS DISTINCT FROM OLD.manifest_payload_json
                    OR NEW.signature IS DISTINCT FROM OLD.signature
                    OR NEW.signing_key_id IS DISTINCT FROM OLD.signing_key_id
                    OR NEW.signed_by IS DISTINCT FROM OLD.signed_by
                    OR NEW.signed_at IS DISTINCT FROM OLD.signed_at
                THEN
                    RAISE EXCEPTION 'Signed skill_versions payload is immutable.'
                        USING ERRCODE = '55000';
                END IF;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        CREATE TRIGGER trg_skill_versions_signed_immutable
        BEFORE UPDATE OR DELETE ON skill_versions
        FOR EACH ROW EXECUTE FUNCTION prevent_phase11_signed_skill_mutation();

        CREATE OR REPLACE FUNCTION prevent_phase11_signed_rule_mutation()
        RETURNS TRIGGER AS $$
        DECLARE
            target_version_id UUID;
            is_signed BOOLEAN;
        BEGIN
            target_version_id := COALESCE(NEW.rule_pack_version_id, OLD.rule_pack_version_id);
            SELECT (rpv.signed_at IS NOT NULL)
            INTO is_signed
            FROM rule_pack_versions rpv
            WHERE rpv.id = target_version_id;
            IF COALESCE(is_signed, false) THEN
                RAISE EXCEPTION 'Rules belonging to a signed rule_pack_version are immutable.'
                    USING ERRCODE = '55000';
            END IF;
            IF TG_OP = 'DELETE' THEN
                RETURN OLD;
            END IF;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
        CREATE TRIGGER trg_rules_signed_immutable
        BEFORE INSERT OR UPDATE OR DELETE ON rules
        FOR EACH ROW EXECUTE FUNCTION prevent_phase11_signed_rule_mutation();
        """
    )

    # 11. Least-privilege runtime grants
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vforge_app') THEN
                GRANT SELECT, INSERT ON rule_fixture_runs, studio_audit_events TO vforge_app;
                REVOKE UPDATE, DELETE ON rule_fixture_runs, studio_audit_events FROM vforge_app;

                GRANT SELECT, INSERT, UPDATE ON
                    rule_packs, rule_pack_versions, skills, skill_versions
                    TO vforge_app;
                REVOKE DELETE ON
                    rule_packs, rule_pack_versions, skills, skill_versions
                    FROM vforge_app;

                GRANT SELECT, INSERT, UPDATE, DELETE ON rules TO vforge_app;
            END IF;
        END $$;
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS trg_rules_signed_immutable ON rules;")
    op.execute("DROP FUNCTION IF EXISTS prevent_phase11_signed_rule_mutation();")
    op.execute("DROP TRIGGER IF EXISTS trg_skill_versions_signed_immutable ON skill_versions;")
    op.execute("DROP FUNCTION IF EXISTS prevent_phase11_signed_skill_mutation();")
    op.execute(
        "DROP TRIGGER IF EXISTS trg_rule_pack_versions_signed_immutable ON rule_pack_versions;"
    )
    op.execute("DROP FUNCTION IF EXISTS prevent_phase11_signed_pack_mutation();")
    for imm_table in _IMMUTABLE_TENANT_TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS trg_{imm_table}_append_only ON {imm_table};")
    op.execute("DROP FUNCTION IF EXISTS prevent_phase11_immutable_mutation();")

    for tbl in _ALL_TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation_{tbl} ON {tbl};")
        op.execute(f"ALTER TABLE {tbl} NO FORCE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {tbl} DISABLE ROW LEVEL SECURITY;")

    op.drop_column("scan_runs", "rule_pack_pins")

    op.drop_index("ix_sae_org_entity", table_name="studio_audit_events")
    op.drop_index("ix_sae_org_occurred", table_name="studio_audit_events")
    op.drop_table("studio_audit_events")

    op.drop_index("ix_sv_org_skill_created", table_name="skill_versions")
    op.drop_index("uq_sv_active_stable", table_name="skill_versions")
    op.drop_index("uq_sv_active_canary", table_name="skill_versions")
    op.drop_table("skill_versions")

    op.drop_index("ix_skills_org_active", table_name="skills")
    op.drop_table("skills")

    op.drop_index("ix_rfr_org_ver_created", table_name="rule_fixture_runs")
    op.drop_table("rule_fixture_runs")

    op.drop_index("ix_rules_org_ver", table_name="rules")
    op.drop_table("rules")

    op.drop_index("ix_rpv_org_pack_created", table_name="rule_pack_versions")
    op.drop_index("uq_rpv_active_stable", table_name="rule_pack_versions")
    op.drop_index("uq_rpv_active_canary", table_name="rule_pack_versions")
    op.drop_table("rule_pack_versions")

    op.drop_index("ix_rule_packs_org_active", table_name="rule_packs")
    op.drop_table("rule_packs")
