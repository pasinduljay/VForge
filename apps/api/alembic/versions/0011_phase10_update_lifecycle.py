"""Phase 10 Release & Update Lifecycle Management schema and initial catalog seed."""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0011_phase10_update_lifecycle"
down_revision = "0010_phase9_threat_intel"
branch_labels = None
depends_on = None

_IMMUTABLE_TABLES = (
    "update_test_results",
    "update_audit_events",
)


def upgrade() -> None:
    # 1. tool_catalog: canonical registry across the 4 streams & 10 channels
    op.create_table(
        "tool_catalog",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("tool_slug", sa.String(length=80), nullable=False),
        sa.Column("display_name", sa.String(length=120), nullable=False),
        sa.Column("stream", sa.String(length=50), nullable=False),
        sa.Column("update_channel", sa.String(length=60), nullable=False),
        sa.Column("adapter_family", sa.String(length=80), nullable=False),
        sa.Column("source_registry", sa.Text(), nullable=False),
        sa.Column(
            "automerge_allowed",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("true"),
        ),
        sa.Column(
            "metadata_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_tool_catalog"),
        sa.UniqueConstraint("tool_slug", name="uq_tool_catalog_slug"),
        sa.CheckConstraint(
            "stream IN ("
            "'engines_and_base_images', 'rules_templates_addons', "
            "'vulnerability_intel_dbs', 'adapters_and_dependencies')",
            name="ck_tool_catalog_stream",
        ),
        sa.CheckConstraint(
            "update_channel IN ("
            "'scanner_engine_versions', 'container_base_images', "
            "'scanner_addons', 'scanner_rules_and_templates', "
            "'vulnerability_databases', 'threat_intelligence_feeds', "
            "'ai_models', 'ai_rule_packs_and_skills', "
            "'application_dependencies', 'cryptographic_and_security_components')",
            name="ck_tool_catalog_channel",
        ),
    )
    op.create_index(
        "ix_tool_catalog_stream_active",
        "tool_catalog",
        ["stream", "is_active"],
    )

    # 2. tool_versions: immutable digest-pinned tool/component releases
    op.create_table(
        "tool_versions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("tool_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("version_tag", sa.String(length=80), nullable=False),
        sa.Column("image_repository", sa.Text(), nullable=False),
        sa.Column("image_digest", sa.String(length=80), nullable=False),
        sa.Column(
            "adapter_version",
            sa.String(length=40),
            nullable=False,
            server_default=sa.text("'1.0.0'"),
        ),
        sa.Column(
            "approval_channel",
            sa.String(length=30),
            nullable=False,
            server_default=sa.text("'candidate'"),
        ),
        sa.Column(
            "is_active_stable",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "is_active_canary",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "previous_stable_version_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column(
            "signature_verified",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("sbom_digest", sa.String(length=80), nullable=True),
        sa.Column("release_notes_url", sa.Text(), nullable=True),
        sa.Column(
            "metadata_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rolled_back_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_tool_versions"),
        sa.ForeignKeyConstraint(
            ["tool_id"],
            ["tool_catalog.id"],
            name="fk_tool_versions_tool",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["previous_stable_version_id"],
            ["tool_versions.id"],
            name="fk_tool_versions_prev_stable",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("tool_id", "image_digest", name="uq_tool_versions_tool_digest"),
        sa.CheckConstraint(
            "lower(btrim(version_tag)) <> 'latest' AND lower(btrim(version_tag)) !~ ':latest$'",
            name="ck_tool_versions_not_latest_tag",
        ),
        sa.CheckConstraint(
            "lower(btrim(image_repository)) !~ ':latest$'",
            name="ck_tool_versions_not_latest_repo",
        ),
        sa.CheckConstraint(
            "image_digest ~ '^sha256:[0-9a-f]{64}$'",
            name="ck_tool_versions_sha256_digest",
        ),
        sa.CheckConstraint(
            "approval_channel IN ("
            "'candidate', 'validated', 'approved', 'canary', "
            "'stable', 'rejected', 'rolled_back')",
            name="ck_tool_versions_approval_channel",
        ),
    )
    op.create_index(
        "uq_tool_versions_active_stable",
        "tool_versions",
        ["tool_id"],
        unique=True,
        postgresql_where=sa.text("is_active_stable = true"),
    )
    op.create_index(
        "uq_tool_versions_active_canary",
        "tool_versions",
        ["tool_id"],
        unique=True,
        postgresql_where=sa.text("is_active_canary = true"),
    )
    op.create_index(
        "ix_tool_versions_tool_channel",
        "tool_versions",
        ["tool_id", "approval_channel", "created_at"],
    )

    # 3. tool_updates: controlled update workflow state machine
    op.create_table(
        "tool_updates",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("tool_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("candidate_version_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("previous_version_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("stream", sa.String(length=50), nullable=False),
        sa.Column("update_channel", sa.String(length=60), nullable=False),
        sa.Column(
            "change_type",
            sa.String(length=30),
            nullable=False,
            server_default=sa.text("'patch'"),
        ),
        sa.Column(
            "status",
            sa.String(length=30),
            nullable=False,
            server_default=sa.text("'detected'"),
        ),
        sa.Column(
            "is_emergency",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column("emergency_justification", sa.Text(), nullable=True),
        sa.Column(
            "detected_from",
            sa.String(length=120),
            nullable=False,
            server_default=sa.text("'update-controller'"),
        ),
        sa.Column("approved_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("promoted_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rolled_back_by_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("rolled_back_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rollback_reason", sa.Text(), nullable=True),
        sa.Column("rejection_reason", sa.Text(), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_tool_updates"),
        sa.ForeignKeyConstraint(
            ["tool_id"],
            ["tool_catalog.id"],
            name="fk_tool_updates_tool",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["candidate_version_id"],
            ["tool_versions.id"],
            name="fk_tool_updates_candidate_version",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["previous_version_id"],
            ["tool_versions.id"],
            name="fk_tool_updates_previous_version",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["approved_by_user_id"],
            ["app_users.id"],
            name="fk_tool_updates_approved_by",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["promoted_by_user_id"],
            ["app_users.id"],
            name="fk_tool_updates_promoted_by",
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["rolled_back_by_user_id"],
            ["app_users.id"],
            name="fk_tool_updates_rolled_back_by",
            ondelete="SET NULL",
        ),
        sa.CheckConstraint(
            "stream IN ("
            "'engines_and_base_images', 'rules_templates_addons', "
            "'vulnerability_intel_dbs', 'adapters_and_dependencies')",
            name="ck_tool_updates_stream",
        ),
        sa.CheckConstraint(
            "change_type IN ('patch', 'minor', 'major', 'security', 'feed_refresh')",
            name="ck_tool_updates_change_type",
        ),
        sa.CheckConstraint(
            "status IN ("
            "'detected', 'validating', 'validated', 'approved', "
            "'canary', 'stable', 'rejected', 'rolled_back')",
            name="ck_tool_updates_status",
        ),
    )
    op.create_index("ix_tool_updates_status_created", "tool_updates", ["status", "created_at"])
    op.create_index("ix_tool_updates_tool_created", "tool_updates", ["tool_id", "created_at"])

    # 4. feed_snapshots: versioned DB/template snapshots with rollback pointer
    op.create_table(
        "feed_snapshots",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("tool_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("feed_slug", sa.String(length=80), nullable=False),
        sa.Column("stream", sa.String(length=50), nullable=False),
        sa.Column("update_channel", sa.String(length=60), nullable=False),
        sa.Column("snapshot_tag", sa.String(length=100), nullable=False),
        sa.Column("archive_sha256", sa.String(length=64), nullable=False),
        sa.Column(
            "schema_version",
            sa.String(length=40),
            nullable=False,
            server_default=sa.text("'v1'"),
        ),
        sa.Column(
            "record_count",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column(
            "approval_channel",
            sa.String(length=30),
            nullable=False,
            server_default=sa.text("'candidate'"),
        ),
        sa.Column(
            "is_active_stable",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "is_active_canary",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
        sa.Column(
            "previous_stable_snapshot_id",
            postgresql.UUID(as_uuid=True),
            nullable=True,
        ),
        sa.Column("source_url", sa.Text(), nullable=True),
        sa.Column(
            "metadata_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("rolled_back_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_feed_snapshots"),
        sa.ForeignKeyConstraint(
            ["tool_id"],
            ["tool_catalog.id"],
            name="fk_feed_snapshots_tool",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["previous_stable_snapshot_id"],
            ["feed_snapshots.id"],
            name="fk_feed_snapshots_prev_stable",
            ondelete="SET NULL",
        ),
        sa.UniqueConstraint("feed_slug", "snapshot_tag", name="uq_feed_snapshots_slug_tag"),
        sa.CheckConstraint(
            "lower(btrim(snapshot_tag)) <> 'latest' AND lower(btrim(snapshot_tag)) !~ ':latest$'",
            name="ck_feed_snapshots_not_latest_tag",
        ),
        sa.CheckConstraint(
            "archive_sha256 ~ '^[0-9a-f]{64}$'",
            name="ck_feed_snapshots_sha256",
        ),
        sa.CheckConstraint(
            "approval_channel IN ("
            "'candidate', 'validated', 'approved', 'canary', "
            "'stable', 'rejected', 'rolled_back')",
            name="ck_feed_snapshots_approval_channel",
        ),
    )
    op.create_index(
        "uq_feed_snapshots_active_stable",
        "feed_snapshots",
        ["feed_slug"],
        unique=True,
        postgresql_where=sa.text("is_active_stable = true"),
    )
    op.create_index(
        "uq_feed_snapshots_active_canary",
        "feed_snapshots",
        ["feed_slug"],
        unique=True,
        postgresql_where=sa.text("is_active_canary = true"),
    )
    op.create_index(
        "ix_feed_snapshots_slug_created",
        "feed_snapshots",
        ["feed_slug", "created_at"],
    )

    # 5. update_test_results: append-only validation gate evidence
    op.create_table(
        "update_test_results",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("update_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tool_version_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("test_category", sa.String(length=50), nullable=False),
        sa.Column("outcome", sa.String(length=20), nullable=False),
        sa.Column("summary", sa.Text(), nullable=False),
        sa.Column(
            "details_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("executed_by", sa.String(length=120), nullable=False),
        sa.Column(
            "executed_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_update_test_results"),
        sa.ForeignKeyConstraint(
            ["update_id"],
            ["tool_updates.id"],
            name="fk_update_test_results_update",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tool_version_id"],
            ["tool_versions.id"],
            name="fk_update_test_results_version",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "test_category IN ("
            "'signature_provenance', 'sbom_and_image_scan', "
            "'adapter_contract', 'regression_corpus')",
            name="ck_update_test_results_category",
        ),
        sa.CheckConstraint(
            "outcome IN ('passed', 'failed', 'skipped')",
            name="ck_update_test_results_outcome",
        ),
    )
    op.create_index(
        "ix_update_test_results_update_exec",
        "update_test_results",
        ["update_id", "executed_at"],
    )

    # 6. update_audit_events: append-only release governance audit log
    op.create_table(
        "update_audit_events",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("update_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("tool_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("tool_version_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("feed_snapshot_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("action", sa.String(length=40), nullable=False),
        sa.Column("actor_user_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("actor_email", sa.String(length=320), nullable=True),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column(
            "details_json",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_update_audit_events"),
        sa.ForeignKeyConstraint(
            ["update_id"],
            ["tool_updates.id"],
            name="fk_update_audit_events_update",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tool_id"],
            ["tool_catalog.id"],
            name="fk_update_audit_events_tool",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["tool_version_id"],
            ["tool_versions.id"],
            name="fk_update_audit_events_version",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["feed_snapshot_id"],
            ["feed_snapshots.id"],
            name="fk_update_audit_events_feed",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["actor_user_id"],
            ["app_users.id"],
            name="fk_update_audit_events_actor",
            ondelete="SET NULL",
        ),
        sa.CheckConstraint(
            "action IN ("
            "'candidate_detected', 'validation_recorded', 'approved', 'emergency_approved', "
            "'promoted_canary', 'promoted_stable', 'rejected', 'rolled_back', "
            "'feed_promoted', 'feed_rolled_back')",
            name="ck_update_audit_events_action",
        ),
    )
    op.create_index(
        "ix_update_audit_events_tool_occurred",
        "update_audit_events",
        ["tool_id", "occurred_at"],
    )
    op.create_index(
        "ix_update_audit_events_update_occurred",
        "update_audit_events",
        ["update_id", "occurred_at"],
    )

    # 7. Immutable scan run provenance pin snapshot column
    op.add_column(
        "scan_runs",
        sa.Column(
            "tool_version_pins",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
    )

    # 8. Append-only triggers on immutable evidence & audit tables
    op.execute(
        """
        CREATE OR REPLACE FUNCTION prevent_phase10_immutable_mutation()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'Table % is strictly append-only; updates and deletes are forbidden.',
                TG_TABLE_NAME
                USING ERRCODE = '55000';
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    for imm_table in _IMMUTABLE_TABLES:
        op.execute(
            f"""
            CREATE TRIGGER trg_{imm_table}_append_only
            BEFORE UPDATE OR DELETE ON {imm_table}
            FOR EACH ROW EXECUTE FUNCTION prevent_phase10_immutable_mutation();
            """
        )

    # 9. Least-privilege runtime grants for vforge_app
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vforge_app') THEN
                GRANT SELECT, INSERT, UPDATE ON tool_catalog TO vforge_app;
                REVOKE DELETE ON tool_catalog FROM vforge_app;

                GRANT SELECT, INSERT, UPDATE ON tool_versions TO vforge_app;
                REVOKE DELETE ON tool_versions FROM vforge_app;

                GRANT SELECT, INSERT, UPDATE ON tool_updates TO vforge_app;
                REVOKE DELETE ON tool_updates FROM vforge_app;

                GRANT SELECT, INSERT, UPDATE ON feed_snapshots TO vforge_app;
                REVOKE DELETE ON feed_snapshots FROM vforge_app;

                GRANT SELECT, INSERT ON update_test_results TO vforge_app;
                REVOKE UPDATE, DELETE ON update_test_results FROM vforge_app;

                GRANT SELECT, INSERT ON update_audit_events TO vforge_app;
                REVOKE UPDATE, DELETE ON update_audit_events FROM vforge_app;
            END IF;
        END $$;
        """
    )

    # 10. Seed baseline catalog, stable tool versions matching config.py, and baseline feeds
    op.execute(  # noqa: E501
        """
        WITH seeded_tools AS (
            INSERT INTO tool_catalog (
                tool_slug, display_name, stream, update_channel,
                adapter_family, source_registry, automerge_allowed, metadata_json
            )
            VALUES
                ('opengrep', 'OpenGrep SAST Engine', 'engines_and_base_images', 'scanner_engine_versions', 'sast_opengrep', 'ghcr.io/opengrep', false, '{"lock_file": "lifecycle/image-lock/phase5-images.json"}'::jsonb),
                ('gitleaks', 'Gitleaks Secrets Engine', 'engines_and_base_images', 'scanner_engine_versions', 'secrets_gitleaks', 'docker.io/zricethezav/gitleaks', false, '{"lock_file": "lifecycle/image-lock/phase5-images.json"}'::jsonb),
                ('syft', 'Anchore Syft SBOM Engine', 'engines_and_base_images', 'scanner_engine_versions', 'sbom_syft', 'docker.io/anchore/syft', false, '{"lock_file": "lifecycle/image-lock/phase6-images.json"}'::jsonb),
                ('grype', 'Anchore Grype SCA Engine', 'engines_and_base_images', 'scanner_engine_versions', 'sca_grype', 'docker.io/anchore/grype', false, '{"lock_file": "lifecycle/image-lock/phase6-images.json"}'::jsonb),
                ('checkov', 'Bridgecrew Checkov IaC Engine', 'engines_and_base_images', 'scanner_engine_versions', 'iac_checkov', 'docker.io/bridgecrew/checkov', false, '{"lock_file": "lifecycle/image-lock/phase6-images.json"}'::jsonb),
                ('zap', 'OWASP ZAP DAST Engine', 'engines_and_base_images', 'scanner_engine_versions', 'dast_zap', 'ghcr.io/zaproxy/zaproxy', false, '{"lock_file": "lifecycle/image-lock/phase7-images.json"}'::jsonb),
                ('nuclei', 'ProjectDiscovery Nuclei Engine', 'engines_and_base_images', 'scanner_engine_versions', 'dast_nuclei', 'docker.io/projectdiscovery/nuclei', false, '{"lock_file": "lifecycle/image-lock/phase7-images.json"}'::jsonb),
                ('nmap', 'Nmap Network Discovery Engine', 'engines_and_base_images', 'scanner_engine_versions', 'network_nmap', 'docker.io/instrumentisto/nmap', false, '{"lock_file": "lifecycle/image-lock/phase7-images.json"}'::jsonb),
                ('testssl', 'testssl.sh TLS Engine', 'engines_and_base_images', 'scanner_engine_versions', 'tls_testssl', 'docker.io/drwetter/testssl.sh', false, '{"lock_file": "lifecycle/image-lock/phase7-images.json"}'::jsonb),
                ('nuclei-templates', 'Nuclei Community Templates Pack', 'rules_templates_addons', 'scanner_rules_and_templates', 'dast_nuclei', 'https://github.com/projectdiscovery/nuclei-templates', true, '{}'::jsonb),
                ('grype-db', 'Anchore Grype Vulnerability DB', 'vulnerability_intel_dbs', 'vulnerability_databases', 'sca_grype', 'https://toolbox-data.anchore.io/grype/databases', true, '{}'::jsonb),
                ('vforge-platform-deps', 'VForge Python & Node Dependencies', 'adapters_and_dependencies', 'application_dependencies', 'platform_core', 'renovate.json', false, '{}'::jsonb)
            ON CONFLICT (tool_slug) DO NOTHING
            RETURNING id, tool_slug
        ),
        catalog_lookup AS (
            SELECT id, tool_slug FROM seeded_tools
            UNION
            SELECT id, tool_slug FROM tool_catalog
        )
        INSERT INTO tool_versions (
            tool_id, version_tag, image_repository, image_digest, adapter_version,
            approval_channel, is_active_stable, is_active_canary, signature_verified,
            promoted_at, metadata_json
        )
        SELECT
            c.id, v.version_tag, v.image_repository, v.image_digest, v.adapter_version,
            'stable', true, false, true, now(), '{"seeded": true}'::jsonb
        FROM catalog_lookup c
        JOIN (
            VALUES
                ('opengrep', '1.33.1', 'vforge-opengrep:1.33.1', 'sha256:a92cb260fea66c388fdf32924ae67ae933be6f13473e3e5c945182c1e4c01365', '1.0.0'),
                ('gitleaks', '8.24.0', 'zricethezav/gitleaks', 'sha256:2bcceac45179b3a91bff11a824d0fb952585b429e54fc928728b1d4d5c3e5176', '1.0.0'),
                ('syft', '1.57.1', 'anchore/syft', 'sha256:03215d0e98b661d0ecbc8575dbc14d65be1743b5de5df6410aecb7e80f95b060', '1.0.0'),
                ('grype', '0.121.3', 'anchore/grype', 'sha256:13113eeceab017260370cf540e1d25442c59665fd07d1b09b66d63bb0c282887', '1.0.0'),
                ('checkov', '3.2.435', 'bridgecrew/checkov', 'sha256:ccead19bd9201d43872ceb7e78bb5868eabfc0d3960d3756fc75f4896067372a', '1.0.0'),
                ('zap', '2.16.0', 'ghcr.io/zaproxy/zaproxy', 'sha256:391f66efa53b30de40d4a1c6e28146477263552fc828bc7613c9cd11a2949908', '1.0.0'),
                ('nuclei', '3.11.1', 'projectdiscovery/nuclei', 'sha256:582d5546902e67052097cb2d07296c642d50a1afc5e44623cb038845df9a32eb', '1.0.0'),
                ('nmap', '7.98', 'instrumentisto/nmap', 'sha256:96f6ed194519b62421a1a1c57809e65a7f94d2aa1c8c25676f247e5e148c0827', '1.0.0'),
                ('testssl', '3.2.5', 'drwetter/testssl.sh', 'sha256:e42cb1ba9445ea861e8b6eec96b97f6f293ce4e5908eebc75c28bdd96d66108e', '1.0.0')
        ) AS v(tool_slug, version_tag, image_repository, image_digest, adapter_version)
            ON v.tool_slug = c.tool_slug
        ON CONFLICT (tool_id, image_digest) DO NOTHING;

        INSERT INTO feed_snapshots (
            tool_id, feed_slug, stream, update_channel, snapshot_tag, archive_sha256,
            schema_version, record_count, approval_channel, is_active_stable, is_active_canary,
            source_url, promoted_at, metadata_json
        )
        SELECT
            c.id, f.feed_slug, f.stream, f.update_channel, f.snapshot_tag, f.archive_sha256,
            f.schema_version, f.record_count, 'stable', true, false,
            f.source_url, now(), '{"seeded": true}'::jsonb
        FROM tool_catalog c
        JOIN (
            VALUES
                ('grype-db', 'grype-db', 'vulnerability_intel_dbs', 'vulnerability_databases', 'v5-2026-11-12', '1111111111111111111111111111111111111111111111111111111111111111', 'v5', 245000, 'https://toolbox-data.anchore.io/grype/databases'),
                ('nuclei-templates', 'nuclei-templates', 'rules_templates_addons', 'scanner_rules_and_templates', 'v10.1.0', '2222222222222222222222222222222222222222222222222222222222222222', 'v10', 9800, 'https://github.com/projectdiscovery/nuclei-templates')
        ) AS f(tool_slug, feed_slug, stream, update_channel, snapshot_tag, archive_sha256, schema_version, record_count, source_url)
            ON f.tool_slug = c.tool_slug
        ON CONFLICT (feed_slug, snapshot_tag) DO NOTHING;
        """  # noqa: E501
    )


def downgrade() -> None:
    for imm_table in _IMMUTABLE_TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS trg_{imm_table}_append_only ON {imm_table};")
    op.execute("DROP FUNCTION IF EXISTS prevent_phase10_immutable_mutation();")

    op.drop_column("scan_runs", "tool_version_pins")

    op.drop_index("ix_update_audit_events_update_occurred", table_name="update_audit_events")
    op.drop_index("ix_update_audit_events_tool_occurred", table_name="update_audit_events")
    op.drop_table("update_audit_events")

    op.drop_index("ix_update_test_results_update_exec", table_name="update_test_results")
    op.drop_table("update_test_results")

    op.drop_index("ix_feed_snapshots_slug_created", table_name="feed_snapshots")
    op.drop_index("uq_feed_snapshots_active_canary", table_name="feed_snapshots")
    op.drop_index("uq_feed_snapshots_active_stable", table_name="feed_snapshots")
    op.drop_table("feed_snapshots")

    op.drop_index("ix_tool_updates_tool_created", table_name="tool_updates")
    op.drop_index("ix_tool_updates_status_created", table_name="tool_updates")
    op.drop_table("tool_updates")

    op.drop_index("ix_tool_versions_tool_channel", table_name="tool_versions")
    op.drop_index("uq_tool_versions_active_canary", table_name="tool_versions")
    op.drop_index("uq_tool_versions_active_stable", table_name="tool_versions")
    op.drop_table("tool_versions")

    op.drop_index("ix_tool_catalog_stream_active", table_name="tool_catalog")
    op.drop_table("tool_catalog")
