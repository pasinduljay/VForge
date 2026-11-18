"""Phase 14 Hardening, Key Epoch Registry, DR Backup Manifests & Restore Drills."""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0015_phase14_hardening_dr"
down_revision: str | None = "0014_phase13_learning_lab"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT_TABLES = (
    "encryption_key_records",
    "dr_backup_manifests",
    "dr_restore_drills",
    "hardening_audit_events",
)

_IMMUTABLE_TABLES = (
    "dr_restore_drills",
    "hardening_audit_events",
)


def upgrade() -> None:
    op.create_table(
        "encryption_key_records",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("key_id", sa.String(120), nullable=False),
        sa.Column("purpose", sa.String(40), nullable=False),
        sa.Column("algorithm_suite", sa.String(80), nullable=False),
        sa.Column(
            "pqc_readiness_status",
            sa.String(32),
            nullable=False,
            server_default=sa.text("'classical_active'"),
        ),
        sa.Column(
            "status",
            sa.String(24),
            nullable=False,
            server_default=sa.text("'active'"),
        ),
        sa.Column("version", sa.Integer(), nullable=False, server_default=sa.text("1")),
        sa.Column("key_fingerprint_sha256", sa.String(64), nullable=False),
        sa.Column(
            "owner_role",
            sa.String(64),
            nullable=False,
            server_default=sa.text("'security_ops'"),
        ),
        sa.Column("cryptoperiod_days", sa.Integer(), nullable=False, server_default=sa.text("90")),
        sa.Column(
            "activated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("rotate_after_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("rotated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
            name="fk_ekr_org",
        ),
        sa.UniqueConstraint("organization_id", "key_id", name="uq_ekr_org_key_id"),
        sa.UniqueConstraint(
            "organization_id", "purpose", "version", name="uq_ekr_org_purpose_version"
        ),
        sa.CheckConstraint(
            "purpose IN ("
            "'artifact_envelope', 'backup_envelope', 'scope_signing', 'runner_mtls_ca'"
            ")",
            name="ck_ekr_purpose",
        ),
        sa.CheckConstraint(
            "pqc_readiness_status IN ('classical_active', 'hybrid_planned', 'not_enabled')",
            name="ck_ekr_pqc_status",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'verify_only', 'rotated_out', 'revoked')",
            name="ck_ekr_status",
        ),
        sa.CheckConstraint("version >= 1", name="ck_ekr_version_pos"),
        sa.CheckConstraint("cryptoperiod_days >= 1", name="ck_ekr_cryptoperiod_pos"),
    )
    op.create_index(
        "ix_ekr_org_purpose_status",
        "encryption_key_records",
        ["organization_id", "purpose", "status"],
    )
    op.create_index(
        "ix_ekr_org_purpose_active",
        "encryption_key_records",
        ["organization_id", "purpose"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )

    op.create_table(
        "dr_backup_manifests",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("backup_scope", sa.String(48), nullable=False),
        sa.Column("storage_key", sa.String(255), nullable=False),
        sa.Column("encryption_key_id", sa.String(120), nullable=False),
        sa.Column(
            "encryption_algorithm",
            sa.String(32),
            nullable=False,
            server_default=sa.text("'AES-256-GCM'"),
        ),
        sa.Column("wrapped_dek_b64", sa.Text(), nullable=False),
        sa.Column("nonce_b64", sa.String(64), nullable=False),
        sa.Column("aad_b64", sa.Text(), nullable=False),
        sa.Column("plaintext_sha256", sa.String(64), nullable=False),
        sa.Column("ciphertext_sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False, server_default=sa.text("0")),
        sa.Column("row_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "status",
            sa.String(24),
            nullable=False,
            server_default=sa.text("'created'"),
        ),
        sa.Column("rpo_target_minutes", sa.Integer(), nullable=False, server_default=sa.text("60")),
        sa.Column("rto_target_minutes", sa.Integer(), nullable=False, server_default=sa.text("30")),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
            name="fk_dbm_org",
        ),
        sa.UniqueConstraint("organization_id", "id", name="uq_dbm_org_id_id"),
        sa.CheckConstraint(
            "backup_scope IN ("
            "'postgres_tenant_snapshot', 'artifact_bundle', 'full_control_plane_metadata'"
            ")",
            name="ck_dbm_scope",
        ),
        sa.CheckConstraint(
            "status IN ('created', 'verified', 'restored', 'failed', 'expired')",
            name="ck_dbm_status",
        ),
        sa.CheckConstraint("size_bytes >= 0", name="ck_dbm_size_nonneg"),
        sa.CheckConstraint("row_count >= 0", name="ck_dbm_rows_nonneg"),
        sa.CheckConstraint("rpo_target_minutes >= 1", name="ck_dbm_rpo_pos"),
        sa.CheckConstraint("rto_target_minutes >= 1", name="ck_dbm_rto_pos"),
    )
    op.create_index(
        "ix_dbm_org_created",
        "dr_backup_manifests",
        ["organization_id", "created_at"],
    )

    op.create_table(
        "dr_restore_drills",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("manifest_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("drill_mode", sa.String(48), nullable=False),
        sa.Column("rto_observed_seconds", sa.Integer(), nullable=False),
        sa.Column("integrity_verified", sa.Boolean(), nullable=False),
        sa.Column("decryption_verified", sa.Boolean(), nullable=False),
        sa.Column("schema_head_verified", sa.String(80), nullable=False),
        sa.Column("findings_summary", sa.Text(), nullable=False),
        sa.Column("status", sa.String(24), nullable=False),
        sa.Column("executed_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "manifest_id"],
            ["dr_backup_manifests.organization_id", "dr_backup_manifests.id"],
            ondelete="CASCADE",
            name="fk_drd_org_manifest",
        ),
        sa.CheckConstraint(
            "drill_mode IN ("
            "'isolated_checksum_decrypt', 'pg_schema_dry_run', 'ephemeral_restore_verify'"
            ")",
            name="ck_drd_mode",
        ),
        sa.CheckConstraint("status IN ('passed', 'failed')", name="ck_drd_status"),
    )
    op.create_index(
        "ix_drd_org_created",
        "dr_restore_drills",
        ["organization_id", "created_at"],
    )

    op.create_table(
        "hardening_audit_events",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            nullable=False,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("category", sa.String(40), nullable=False),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("outcome", sa.String(24), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("actor_email", sa.String(320), nullable=False),
        sa.Column(
            "details_json",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
            name="fk_hae_org",
        ),
        sa.CheckConstraint(
            "category IN ("
            "'key_rotation', 'cert_monitoring', 'openbao_check', "
            "'backup_created', 'restore_drill', 'security_self_test', 'crypto_agility'"
            ")",
            name="ck_hae_category",
        ),
        sa.CheckConstraint(
            "outcome IN ('allowed', 'denied', 'completed', 'failed')",
            name="ck_hae_outcome",
        ),
    )
    op.create_index(
        "ix_hae_org_occurred",
        "hardening_audit_events",
        ["organization_id", "occurred_at"],
    )

    for tbl in _TENANT_TABLES:
        op.execute(f"ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {tbl} FORCE ROW LEVEL SECURITY;")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation_{tbl} ON {tbl}
            USING (
                organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
            )
            WITH CHECK (
                organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
            );
            """
        )

    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vforge_app') THEN
                GRANT SELECT, INSERT, UPDATE ON
                    encryption_key_records, dr_backup_manifests
                    TO vforge_app;
                REVOKE DELETE ON
                    encryption_key_records, dr_backup_manifests
                    FROM vforge_app;

                GRANT SELECT, INSERT ON
                    dr_restore_drills, hardening_audit_events
                    TO vforge_app;
                REVOKE UPDATE, DELETE ON
                    dr_restore_drills, hardening_audit_events
                    FROM vforge_app;
            END IF;
        END $$;
        """
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION prevent_phase14_immutable_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION
                'Table % is append-only and cannot be mutated (%)',
                TG_TABLE_NAME, TG_OP;
        END;
        $$;
        """
    )

    for tbl in _IMMUTABLE_TABLES:
        op.execute(
            f"""
            CREATE TRIGGER trg_{tbl}_immutable
            BEFORE UPDATE OR DELETE ON {tbl}
            FOR EACH ROW EXECUTE FUNCTION prevent_phase14_immutable_mutation();
            """
        )


def downgrade() -> None:
    for tbl in _IMMUTABLE_TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS trg_{tbl}_immutable ON {tbl};")
    op.execute("DROP FUNCTION IF EXISTS prevent_phase14_immutable_mutation();")

    for tbl in reversed(_TENANT_TABLES):
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation_{tbl} ON {tbl};")
        op.execute(f"ALTER TABLE {tbl} DISABLE ROW LEVEL SECURITY;")
        op.drop_table(tbl)
