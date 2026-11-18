"""Phase 2 scope snapshots, authorization scoping metadata, and asset versioning

Revision ID: 0003_phase2_scope_snapshots
Revises: 0002_phase1_domain_rls
Create Date: 2026-11-12 12:00:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0003_phase2_scope_snapshots"
down_revision: str | Sequence[str] | None = "0002_phase1_domain_rls"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column(
            "version",
            sa.Integer(),
            nullable=False,
            server_default=sa.text("1"),
        ),
    )

    op.add_column(
        "authorizations",
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "authorizations",
        sa.Column("environment_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.execute(
        """
        UPDATE authorizations AS az
        SET environment_id = a.environment_id,
            project_id = e.project_id
        FROM assets AS a
        JOIN environments AS e
          ON e.id = a.environment_id
         AND e.organization_id = a.organization_id
        WHERE az.asset_id = a.id
          AND az.organization_id = a.organization_id;
        """
    )
    op.alter_column("authorizations", "project_id", nullable=False)
    op.alter_column("authorizations", "environment_id", nullable=False)

    op.add_column(
        "authorizations",
        sa.Column(
            "permitted_intensity",
            sa.String(length=20),
            nullable=False,
            server_default=sa.text("'passive'"),
        ),
    )
    op.add_column(
        "authorizations",
        sa.Column(
            "policy_version",
            sa.String(length=80),
            nullable=False,
            server_default=sa.text("'2026-11-12.v2'"),
        ),
    )
    op.add_column(
        "authorizations",
        sa.Column(
            "allow_private_networks",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )

    op.create_unique_constraint(
        "uq_authorizations_org_id_id",
        "authorizations",
        ["organization_id", "id"],
    )
    op.create_foreign_key(
        "fk_authorizations_org_project",
        "authorizations",
        "projects",
        ["organization_id", "project_id"],
        ["organization_id", "id"],
        ondelete="CASCADE",
    )
    op.create_foreign_key(
        "fk_authorizations_org_environment",
        "authorizations",
        "environments",
        ["organization_id", "environment_id"],
        ["organization_id", "id"],
        ondelete="CASCADE",
    )
    op.create_check_constraint(
        "ck_authorizations_intensity",
        "authorizations",
        "permitted_intensity IN ('passive', 'low', 'medium', 'high')",
    )

    op.create_table(
        "scope_snapshots",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("environment_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("authorization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("snapshot_version", sa.Integer(), nullable=False),
        sa.Column("asset_version", sa.Integer(), nullable=False),
        sa.Column("policy_version", sa.String(length=80), nullable=False),
        sa.Column("target_type", sa.String(length=40), nullable=False),
        sa.Column("canonical_locator", sa.Text(), nullable=False),
        sa.Column(
            "resolved_ips",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "allowed_ports",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "permitted_capabilities",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("permitted_intensity", sa.String(length=20), nullable=False),
        sa.Column(
            "scope_definition",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
        ),
        sa.Column("payload_sha256", sa.String(length=64), nullable=False),
        sa.Column("signing_key_id", sa.String(length=120), nullable=False),
        sa.Column(
            "signature_algorithm",
            sa.String(length=30),
            server_default=sa.text("'Ed25519'"),
            nullable=False,
        ),
        sa.Column("signature", sa.Text(), nullable=False),
        sa.Column(
            "authorization_expires_at",
            sa.DateTime(timezone=True),
            nullable=False,
        ),
        sa.Column("created_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("now()"),
            nullable=False,
        ),
        sa.CheckConstraint("snapshot_version >= 1", name="ck_scope_snapshots_version"),
        sa.CheckConstraint("asset_version >= 1", name="ck_scope_snapshots_asset_version"),
        sa.CheckConstraint(
            "permitted_intensity IN ('passive', 'low', 'medium', 'high')",
            name="ck_scope_snapshots_intensity",
        ),
        sa.ForeignKeyConstraint(
            ["created_by"],
            ["app_users.id"],
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "asset_id"],
            ["assets.organization_id", "assets.id"],
            ondelete="CASCADE",
            name="fk_scope_snapshots_org_asset",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "authorization_id"],
            ["authorizations.organization_id", "authorizations.id"],
            ondelete="CASCADE",
            name="fk_scope_snapshots_org_authorization",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "environment_id"],
            ["environments.organization_id", "environments.id"],
            ondelete="CASCADE",
            name="fk_scope_snapshots_org_environment",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["projects.organization_id", "projects.id"],
            ondelete="CASCADE",
            name="fk_scope_snapshots_org_project",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "authorization_id",
            "snapshot_version",
            name="uq_scope_snapshots_authz_version",
        ),
    )
    op.create_index(
        "ix_scope_snapshots_org_authz",
        "scope_snapshots",
        ["organization_id", "authorization_id", "snapshot_version"],
    )

    op.execute(
        """
        CREATE OR REPLACE FUNCTION prevent_scope_snapshots_mutation()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'scope_snapshots is immutable: % is not permitted', TG_OP;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_scope_snapshots_immutable
        BEFORE UPDATE OR DELETE ON scope_snapshots
        FOR EACH ROW EXECUTE FUNCTION prevent_scope_snapshots_mutation();
        """
    )

    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vforge_app') THEN
                GRANT SELECT, INSERT ON TABLE scope_snapshots TO vforge_app;
                REVOKE UPDATE, DELETE ON TABLE scope_snapshots FROM vforge_app;
            END IF;
        END $$;
        """
    )

    op.execute("ALTER TABLE scope_snapshots ENABLE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE scope_snapshots FORCE ROW LEVEL SECURITY;")
    op.execute(
        """
        CREATE POLICY p_scope_snapshots_select ON scope_snapshots
        FOR SELECT
        USING (
            organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
        );
        """
    )
    op.execute(
        """
        CREATE POLICY p_scope_snapshots_insert ON scope_snapshots
        FOR INSERT
        WITH CHECK (
            organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
        );
        """
    )


def downgrade() -> None:
    op.execute("ALTER TABLE scope_snapshots NO FORCE ROW LEVEL SECURITY;")
    op.execute("ALTER TABLE scope_snapshots DISABLE ROW LEVEL SECURITY;")
    op.execute("DROP POLICY IF EXISTS p_scope_snapshots_insert ON scope_snapshots;")
    op.execute("DROP POLICY IF EXISTS p_scope_snapshots_select ON scope_snapshots;")

    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vforge_app') THEN
                REVOKE ALL PRIVILEGES ON TABLE scope_snapshots FROM vforge_app;
            END IF;
        END $$;
        """
    )

    op.execute("DROP TRIGGER IF EXISTS trg_scope_snapshots_immutable ON scope_snapshots;")
    op.execute("DROP FUNCTION IF EXISTS prevent_scope_snapshots_mutation();")

    op.drop_index("ix_scope_snapshots_org_authz", table_name="scope_snapshots")
    op.drop_table("scope_snapshots")

    op.drop_constraint("ck_authorizations_intensity", "authorizations", type_="check")
    op.drop_constraint("fk_authorizations_org_environment", "authorizations", type_="foreignkey")
    op.drop_constraint("fk_authorizations_org_project", "authorizations", type_="foreignkey")
    op.drop_constraint("uq_authorizations_org_id_id", "authorizations", type_="unique")
    op.drop_column("authorizations", "allow_private_networks")
    op.drop_column("authorizations", "policy_version")
    op.drop_column("authorizations", "permitted_intensity")
    op.drop_column("authorizations", "environment_id")
    op.drop_column("authorizations", "project_id")
    op.drop_column("assets", "version")
