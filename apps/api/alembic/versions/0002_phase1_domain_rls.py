"""Phase 1 domain model, roles, append-only audit, and PostgreSQL RLS

Revision ID: 0002_phase1_domain_rls
Revises: 0001_phase0_foundation
Create Date: 2026-11-12 09:00:00+00:00
"""

from __future__ import annotations

import os
from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0002_phase1_domain_rls"
down_revision: str | Sequence[str] | None = "0001_phase0_foundation"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_TENANT_STRICT_TABLES = (
    "projects",
    "environments",
    "assets",
    "authorizations",
    "auth_profiles",
    "scan_profiles",
)


def upgrade() -> None:
    op.create_table(
        "organizations",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("slug", sa.String(length=100), nullable=False),
        sa.Column(
            "status",
            sa.String(length=20),
            server_default=sa.text("'active'"),
            nullable=False,
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
        sa.CheckConstraint(
            "status IN ('active', 'suspended', 'archived')",
            name="ck_organizations_status",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("slug"),
    )

    op.create_table(
        "app_users",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("oidc_issuer", sa.Text(), nullable=False),
        sa.Column("oidc_subject", sa.Text(), nullable=False),
        sa.Column("email", sa.Text(), nullable=False),
        sa.Column("display_name", sa.String(length=200), nullable=False),
        sa.Column(
            "status",
            sa.String(length=20),
            server_default=sa.text("'active'"),
            nullable=False,
        ),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
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
        sa.CheckConstraint(
            "status IN ('active', 'disabled', 'locked')",
            name="ck_app_users_status",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("oidc_issuer", "oidc_subject", name="uq_app_users_issuer_subject"),
    )

    op.create_table(
        "memberships",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("role", sa.String(length=30), nullable=False),
        sa.Column(
            "status",
            sa.String(length=20),
            server_default=sa.text("'active'"),
            nullable=False,
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
        sa.CheckConstraint(
            "role IN ('owner', 'admin', 'security_lead', 'security_analyst', "
            "'developer', 'auditor', 'viewer')",
            name="ck_memberships_role",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'invited', 'suspended', 'removed')",
            name="ck_memberships_status",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["user_id"], ["app_users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "user_id", name="uq_memberships_org_user"),
    )
    op.create_index("ix_memberships_user_org", "memberships", ["user_id", "organization_id"])

    op.create_table(
        "projects",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("slug", sa.String(length=120), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "criticality",
            sa.String(length=20),
            server_default=sa.text("'medium'"),
            nullable=False,
        ),
        sa.Column(
            "status",
            sa.String(length=20),
            server_default=sa.text("'active'"),
            nullable=False,
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
        sa.CheckConstraint(
            "criticality IN ('critical', 'high', 'medium', 'low')",
            name="ck_projects_criticality",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'archived')",
            name="ck_projects_status",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "id", name="uq_projects_org_id_id"),
        sa.UniqueConstraint("organization_id", "slug", name="uq_projects_org_slug"),
    )
    op.create_index("ix_projects_org_created", "projects", ["organization_id", "created_at"])

    op.create_table(
        "environments",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=100), nullable=False),
        sa.Column("environment_type", sa.String(length=30), nullable=False),
        sa.Column(
            "status",
            sa.String(length=20),
            server_default=sa.text("'active'"),
            nullable=False,
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
        sa.CheckConstraint(
            "environment_type IN ('development', 'testing', 'staging', "
            "'production', 'isolated_lab')",
            name="ck_environments_type",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'inactive', 'archived')",
            name="ck_environments_status",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["projects.organization_id", "projects.id"],
            name="fk_environments_org_project",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "id", name="uq_environments_org_id_id"),
        sa.UniqueConstraint("project_id", "name", name="uq_environments_project_name"),
    )
    op.create_index(
        "ix_environments_org_project",
        "environments",
        ["organization_id", "project_id"],
    )

    op.create_table(
        "assets",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("environment_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_type", sa.String(length=40), nullable=False),
        sa.Column("normalized_locator", sa.Text(), nullable=False),
        sa.Column(
            "scope_metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "registration_state",
            sa.String(length=30),
            server_default=sa.text("'registered'"),
            nullable=False,
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
        sa.CheckConstraint(
            "asset_type IN ('web_application', 'rest_api', 'source_repository', "
            "'container_image', 'ip_address', 'cidr_range', 'network_service', "
            "'infrastructure_definition')",
            name="ck_assets_type",
        ),
        sa.CheckConstraint(
            "registration_state IN ('registered', 'pending_verification', 'decommissioned')",
            name="ck_assets_registration_state",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "environment_id"],
            ["environments.organization_id", "environments.id"],
            name="fk_assets_org_environment",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "id", name="uq_assets_org_id_id"),
        sa.UniqueConstraint(
            "environment_id",
            "asset_type",
            "normalized_locator",
            name="uq_assets_env_type_locator",
        ),
    )
    op.create_index("ix_assets_org_env", "assets", ["organization_id", "environment_id"])

    op.create_table(
        "authorizations",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("requested_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("approved_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("revoked_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "approved_testing_scope",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "approved_activities",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("allowed_ports", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("authorization_reference", sa.String(length=200), nullable=False),
        sa.Column("valid_from", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "status",
            sa.String(length=20),
            server_default=sa.text("'pending'"),
            nullable=False,
        ),
        sa.Column("decision_reason", sa.Text(), nullable=True),
        sa.Column("revocation_reason", sa.Text(), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "audit_history",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
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
        sa.CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'expired', 'revoked')",
            name="ck_authorizations_status",
        ),
        sa.CheckConstraint("expires_at > valid_from", name="ck_authorizations_valid_window"),
        sa.CheckConstraint(
            "approved_by IS NULL OR approved_by <> requested_by",
            name="ck_authorizations_separation_of_duties",
        ),
        sa.ForeignKeyConstraint(["approved_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(
            ["organization_id", "asset_id"],
            ["assets.organization_id", "assets.id"],
            name="fk_authorizations_org_asset",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(["requested_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["revoked_by"], ["app_users.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_authorizations_org_asset_status",
        "authorizations",
        ["organization_id", "asset_id", "status"],
    )

    op.create_table(
        "auth_profiles",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("environment_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=150), nullable=False),
        sa.Column("auth_type", sa.String(length=40), nullable=False),
        sa.Column("secret_manager_ref", sa.Text(), nullable=False),
        sa.Column(
            "status",
            sa.String(length=20),
            server_default=sa.text("'active'"),
            nullable=False,
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
        sa.CheckConstraint(
            "auth_type IN ('oauth2_client_credentials', 'oidc_service_account', "
            "'api_key_ref', 'bearer_token_ref', 'basic_auth_ref', 'mtls_cert_ref', "
            "'session_cookie_ref')",
            name="ck_auth_profiles_type",
        ),
        sa.CheckConstraint(
            "status IN ('active', 'disabled', 'revoked')",
            name="ck_auth_profiles_status",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "environment_id"],
            ["environments.organization_id", "environments.id"],
            name="fk_auth_profiles_org_environment",
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("environment_id", "name", name="uq_auth_profiles_env_name"),
    )
    op.create_index(
        "ix_auth_profiles_org_env", "auth_profiles", ["organization_id", "environment_id"]
    )

    op.create_table(
        "scan_profiles",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("name", sa.String(length=150), nullable=False),
        sa.Column(
            "version",
            sa.Integer(),
            server_default=sa.text("1"),
            nullable=False,
        ),
        sa.Column("configuration", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column(
            "status",
            sa.String(length=20),
            server_default=sa.text("'active'"),
            nullable=False,
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
        sa.CheckConstraint("version >= 1", name="ck_scan_profiles_version"),
        sa.CheckConstraint(
            "status IN ('draft', 'active', 'deprecated', 'disabled')",
            name="ck_scan_profiles_status",
        ),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "name",
            "version",
            name="uq_scan_profiles_org_name_version",
        ),
    )
    op.create_index("ix_scan_profiles_org_name", "scan_profiles", ["organization_id", "name"])

    op.create_table(
        "audit_events",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("correlation_id", sa.String(length=64), nullable=True),
        sa.Column("action", sa.String(length=120), nullable=False),
        sa.Column("resource_type", sa.String(length=100), nullable=True),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column(
            "outcome",
            sa.String(length=20),
            server_default=sa.text("'success'"),
            nullable=False,
        ),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "outcome IN ('success', 'denied', 'failure')",
            name="ck_audit_events_outcome",
        ),
        sa.ForeignKeyConstraint(["actor_id"], ["app_users.id"], ondelete="SET NULL"),
        sa.ForeignKeyConstraint(["organization_id"], ["organizations.id"], ondelete="RESTRICT"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_audit_events_org_created", "audit_events", ["organization_id", "created_at"]
    )
    op.create_index("ix_audit_events_action", "audit_events", ["action"])

    op.create_table(
        "auth_sessions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("active_organization_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("token_hash", sa.String(length=64), nullable=False),
        sa.Column("csrf_token", sa.String(length=128), nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=True),
        sa.Column("user_agent", sa.String(length=512), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.ForeignKeyConstraint(
            ["active_organization_id"], ["organizations.id"], ondelete="SET NULL"
        ),
        sa.ForeignKeyConstraint(["user_id"], ["app_users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index("ix_auth_sessions_user_expires", "auth_sessions", ["user_id", "expires_at"])

    op.create_table(
        "oidc_auth_states",
        sa.Column("state_hash", sa.String(length=64), nullable=False),
        sa.Column("nonce_hash", sa.String(length=64), nullable=False),
        sa.Column("code_verifier", sa.String(length=256), nullable=False),
        sa.Column(
            "redirect_path",
            sa.String(length=512),
            server_default=sa.text("'/'"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("state_hash"),
    )
    op.create_index("ix_oidc_auth_states_expires", "oidc_auth_states", ["expires_at"])

    # Append-only trigger on audit_events
    op.execute(
        """
        CREATE OR REPLACE FUNCTION prevent_audit_events_mutation()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION 'audit_events is append-only: % is not permitted', TG_OP;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    op.execute(
        """
        CREATE TRIGGER trg_audit_events_append_only
        BEFORE UPDATE OR DELETE ON audit_events
        FOR EACH ROW EXECUTE FUNCTION prevent_audit_events_mutation();
        """
    )

    # Separate non-owner, NOBYPASSRLS application role
    op.execute(
        """
        DO $$
        DECLARE
            v_can_manage_roles boolean := false;
        BEGIN
            SELECT (rolsuper OR rolcreaterole) INTO v_can_manage_roles
            FROM pg_roles
            WHERE rolname = current_user;

            IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vforge_app') THEN
                IF v_can_manage_roles THEN
                    CREATE ROLE vforge_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
                        NOINHERIT NOREPLICATION NOBYPASSRLS;
                ELSE
                    RAISE EXCEPTION
                        'Role vforge_app missing and current_user (%) lacks CREATEROLE',
                        current_user;
                END IF;
            ELSIF v_can_manage_roles AND EXISTS (
                SELECT 1 FROM pg_roles
                WHERE rolname = 'vforge_app'
                  AND (rolsuper OR rolcreatedb OR rolcreaterole OR rolinherit OR rolbypassrls)
            ) THEN
                ALTER ROLE vforge_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE
                    NOINHERIT NOREPLICATION NOBYPASSRLS;
            END IF;
        END $$;
        """
    )

    app_pw = os.environ.get("POSTGRES_APP_PASSWORD", "")
    if app_pw:
        op.execute(
            sa.text("SELECT set_config('vforge.init_app_pw', :pw, true)").bindparams(pw=app_pw)
        )
        op.execute(
            """
            DO $$
            DECLARE
                pw text := current_setting('vforge.init_app_pw', true);
                v_can_manage_roles boolean := false;
            BEGIN
                SELECT (rolsuper OR rolcreaterole) INTO v_can_manage_roles
                FROM pg_roles
                WHERE rolname = current_user;

                IF v_can_manage_roles AND pw IS NOT NULL AND pw <> '' THEN
                    EXECUTE format('ALTER ROLE vforge_app WITH LOGIN PASSWORD %L', pw);
                END IF;
                PERFORM set_config('vforge.init_app_pw', '', true);
            END $$;
            """
        )

    op.execute("GRANT USAGE ON SCHEMA public TO vforge_app;")
    op.execute("GRANT SELECT ON TABLE alembic_version, platform_metadata TO vforge_app;")
    op.execute(
        """
        GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
            organizations,
            app_users,
            memberships,
            projects,
            environments,
            assets,
            authorizations,
            auth_profiles,
            scan_profiles,
            auth_sessions,
            oidc_auth_states
        TO vforge_app;
        """
    )
    op.execute("GRANT SELECT, INSERT ON TABLE audit_events TO vforge_app;")
    op.execute("REVOKE UPDATE, DELETE ON TABLE audit_events FROM vforge_app;")

    # Enable and FORCE Row-Level Security on tenant-scoped tables
    for table in (
        "organizations",
        "app_users",
        "memberships",
        *_TENANT_STRICT_TABLES,
        "audit_events",
        "auth_sessions",
    ):
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;")

    # Strict tenant-scoped RLS policies
    for table in _TENANT_STRICT_TABLES:
        op.execute(
            f"""
            CREATE POLICY p_{table}_tenant_isolation ON {table}
            USING (organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid)
            WITH CHECK (
                organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
            );
            """
        )

    # Organizations RLS policies
    op.execute(
        """
        CREATE POLICY p_organizations_select ON organizations
        FOR SELECT
        USING (
            id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
            OR EXISTS (
                SELECT 1
                FROM memberships m
                WHERE m.organization_id = organizations.id
                  AND m.user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
                  AND m.status = 'active'
            )
        );
        """
    )
    op.execute(
        """
        CREATE POLICY p_organizations_insert ON organizations
        FOR INSERT
        WITH CHECK (
            NULLIF(current_setting('app.current_user_id', true), '') IS NOT NULL
        );
        """
    )
    op.execute(
        """
        CREATE POLICY p_organizations_update ON organizations
        FOR UPDATE
        USING (id = NULLIF(current_setting('app.current_org_id', true), '')::uuid)
        WITH CHECK (id = NULLIF(current_setting('app.current_org_id', true), '')::uuid);
        """
    )
    op.execute(
        """
        CREATE POLICY p_organizations_delete ON organizations
        FOR DELETE
        USING (id = NULLIF(current_setting('app.current_org_id', true), '')::uuid);
        """
    )

    # Memberships RLS policies
    op.execute(
        """
        CREATE POLICY p_memberships_select ON memberships
        FOR SELECT
        USING (
            organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
            OR (
                NULLIF(current_setting('app.current_org_id', true), '') IS NULL
                AND user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
            )
        );
        """
    )
    op.execute(
        """
        CREATE POLICY p_memberships_mutate ON memberships
        FOR ALL
        USING (organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid)
        WITH CHECK (
            organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
        );
        """
    )

    # AppUsers RLS policies
    op.execute(
        """
        CREATE POLICY p_app_users_select ON app_users
        FOR SELECT
        USING (
            (
                oidc_issuer = NULLIF(current_setting('app.auth_lookup_issuer', true), '')
                AND oidc_subject = NULLIF(current_setting('app.auth_lookup_subject', true), '')
            )
            OR id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
            OR EXISTS (
                SELECT 1
                FROM memberships m
                WHERE m.user_id = app_users.id
                  AND m.organization_id = NULLIF(
                      current_setting('app.current_org_id', true), ''
                  )::uuid
            )
        );
        """
    )
    op.execute(
        """
        CREATE POLICY p_app_users_insert ON app_users
        FOR INSERT
        WITH CHECK (
            oidc_issuer = NULLIF(current_setting('app.auth_lookup_issuer', true), '')
            AND oidc_subject = NULLIF(current_setting('app.auth_lookup_subject', true), '')
        );
        """
    )
    op.execute(
        """
        CREATE POLICY p_app_users_update ON app_users
        FOR UPDATE
        USING (
            (
                oidc_issuer = NULLIF(current_setting('app.auth_lookup_issuer', true), '')
                AND oidc_subject = NULLIF(current_setting('app.auth_lookup_subject', true), '')
            )
            OR id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
        )
        WITH CHECK (
            (
                oidc_issuer = NULLIF(current_setting('app.auth_lookup_issuer', true), '')
                AND oidc_subject = NULLIF(current_setting('app.auth_lookup_subject', true), '')
            )
            OR id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
        );
        """
    )

    # AuditEvents RLS policies (SELECT/INSERT only; UPDATE/DELETE denied by RLS + trigger + REVOKE)
    op.execute(
        """
        CREATE POLICY p_audit_events_select ON audit_events
        FOR SELECT
        USING (organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid);
        """
    )
    op.execute(
        """
        CREATE POLICY p_audit_events_insert ON audit_events
        FOR INSERT
        WITH CHECK (
            organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
            OR (
                organization_id IS NULL
                AND NULLIF(current_setting('app.current_org_id', true), '') IS NULL
            )
        );
        """
    )

    # AuthSessions RLS policies
    op.execute(
        """
        CREATE POLICY p_auth_sessions_select ON auth_sessions
        FOR SELECT
        USING (
            token_hash = NULLIF(current_setting('app.session_token_hash', true), '')
            OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
        );
        """
    )
    op.execute(
        """
        CREATE POLICY p_auth_sessions_insert ON auth_sessions
        FOR INSERT
        WITH CHECK (
            user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
        );
        """
    )
    op.execute(
        """
        CREATE POLICY p_auth_sessions_update ON auth_sessions
        FOR UPDATE
        USING (
            token_hash = NULLIF(current_setting('app.session_token_hash', true), '')
            OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
        )
        WITH CHECK (
            token_hash = NULLIF(current_setting('app.session_token_hash', true), '')
            OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
        );
        """
    )
    op.execute(
        """
        CREATE POLICY p_auth_sessions_delete ON auth_sessions
        FOR DELETE
        USING (
            token_hash = NULLIF(current_setting('app.session_token_hash', true), '')
            OR user_id = NULLIF(current_setting('app.current_user_id', true), '')::uuid
        );
        """
    )


def downgrade() -> None:
    for table in (
        "auth_sessions",
        "audit_events",
        *_TENANT_STRICT_TABLES,
        "memberships",
        "app_users",
        "organizations",
    ):
        op.execute(f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY;")

    op.execute("DROP POLICY IF EXISTS p_auth_sessions_delete ON auth_sessions;")
    op.execute("DROP POLICY IF EXISTS p_auth_sessions_update ON auth_sessions;")
    op.execute("DROP POLICY IF EXISTS p_auth_sessions_insert ON auth_sessions;")
    op.execute("DROP POLICY IF EXISTS p_auth_sessions_select ON auth_sessions;")
    op.execute("DROP POLICY IF EXISTS p_audit_events_insert ON audit_events;")
    op.execute("DROP POLICY IF EXISTS p_audit_events_select ON audit_events;")
    op.execute("DROP POLICY IF EXISTS p_app_users_update ON app_users;")
    op.execute("DROP POLICY IF EXISTS p_app_users_insert ON app_users;")
    op.execute("DROP POLICY IF EXISTS p_app_users_select ON app_users;")
    op.execute("DROP POLICY IF EXISTS p_memberships_mutate ON memberships;")
    op.execute("DROP POLICY IF EXISTS p_memberships_select ON memberships;")
    op.execute("DROP POLICY IF EXISTS p_organizations_delete ON organizations;")
    op.execute("DROP POLICY IF EXISTS p_organizations_update ON organizations;")
    op.execute("DROP POLICY IF EXISTS p_organizations_insert ON organizations;")
    op.execute("DROP POLICY IF EXISTS p_organizations_select ON organizations;")
    for table in _TENANT_STRICT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS p_{table}_tenant_isolation ON {table};")

    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vforge_app') THEN
                REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM vforge_app;
                REVOKE USAGE ON SCHEMA public FROM vforge_app;
            END IF;
        END $$;
        """
    )

    op.execute("DROP TRIGGER IF EXISTS trg_audit_events_append_only ON audit_events;")
    op.execute("DROP FUNCTION IF EXISTS prevent_audit_events_mutation();")

    op.drop_index("ix_oidc_auth_states_expires", table_name="oidc_auth_states")
    op.drop_table("oidc_auth_states")
    op.drop_index("ix_auth_sessions_user_expires", table_name="auth_sessions")
    op.drop_table("auth_sessions")
    op.drop_index("ix_audit_events_action", table_name="audit_events")
    op.drop_index("ix_audit_events_org_created", table_name="audit_events")
    op.drop_table("audit_events")
    op.drop_index("ix_scan_profiles_org_name", table_name="scan_profiles")
    op.drop_table("scan_profiles")
    op.drop_index("ix_auth_profiles_org_env", table_name="auth_profiles")
    op.drop_table("auth_profiles")
    op.drop_index("ix_authorizations_org_asset_status", table_name="authorizations")
    op.drop_table("authorizations")
    op.drop_index("ix_assets_org_env", table_name="assets")
    op.drop_table("assets")
    op.drop_index("ix_environments_org_project", table_name="environments")
    op.drop_table("environments")
    op.drop_index("ix_projects_org_created", table_name="projects")
    op.drop_table("projects")
    op.drop_index("ix_memberships_user_org", table_name="memberships")
    op.drop_table("memberships")
    op.drop_table("app_users")
    op.drop_table("organizations")
