"""Phase 7 Web/API DAST, target leases, auth profile resolution, and safety health probes.

Revision ID: 0008_phase7_dast
Revises: 0007_phase6_supply_chain_iac
Create Date: 2026-11-12 23:00:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0008_phase7_dast"
down_revision: str | Sequence[str] | None = "0007_phase6_supply_chain_iac"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_IMMUTABLE_TENANT_TABLES = ("target_health_probes",)


def upgrade() -> None:
    # 1. Add composite unique constraint on auth_profiles if missing so it can be referenced
    # by composite tenant foreign keys.
    op.create_unique_constraint(
        "uq_auth_profiles_org_id_id",
        "auth_profiles",
        ["organization_id", "id"],
    )

    # 2. Add auth_profile_id column and foreign key to scan_runs
    op.add_column(
        "scan_runs",
        sa.Column("auth_profile_id", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_scan_runs_org_auth_profile",
        "scan_runs",
        "auth_profiles",
        ["organization_id", "auth_profile_id"],
        ["organization_id", "id"],
        ondelete="RESTRICT",
    )
    op.create_index(
        "ix_scan_runs_org_auth_profile",
        "scan_runs",
        ["organization_id", "auth_profile_id"],
    )

    # 3. Create target_health_probes table for DAST safety monitoring and emergency aborts
    op.create_table(
        "target_health_probes",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_run_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("runner_job_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("asset_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("probe_type", sa.String(length=30), nullable=False),
        sa.Column("target_url", sa.Text(), nullable=False),
        sa.Column("status_code", sa.Integer(), nullable=True),
        sa.Column(
            "latency_ms",
            sa.Integer(),
            server_default=sa.text("0"),
            nullable=False,
        ),
        sa.Column(
            "healthy",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column(
            "probe_metadata",
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
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("organization_id", "id", name="uq_target_health_probes_org_id_id"),
        sa.CheckConstraint(
            "probe_type IN ('baseline', 'periodic', 'tripwire', 'post_scan')",
            name="ck_target_health_probes_type",
        ),
        sa.CheckConstraint("latency_ms >= 0", name="ck_target_health_probes_latency_nonneg"),
        sa.ForeignKeyConstraint(
            ["organization_id", "scan_run_id"],
            ["scan_runs.organization_id", "scan_runs.id"],
            name="fk_target_health_probes_org_run",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "runner_job_id"],
            ["runner_jobs.organization_id", "runner_jobs.id"],
            name="fk_target_health_probes_org_job",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "asset_id"],
            ["assets.organization_id", "assets.id"],
            name="fk_target_health_probes_org_asset",
            ondelete="RESTRICT",
        ),
    )

    op.create_index(
        "ix_target_health_probes_org_run_created",
        "target_health_probes",
        ["organization_id", "scan_run_id", "created_at"],
    )
    op.create_index(
        "ix_target_health_probes_healthy",
        "target_health_probes",
        ["organization_id", "healthy"],
    )

    # 4. RLS & Tenant Isolation
    for table in _IMMUTABLE_TENANT_TABLES:
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"""
            CREATE POLICY p_{table}_tenant_isolation ON {table}
            FOR ALL
            USING (
                organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
            )
            WITH CHECK (
                organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
            )
            """
        )

    # 5. Append-only trigger
    op.execute(
        """
        CREATE OR REPLACE FUNCTION prevent_phase7_immutable_mutation()
        RETURNS TRIGGER AS $$
        BEGIN
            RAISE EXCEPTION '% is immutable/append-only: % is not permitted', TG_TABLE_NAME, TG_OP;
        END;
        $$ LANGUAGE plpgsql;
        """
    )
    for imm_table in _IMMUTABLE_TENANT_TABLES:
        op.execute(
            f"""
            CREATE TRIGGER trg_{imm_table}_append_only
            BEFORE UPDATE OR DELETE ON {imm_table}
            FOR EACH ROW EXECUTE FUNCTION prevent_phase7_immutable_mutation();
            """
        )

    # 6. Runtime role permissions
    op.execute(
        f"""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vforge_app') THEN
                GRANT SELECT, INSERT ON TABLE {", ".join(_IMMUTABLE_TENANT_TABLES)}
                TO vforge_app;
                REVOKE UPDATE, DELETE ON TABLE {", ".join(_IMMUTABLE_TENANT_TABLES)}
                FROM vforge_app;
            END IF;
        END
        $$;
        """  # noqa: S608
    )


def downgrade() -> None:
    for imm_table in _IMMUTABLE_TENANT_TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS trg_{imm_table}_append_only ON {imm_table}")
    op.execute("DROP FUNCTION IF EXISTS prevent_phase7_immutable_mutation()")

    op.drop_index("ix_target_health_probes_healthy", table_name="target_health_probes")
    op.drop_index(
        "ix_target_health_probes_org_run_created",
        table_name="target_health_probes",
    )
    op.drop_table("target_health_probes")

    op.drop_index("ix_scan_runs_org_auth_profile", table_name="scan_runs")
    op.drop_constraint("fk_scan_runs_org_auth_profile", "scan_runs", type_="foreignkey")
    op.drop_column("scan_runs", "auth_profile_id")

    op.drop_constraint("uq_auth_profiles_org_id_id", "auth_profiles", type_="unique")
