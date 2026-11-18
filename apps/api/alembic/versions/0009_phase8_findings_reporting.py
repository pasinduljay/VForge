"""Phase 8 Canonical findings, triage/retest lifecycle, SLA tracking, risk exceptions, and reports.

Revision ID: 0009_phase8_findings_reporting
Revises: 0008_phase7_dast
Create Date: 2026-11-13 01:00:00+00:00
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "0009_phase8_findings_reporting"
down_revision: str | Sequence[str] | None = "0008_phase7_dast"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_IMMUTABLE_TENANT_TABLES = ("finding_events",)
_MUTABLE_TENANT_TABLES = ("risk_exceptions", "reports")
_ALL_TENANT_TABLES = _IMMUTABLE_TENANT_TABLES + _MUTABLE_TENANT_TABLES


def upgrade() -> None:
    # 1. Extend findings table with SLA, assignment, retest, and risk scoring columns
    op.add_column(
        "findings",
        sa.Column("sla_due_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column(
            "sla_breached",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("false"),
        ),
    )
    op.add_column(
        "findings",
        sa.Column("assigned_to", postgresql.UUID(as_uuid=True), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("remediation_notes", sa.Text(), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("retest_status", sa.String(length=30), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column(
            "business_priority",
            sa.String(length=20),
            nullable=False,
            server_default=sa.text("'medium'"),
        ),
    )
    op.add_column(
        "findings",
        sa.Column("cvss_score", sa.Numeric(precision=3, scale=1), nullable=True),
    )
    op.add_column(
        "findings",
        sa.Column("cvss_vector", sa.String(length=100), nullable=True),
    )

    op.create_foreign_key(
        "fk_findings_assigned_to",
        "findings",
        "app_users",
        ["assigned_to"],
        ["id"],
        ondelete="SET NULL",
    )
    op.create_check_constraint(
        "ck_findings_business_priority",
        "findings",
        "business_priority IN ('critical', 'high', 'medium', 'low', 'info')",
    )
    op.create_check_constraint(
        "ck_findings_retest_status",
        "findings",
        (
            "retest_status IS NULL OR retest_status IN "
            "('pending_retest', 'retest_passed', 'retest_failed')"
        ),
    )
    op.create_index(
        "ix_findings_org_sla",
        "findings",
        ["organization_id", "sla_due_at", "sla_breached"],
    )
    op.create_index(
        "ix_findings_org_assigned",
        "findings",
        ["organization_id", "assigned_to"],
    )
    op.create_index(
        "ix_findings_org_priority",
        "findings",
        ["organization_id", "business_priority"],
    )

    # 2. Create finding_events table (append-only lifecycle audit log)
    op.create_table(
        "finding_events",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("actor_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("event_type", sa.String(length=50), nullable=False),
        sa.Column("previous_status", sa.String(length=30), nullable=True),
        sa.Column("new_status", sa.String(length=30), nullable=True),
        sa.Column("comment", sa.Text(), nullable=True),
        sa.Column(
            "metadata",
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
        sa.PrimaryKeyConstraint("id", name="pk_finding_events"),
        sa.UniqueConstraint("organization_id", "id", name="uq_finding_events_org_id_id"),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_finding_events_org",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "finding_id"],
            ["findings.organization_id", "findings.id"],
            name="fk_finding_events_org_finding",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["actor_id"],
            ["app_users.id"],
            name="fk_finding_events_actor",
            ondelete="SET NULL",
        ),
    )
    op.create_index(
        "ix_finding_events_org_finding_created",
        "finding_events",
        ["organization_id", "finding_id", "created_at"],
    )

    # 3. Create risk_exceptions table (time-bound risk acceptance lifecycle)
    op.create_table(
        "risk_exceptions",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("finding_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "status",
            sa.String(length=30),
            nullable=False,
            server_default=sa.text("'pending'"),
        ),
        sa.Column("requested_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("reviewed_by", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("reason", sa.Text(), nullable=False),
        sa.Column("mitigating_controls", sa.Text(), nullable=False),
        sa.Column("review_notes", sa.Text(), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
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
        sa.PrimaryKeyConstraint("id", name="pk_risk_exceptions"),
        sa.UniqueConstraint("organization_id", "id", name="uq_risk_exceptions_org_id_id"),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_risk_exceptions_org",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["projects.organization_id", "projects.id"],
            name="fk_risk_exceptions_org_project",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "finding_id"],
            ["findings.organization_id", "findings.id"],
            name="fk_risk_exceptions_org_finding",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["requested_by"],
            ["app_users.id"],
            name="fk_risk_exceptions_requested_by",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["reviewed_by"],
            ["app_users.id"],
            name="fk_risk_exceptions_reviewed_by",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "status IN ('pending', 'approved', 'rejected', 'expired', 'revoked')",
            name="ck_risk_exceptions_status",
        ),
    )
    op.create_index(
        "ix_risk_exceptions_org_proj_status",
        "risk_exceptions",
        ["organization_id", "project_id", "status"],
    )
    op.create_index(
        "ix_risk_exceptions_org_finding",
        "risk_exceptions",
        ["organization_id", "finding_id"],
    )
    op.create_index(
        "ix_risk_exceptions_org_expires",
        "risk_exceptions",
        ["organization_id", "expires_at"],
    )

    # 4. Make artifacts.scan_run_id nullable and allow 'sbom' and 'report' types
    op.alter_column(
        "artifacts",
        "scan_run_id",
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=True,
    )
    op.drop_constraint("ck_artifacts_type", "artifacts", type_="check")
    op.create_check_constraint(
        "ck_artifacts_type",
        "artifacts",
        "artifact_type IN ('raw_output', 'execution_log', 'manifest', 'sbom', 'report')",
    )

    # 5. Create reports table
    op.create_table(
        "reports",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            nullable=False,
        ),
        sa.Column("organization_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("project_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("scan_run_id", postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column("report_type", sa.String(length=30), nullable=False),
        sa.Column("format", sa.String(length=20), nullable=False),
        sa.Column("title", sa.Text(), nullable=False),
        sa.Column(
            "summary",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("artifact_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("generated_by", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id", name="pk_reports"),
        sa.UniqueConstraint("organization_id", "id", name="uq_reports_org_id_id"),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            name="fk_reports_org",
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "project_id"],
            ["projects.organization_id", "projects.id"],
            name="fk_reports_org_project",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "scan_run_id"],
            ["scan_runs.organization_id", "scan_runs.id"],
            name="fk_reports_org_scan_run",
            ondelete="SET NULL (scan_run_id)",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id", "artifact_id"],
            ["artifacts.organization_id", "artifacts.id"],
            name="fk_reports_org_artifact",
            ondelete="RESTRICT",
        ),
        sa.ForeignKeyConstraint(
            ["generated_by"],
            ["app_users.id"],
            name="fk_reports_generated_by",
            ondelete="RESTRICT",
        ),
        sa.CheckConstraint(
            "report_type IN ('executive', 'technical_vapt', 'compliance_summary', 'sarif_export')",
            name="ck_reports_type",
        ),
        sa.CheckConstraint(
            "format IN ('html', 'pdf', 'json', 'sarif')",
            name="ck_reports_format",
        ),
    )
    op.create_index(
        "ix_reports_org_proj_created",
        "reports",
        ["organization_id", "project_id", "created_at"],
    )
    op.create_index(
        "ix_reports_org_run",
        "reports",
        ["organization_id", "scan_run_id"],
    )

    # 5. Row-Level Security (RLS) enforcement
    for tbl in _ALL_TENANT_TABLES:
        op.execute(f"ALTER TABLE {tbl} ENABLE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {tbl} FORCE ROW LEVEL SECURITY;")
        op.execute(
            f"""
            CREATE POLICY tenant_isolation_{tbl} ON {tbl}
            FOR ALL
            TO vforge_app
            USING (organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid)
            WITH CHECK (
                organization_id = NULLIF(current_setting('app.current_org_id', true), '')::uuid
            );
            """
        )

    # 6. Append-only trigger for finding_events
    op.execute(
        """
        CREATE OR REPLACE FUNCTION prevent_phase8_immutable_mutation()
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
            FOR EACH ROW EXECUTE FUNCTION prevent_phase8_immutable_mutation();
            """
        )

    # 7. Runtime role permissions
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vforge_app') THEN
                -- finding_events is append-only
                GRANT SELECT, INSERT ON finding_events TO vforge_app;
                REVOKE UPDATE, DELETE ON finding_events FROM vforge_app;

                -- risk_exceptions supports updates (for review and status changes)
                GRANT SELECT, INSERT, UPDATE ON risk_exceptions TO vforge_app;
                REVOKE DELETE ON risk_exceptions FROM vforge_app;

                -- reports supports standard lifecycle
                GRANT SELECT, INSERT, UPDATE, DELETE ON reports TO vforge_app;
            END IF;
        END $$;
        """
    )


def downgrade() -> None:
    for imm_table in _IMMUTABLE_TENANT_TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS trg_{imm_table}_append_only ON {imm_table};")
    op.execute("DROP FUNCTION IF EXISTS prevent_phase8_immutable_mutation();")

    for tbl in _ALL_TENANT_TABLES:
        op.execute(f"DROP POLICY IF EXISTS tenant_isolation_{tbl} ON {tbl};")
        op.execute(f"ALTER TABLE {tbl} NO FORCE ROW LEVEL SECURITY;")
        op.execute(f"ALTER TABLE {tbl} DISABLE ROW LEVEL SECURITY;")

    op.drop_index("ix_reports_org_run", table_name="reports")
    op.drop_index("ix_reports_org_proj_created", table_name="reports")
    op.drop_table("reports")

    op.execute("ALTER TABLE artifacts DISABLE TRIGGER trg_artifacts_append_only;")
    op.execute("DELETE FROM artifacts WHERE scan_run_id IS NULL;")
    op.execute("ALTER TABLE artifacts ENABLE TRIGGER trg_artifacts_append_only;")
    op.drop_constraint("ck_artifacts_type", "artifacts", type_="check")
    op.create_check_constraint(
        "ck_artifacts_type",
        "artifacts",
        "artifact_type IN ('raw_output', 'execution_log', 'manifest')",
    )
    op.alter_column(
        "artifacts",
        "scan_run_id",
        existing_type=postgresql.UUID(as_uuid=True),
        nullable=False,
    )

    op.drop_index("ix_risk_exceptions_org_expires", table_name="risk_exceptions")
    op.drop_index("ix_risk_exceptions_org_finding", table_name="risk_exceptions")
    op.drop_index("ix_risk_exceptions_org_proj_status", table_name="risk_exceptions")
    op.drop_table("risk_exceptions")

    op.drop_index("ix_finding_events_org_finding_created", table_name="finding_events")
    op.drop_table("finding_events")

    op.drop_index("ix_findings_org_priority", table_name="findings")
    op.drop_index("ix_findings_org_assigned", table_name="findings")
    op.drop_index("ix_findings_org_sla", table_name="findings")
    op.drop_constraint("ck_findings_retest_status", "findings", type_="check")
    op.drop_constraint("ck_findings_business_priority", "findings", type_="check")
    op.drop_constraint("fk_findings_assigned_to", "findings", type_="foreignkey")

    for col in (
        "cvss_vector",
        "cvss_score",
        "business_priority",
        "retest_status",
        "remediation_notes",
        "assigned_to",
        "sla_breached",
        "sla_due_at",
    ):
        op.drop_column("findings", col)
